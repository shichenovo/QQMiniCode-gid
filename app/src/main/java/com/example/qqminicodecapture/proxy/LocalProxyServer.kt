// 由 huojiujian 开源免费使用，二改请备注来源；地址 https://github.com/huojiujian2

package com.example.qqminicodecapture.proxy

import com.example.qqminicodecapture.util.AppLogger
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * 本地 SOCKS5 代理服务器。
 *
 * 这是 Reqable 同款架构的"第二段"：
 *   QQ 流量 → VPN TUN → tun2proxy(Rust 用户态 TCP/IP 栈) → SOCKS5(本类)
 *
 * 本类接受 tun2proxy 发来的 SOCKS5 连接，并根据目标地址分流：
 *   - TLS 且 SNI 命中目标域名 → [MitmTunnel] 完整 MITM（提取 code 后透传）
 *   - 其它所有流量 → 原始字节透传（QQ 登录等一切正常）
 *
 * SOCKS5 细节：
 *   - 仅支持 CONNECT（TCP）；UDP ASSOCIATE 回复"不支持"，
 *     促使 QUIC/HTTP3 客户端回退到 TCP+TLS，保证能被捕获
 *   - 支持 IPv4 / 域名 / IPv6 三种地址类型
 */
class LocalProxyServer(
    private val port: Int,
    private val caCert: X509Certificate,
    private val caKey: PrivateKey,
    private val protect: (Socket) -> Unit
) {

    companion object {
        private const val TAG = "Proxy"

        /** 仅对该域名做 MITM 解密，其它域名全部透传 */
        const val TARGET_HOST = "gate-obt.nqf.qq.com"
    }

    private val running = AtomicBoolean(false)
    private var serverSocket: ServerSocket? = null
    private val executor: ExecutorService = Executors.newCachedThreadPool { r ->
        Thread(r, "socks-worker").apply { isDaemon = true }
    }
    /**
     * 活跃连接集合。
     *
     * ★ 关键修复：原来是 CopyOnWriteArraySet，它的 add() 每次都会复制整个底层数组，
     * 在"每个 TCP 连接都 add 一次"的高频场景下是 O(n²)：第 N 个连接要复制 N 个元素。
     * QQ 小程序抓包几分钟就能累积数千个连接，CPU 和 GC 压力会随时间线性恶化。
     * 换成 ConcurrentHashMap 的 keySet，add/remove 都是 O(1)。
     */
    private val activeSockets: MutableSet<Socket> = ConcurrentHashMap.newKeySet()

    fun start() {
        if (!running.compareAndSet(false, true)) return
        serverSocket = ServerSocket().apply {
            reuseAddress = true
            bind(InetSocketAddress("127.0.0.1", port))
        }
        AppLogger.i(TAG, "SOCKS5 代理已启动: 127.0.0.1:$port")
        Thread({ acceptLoop() }, "socks-accept").apply {
            isDaemon = true
            start()
        }
    }

    fun stop() {
        if (!running.compareAndSet(true, false)) return
        try { serverSocket?.close() } catch (_: Throwable) {}
        // 关闭所有活跃连接 → 各 worker 线程的读写随即失败退出，finally 里会 remove；
        // 这里再显式清空兜底，保证下次 start() 时集合是干净的（并发安全）。
        activeSockets.forEach { runCatching { it.close() } }
        activeSockets.clear()
        executor.shutdownNow()
    }

    private fun acceptLoop() {
        val ss = serverSocket ?: return
        while (running.get()) {
            val client = try {
                ss.accept()
            } catch (_: Throwable) {
                break
            }
            activeSockets.add(client)
            executor.submit {
                try {
                    handleClient(client)
                } catch (t: Throwable) {
                    // handleClient 内部虽有多处 try/catch，但协议解析阶段仍可能抛出
                    //（SocketException、越界等）。异常若逃逸到 Future 会被静默吞掉，
                    // 而 socket 会永远留在 activeSockets 里 —— 这里必须兜底清理。
                    AppLogger.w(TAG, "客户端处理异常: ${t.message}")
                } finally {
                    // ★ 关键修复：连接结束必须移出活跃集合。
                    // 原实现只在 acceptLoop 里 add、从不 remove，集合只增不减；
                    // 配合 CopyOnWriteArraySet 的 O(n²) add，抓包时间越长
                    // 内存与 GC 压力越大，停止时叠加一波集中操作就会把进程拖垮。
                    activeSockets.remove(client)
                    closeQuietly(client)
                }
            }
        }
    }

    // ------------------------------------------------------------- SOCKS5 协议

    private fun handleClient(client: Socket) {
        try {
            client.tcpNoDelay = true
            val input = client.getInputStream()
            val output = client.getOutputStream()

            // --- greeting: VER NMETHODS METHODS... ---
            val ver = input.read()
            if (ver != 5) return closeQuietly(client)
            val nMethods = input.read()
            if (nMethods <= 0) return closeQuietly(client)
            skipFully(input, nMethods)
            output.write(byteArrayOf(5, 0))   // 选择"无需认证"
            output.flush()

            // --- request: VER CMD RSV ATYP ADDR PORT ---
            val rVer = input.read()
            val cmd = input.read()
            input.read() // RSV
            val atyp = input.read()
            if (rVer != 5 || atyp < 0) return closeQuietly(client)

            val host: String = when (atyp) {
                0x01 -> {
                    val b = ByteArray(4)
                    if (!readFully(input, b)) return closeQuietly(client)
                    InetAddress.getByAddress(b).hostAddress ?: ""
                }
                0x03 -> {
                    val len = input.read()
                    if (len <= 0) return closeQuietly(client)
                    val b = ByteArray(len)
                    if (!readFully(input, b)) return closeQuietly(client)
                    String(b, Charsets.US_ASCII)
                }
                0x04 -> {
                    val b = ByteArray(16)
                    if (!readFully(input, b)) return closeQuietly(client)
                    InetAddress.getByAddress(b).hostAddress ?: ""
                }
                else -> return closeQuietly(client)
            }
            val p1 = input.read()
            val p2 = input.read()
            if (p1 < 0 || p2 < 0) return closeQuietly(client)
            val portNum = (p1 shl 8) or p2

            if (cmd != 0x01) {
                // UDP ASSOCIATE 等不支持 → 回复 0x07 (command not supported)
                output.write(byteArrayOf(5, 7, 0, 1, 0, 0, 0, 0, 0, 0))
                output.flush()
                return closeQuietly(client)
            }

            // --- 回复连接成功（绑定地址填 0.0.0.0:0 即可）---
            output.write(byteArrayOf(5, 0, 0, 1, 0, 0, 0, 0, 0, 0))
            output.flush()

            dispatch(client, host, portNum)
        } catch (_: Throwable) {
            closeQuietly(client)
        }
    }

    // ------------------------------------------------------------- 分流决策

    /**
     * 先看首包：
     *   0x16 开头且端口 443 → TLS。读取完整首个 record 解析 SNI，
     *   命中目标域名走 MITM，否则透传。
     * 其它 → 直接透传。
     */
    private fun dispatch(client: Socket, host: String, port: Int) {
        val input = client.getInputStream()

        // 读 5 字节 TLS record 头（或任意首包的前 5 字节）
        val head = readN(input, 5) ?: return closeQuietly(client)

        if ((head[0].toInt() and 0xFF) == 0x16 && port == 443) {
            val recLen = ((head[3].toInt() and 0xFF) shl 8) or (head[4].toInt() and 0xFF)
            if (recLen in 1..65535) {
                val body = readN(input, recLen)
                if (body != null) {
                    val fullRecord = head + body
                    val sni = parseSni(fullRecord)
                    if (sni == TARGET_HOST) {
                        AppLogger.i(TAG, "命中目标域名，进入 MITM: $sni")
                        MitmTunnel(client, fullRecord, sni, port, caCert, caKey, protect).run()
                        return
                    }
                    // 有 SNI 但不是目标 → 按 SNI 透传（域名直连更准）
                    if (sni != null) {
                        AppLogger.i(TAG, "透传(TLS): $sni:$port")
                        rawRelay(client, fullRecord, sni, port)
                        return
                    }
                    AppLogger.i(TAG, "透传(TLS无SNI): $host:$port")
                    rawRelay(client, fullRecord, host, port)
                    return
                }
            }
            AppLogger.i(TAG, "透传(不完整TLS): $host:$port")
            rawRelay(client, head, host, port)
            return
        }

        // 非 TLS 流量
        AppLogger.i(TAG, "透传: $host:$port")
        rawRelay(client, head, host, port)
    }

    /** 原始字节透传（不感知内容） */
    private fun rawRelay(client: Socket, initial: ByteArray, host: String, port: Int) {
        val upstream = Socket()
        try {
            upstream.tcpNoDelay = true
            protect(upstream)
            upstream.connect(InetSocketAddress(host, port), 15000)

            if (initial.isNotEmpty()) {
                upstream.getOutputStream().write(initial)
                upstream.getOutputStream().flush()
            }

            val cIn = client.getInputStream()
            val cOut = client.getOutputStream()
            val uIn = upstream.getInputStream()
            val uOut = upstream.getOutputStream()

            val t1 = Thread({ pumpRaw(cIn, uOut) }, "relay-c2u").apply { isDaemon = true }
            val t2 = Thread({ pumpRaw(uIn, cOut) }, "relay-u2c").apply { isDaemon = true }
            t1.start()
            t2.start()
            t1.join()
            // 任一方向结束 → 关闭两端，唤醒另一方向的阻塞读
            closeQuietly(client)
            closeQuietly(upstream)
            t2.join(1000)
        } catch (_: Throwable) {
            closeQuietly(client)
            closeQuietly(upstream)
        }
    }

    private fun pumpRaw(ins: InputStream, outs: OutputStream) {
        val buf = ByteArray(16 * 1024)
        try {
            while (true) {
                val n = ins.read(buf)
                if (n <= 0) break
                outs.write(buf, 0, n)
                outs.flush()
            }
        } catch (_: Throwable) {
        }
    }

    private fun closeQuietly(s: Socket) {
        activeSockets.remove(s)
        try { s.close() } catch (_: Throwable) {}
    }

    // ------------------------------------------------------------- 工具

    /** 精确读取 n 字节；EOF 返回 null */
    private fun readN(input: InputStream, n: Int): ByteArray? {
        val buf = ByteArray(n)
        return if (readFully(input, buf)) buf else null
    }

    private fun readFully(input: InputStream, buf: ByteArray): Boolean {
        var off = 0
        while (off < buf.size) {
            val n = try {
                input.read(buf, off, buf.size - off)
            } catch (_: Throwable) {
                return false
            }
            if (n <= 0) return false
            off += n
        }
        return true
    }

    private fun skipFully(input: InputStream, n: Int) {
        var left = n
        val tmp = ByteArray(64)
        while (left > 0) {
            val r = input.read(tmp, 0, minOf(left, tmp.size))
            if (r <= 0) return
            left -= r
        }
    }

    /**
     * 从完整的 TLS record（0x16 开头）中解析 SNI。
     * 结构：record(5) → handshake(4) → ClientHello → extensions → server_name
     */
    private fun parseSni(record: ByteArray): String? {
        return try {
            if (record.size < 10) return null
            if (record[0].toInt() and 0xFF != 0x16) return null
            var p = 5
            if (record[p].toInt() and 0xFF != 0x01) return null   // ClientHello
            p += 4                                                   // type(1) + len(3)
            p += 34                                                   // version(2) + random(32)
            if (p >= record.size) return null
            val sidLen = record[p].toInt() and 0xFF
            p += 1 + sidLen
            if (p + 2 > record.size) return null
            val csLen = ((record[p].toInt() and 0xFF) shl 8) or (record[p + 1].toInt() and 0xFF)
            p += 2 + csLen
            if (p >= record.size) return null
            val cmLen = record[p].toInt() and 0xFF
            p += 1 + cmLen
            if (p + 2 > record.size) return null
            val extLen = ((record[p].toInt() and 0xFF) shl 8) or (record[p + 1].toInt() and 0xFF)
            p += 2
            val extEnd = p + extLen
            while (p + 4 <= record.size && p < extEnd) {
                val type = ((record[p].toInt() and 0xFF) shl 8) or (record[p + 1].toInt() and 0xFF)
                val len = ((record[p + 2].toInt() and 0xFF) shl 8) or (record[p + 3].toInt() and 0xFF)
                p += 4
                if (type == 0x0000) {                                // server_name
                    if (p + 2 > record.size) return null
                    val listLen = ((record[p].toInt() and 0xFF) shl 8) or (record[p + 1].toInt() and 0xFF)
                    var q = p + 2
                    val listEnd = q + listLen
                    while (q + 3 <= record.size && q < listEnd) {
                        val nameType = record[q].toInt() and 0xFF
                        val nameLen = ((record[q + 1].toInt() and 0xFF) shl 8) or (record[q + 2].toInt() and 0xFF)
                        q += 3
                        if (nameType == 0x00) {
                            if (q + nameLen > record.size) return null
                            return String(record, q, nameLen, Charsets.US_ASCII)
                        }
                        q += nameLen
                    }
                    return null
                }
                p += len
            }
            null
        } catch (_: Throwable) {
            null
        }
    }
}
// 由 huojiujian 开源免费使用，二改请备注来源；地址 https://github.com/huojiujian2

package com.example.qqminicodecapture.proxy

import com.example.qqminicodecapture.crypto.CertBuilder
import com.example.qqminicodecapture.util.AppLogger
import com.example.qqminicodecapture.util.CodeBus
import java.net.InetSocketAddress
import java.net.Socket
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager

/**
 * MITM 隧道（完整双向 TLS 桥）。
 *
 *             ┌─────────────┐ 伪造证书   ┌──────────────┐
 *   QQ 客户端 ─┤  serverEngine ├◄──────────┤  本类         │
 *             └─────────────┘           └──────┬───────┘
 *                                             │ 解密后的明文
 *                                             ▼
 *             ┌───────────────┐ 信任上游   ┌──────────────┐
 *   真实服务器 ─┤ upstreamEngine ├◄──────────┤  本类         │
 *             └───────────────┘           └──────────────┘
 *
 * 流程：
 *  1. 用 CA 给目标域名动态签发叶子证书
 *  2. 与 QQ 客户端完成 TLS 握手（客户端看到的是我们签的证书）
 *  3. 读取首个 HTTP 请求头，提取 ?code=xxx 并推送到 UI
 *  4. 与真实服务器再建一条 TLS 连接，把请求原样发出
 *  5. 之后两个方向全程透传（QQ 使用不受影响）
 */
class MitmTunnel(
    private val clientSocket: Socket,
    private val initialClientNet: ByteArray,
    private val host: String,
    private val port: Int,
    private val caCert: X509Certificate,
    private val caKey: PrivateKey,
    private val protect: (Socket) -> Unit
) {

    companion object {
        private const val TAG = "MitmTunnel"

        /** 信任所有证书的上游 SSLContext（我们只做转发，不做校验） */
        private val trustAllContext: SSLContext by lazy {
            SSLContext.getInstance("TLS").apply {
                init(null, arrayOf(object : X509TrustManager {
                    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
                    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
                    override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
                }), null)
            }
        }
    }

    private var upstreamSocket: Socket? = null
    private val bothClosed = AtomicBoolean(false)

    fun run() {
        try {
            // ---- 1. 动态叶子证书（带缓存，见 CertBuilder）----
            val (leafCert, leafKey) = CertBuilder.issueLeaf(host, caCert, caKey)

            // ---- 2. 与客户端握手 ----
            val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
            val ks = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
                load(null, null)
                setKeyEntry("leaf", leafKey, CharArray(0), arrayOf(leafCert, caCert))
            }
            kmf.init(ks, CharArray(0))
            val serverCtx = SSLContext.getInstance("TLS").apply {
                init(kmf.keyManagers, null, null)
            }
            val serverEngine = serverCtx.createSSLEngine().apply {
                useClientMode = false
            }

            val clientEndpoint = TlsEndpoint(
                "client", serverEngine,
                clientSocket.getInputStream(), clientSocket.getOutputStream()
            )
            clientEndpoint.handshake(initialClientNet)
            AppLogger.i(TAG, "客户端 TLS 握手成功: $host")

            // ---- 3. 读首个请求头并提取 code ----
            val firstRequest = readRequestHead(clientEndpoint)
            if (firstRequest != null) {
                val text = String(firstRequest, Charsets.ISO_8859_1)
                text.lineSequence().firstOrNull { it.isNotEmpty() }?.let { line ->
                    AppLogger.i(TAG, "请求行: ${line.take(200)}")
                }
                extractAndReportCode(text)
            }

            // ---- 4. 连接真实服务器并握手 ----
            val upstream = Socket().apply { tcpNoDelay = true }
            upstreamSocket = upstream
            protect(upstream)
            upstream.connect(InetSocketAddress(host, port), 15000)

            val upstreamEngine = trustAllContext.createSSLEngine(host, port).apply {
                useClientMode = true
            }
            val upstreamEndpoint = TlsEndpoint(
                "upstream", upstreamEngine,
                upstream.getInputStream(), upstream.getOutputStream()
            )
            upstreamEndpoint.handshake(ByteArray(0))
            AppLogger.i(TAG, "上游 TLS 握手成功: $host")

            // ---- 5. 首个请求发给上游 ----
            if (firstRequest != null && firstRequest.isNotEmpty()) {
                upstreamEndpoint.writeApp(firstRequest)
            }

            // ---- 6. 双向透传（u2c 方向挂 v2.1 好友嗅探器，只读不改）----
            val sniffer = WsFriendSniffer(host).apply {
                logger = { msg -> AppLogger.i("FriendSniffer", msg) }
                onFriends = { selfGid, json ->
                    com.example.qqminicodecapture.util.CodeBus.broadcastFriends(selfGid, json)
                }
            }
            val t1 = Thread({ pump(clientEndpoint, upstreamEndpoint, null) }, "mitm-c2u").apply {
                isDaemon = true
            }
            val t2 = Thread({ pump(upstreamEndpoint, clientEndpoint, sniffer) }, "mitm-u2c").apply {
                isDaemon = true
            }
            t1.start()
            t2.start()
            t1.join()
            t2.join()
        } catch (t: Throwable) {
            AppLogger.w(TAG, "MITM 会话结束($host): ${t.message ?: t.javaClass.simpleName}")
        } finally {
            closeBoth()
        }
    }

    /**
     * 读取首个 HTTP 请求：直到出现空行（\r\n\r\n）为止；
     * 读到的内容（含请求行 + 全部请求头）原样转发给上游。
     */
    private fun readRequestHead(ep: TlsEndpoint): ByteArray? {
        val buf = StringBuilder()
        val raw = java.io.ByteArrayOutputStream()
        val tmp = ByteArray(8 * 1024)
        try {
            while (raw.size() < 64 * 1024) {
                val chunk = ep.readApp() ?: break
                raw.write(chunk)
                buf.append(String(chunk, Charsets.ISO_8859_1))
                if (buf.indexOf("\r\n\r\n") >= 0) break
            }
        } catch (_: Throwable) {
            // 读一半断开：能拿多少算多少
        }
        return if (raw.size() > 0) raw.toByteArray() else null
    }

    private fun extractAndReportCode(text: String) {
        // 同一个请求里同时有 ver= 和 code=，一起提取出来
        val versionMatch = Regex("ver=([A-Za-z0-9._-]+)").find(text)
        if (versionMatch != null) {
            val ver = versionMatch.groupValues[1]
            if (ver.isNotEmpty()) {
                AppLogger.i(TAG, ">>> 捕获到版本号: $ver")
                CodeBus.broadcastVersion(ver)
            }
        }
        val m = Regex("code=([A-Za-z0-9_-]+)").find(text) ?: return
        val code = m.groupValues[1]
        if (code.length >= 8) {   // 防误报：code 一般是 32 位十六进制
            AppLogger.i(TAG, ">>> 成功捕获 code: $code")
            CodeBus.broadcastCode(code)
        }
    }

    /** 单向泵：解密一端 → 加密发往另一端；sniffer 非空时把明文喂给嗅探器（u2c） */
    private fun pump(from: TlsEndpoint, to: TlsEndpoint, sniffer: WsFriendSniffer?) {
        try {
            while (true) {
                val chunk = from.readApp() ?: break
                if (sniffer != null) sniffer.feed(chunk)
                to.writeApp(chunk)
            }
        } catch (_: Throwable) {
        } finally {
            from.shutdownOutput()
            closeBoth()   // 任一方向结束即整条会话结束（QQ 会自动重连）
        }
    }

    private fun closeBoth() {
        if (bothClosed.compareAndSet(false, true)) {
            try { clientSocket.close() } catch (_: Throwable) {}
            try { upstreamSocket?.close() } catch (_: Throwable) {}
        }
    }
}
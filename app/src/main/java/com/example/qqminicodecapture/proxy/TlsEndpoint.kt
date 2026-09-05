// 由 huojiujian 开源免费使用，二改请备注来源；地址 https://github.com/huojiujian2

package com.example.qqminicodecapture.proxy

import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLEngineResult

/**
 * 单个 TLS 端点：一个 SSLEngine + 底层 socket 流。
 *
 * 封装了完整的握手状态机与应用数据读写：
 *  - handshake(initialNet)：阻塞完成 TLS 握手（支持 TLS 1.2 / 1.3）
 *  - readApp()：阻塞读一段解密后的应用数据，EOF 返回 null
 *  - writeApp(data)：加密并发出一段应用数据
 *
 * 缓冲区约定：
 *  - peerNet 始终处于"写模式"（position == 已缓冲密文末尾），
 *    unwrap 前 flip()，unwrap 后 compact()
 *  - 握手期间意外到达的应用数据被保存在 pending 队列，不会丢失
 */
class TlsEndpoint(
    val tag: String,
    val engine: SSLEngine,
    private val input: InputStream,
    private val output: OutputStream
) {

    companion object {
        private const val INIT_NET = 16 * 1024
        private const val INIT_APP = 16 * 1024
        private const val MAX_NET = 1 shl 20
        private const val MAX_APP = 1 shl 20
        private val EMPTY: ByteBuffer = ByteBuffer.allocate(0)
    }

    /** 来自对端的密文（写模式） */
    private var peerNet = ByteBuffer.allocate(INIT_NET)

    /** 发往对端的密文（写模式） */
    private val myNet = ByteBuffer.allocate(64 * 1024)

    /** unwrap 用的应用数据暂存 */
    private var appScratch = ByteBuffer.allocate(INIT_APP)

    /** 已解出但尚未被取走的应用数据 */
    private val pending = ArrayDeque<ByteArray>()

    // ------------------------------------------------------------------ 基础

    private fun runTasks() {
        var task = engine.delegatedTask
        while (task != null) {
            task.run()
            task = engine.delegatedTask
        }
    }

    private fun growPeerNet() {
        if (peerNet.capacity() >= MAX_NET) throw IOException("$tag: TLS record too large")
        peerNet.flip()
        val bigger = ByteBuffer.allocate(minOf(peerNet.capacity() * 2, MAX_NET))
        bigger.put(peerNet)
        peerNet = bigger
    }

    private fun growAppScratch() {
        if (appScratch.capacity() >= MAX_APP) throw IOException("$tag: TLS app data too large")
        appScratch = ByteBuffer.allocate(minOf(appScratch.capacity() * 2, MAX_APP))
    }

    /** 阻塞读底层密文到 peerNet；EOF / 异常返回 false */
    private fun readPeer(): Boolean {
        while (!peerNet.hasRemaining()) growPeerNet()
        return try {
            val n = input.read(peerNet.array(), peerNet.position(), peerNet.remaining())
            if (n <= 0) false else {
                peerNet.position(peerNet.position() + n)
                true
            }
        } catch (t: Throwable) {
            false
        }
    }

    private fun putPeerNet(bytes: ByteArray) {
        while (peerNet.remaining() < bytes.size) growPeerNet()
        peerNet.put(bytes)
    }

    // ------------------------------------------------------------------ 握手

    /**
     * 完成握手。
     * @param initialNet 之前 peek 出来的密文（例如 ClientHello），会被一并交给引擎
     */
    @Throws(IOException::class)
    fun handshake(initialNet: ByteArray) {
        if (initialNet.isNotEmpty()) putPeerNet(initialNet)
        engine.beginHandshake()
        while (true) {
            when (engine.handshakeStatus) {
                SSLEngineResult.HandshakeStatus.FINISHED,
                SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING -> return

                SSLEngineResult.HandshakeStatus.NEED_UNWRAP -> {
                    peerNet.flip()
                    appScratch.clear()
                    val res = try {
                        engine.unwrap(peerNet, appScratch)
                    } finally {
                        peerNet.compact()
                    }
                    when (res.status) {
                        SSLEngineResult.Status.OK -> {
                            if (res.bytesProduced() > 0) {
                                val chunk = ByteArray(res.bytesProduced())
                                appScratch.flip()
                                appScratch.get(chunk)
                                pending.addLast(chunk)
                            }
                            if (res.handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_TASK) runTasks()
                        }
                        SSLEngineResult.Status.BUFFER_UNDERFLOW -> {
                            if (!readPeer()) throw EOFException("$tag: 对端在握手期间断开")
                        }
                        SSLEngineResult.Status.BUFFER_OVERFLOW -> growAppScratch()
                        SSLEngineResult.Status.CLOSED -> throw EOFException("$tag: 对端在握手期间关闭")
                    }
                }

                SSLEngineResult.HandshakeStatus.NEED_WRAP -> {
                    myNet.clear()
                    val res = engine.wrap(EMPTY, myNet)
                    when (res.status) {
                        SSLEngineResult.Status.OK, SSLEngineResult.Status.CLOSED -> {
                            myNet.flip()
                            if (myNet.hasRemaining()) {
                                output.write(myNet.array(), 0, myNet.remaining())
                                output.flush()
                            }
                            if (res.handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_TASK) runTasks()
                        }
                        SSLEngineResult.Status.BUFFER_OVERFLOW ->
                            throw IOException("$tag: wrap overflow during handshake")
                        SSLEngineResult.Status.BUFFER_UNDERFLOW ->
                            throw IOException("$tag: wrap underflow during handshake")
                    }
                }

                SSLEngineResult.HandshakeStatus.NEED_TASK -> runTasks()
            }
        }
    }

    // ------------------------------------------------------------------ 数据

    /** 阻塞读取一段应用数据；连接正常结束返回 null */
    @Throws(IOException::class)
    fun readApp(): ByteArray? {
        while (pending.isEmpty()) {
            if (engine.isInboundDone) return null
            if (!readPeer()) return null
            drainPeerNet()
        }
        return pending.removeFirst()
    }

    /** 尽可能多地消费 peerNet 中可解密的记录 */
    @Throws(IOException::class)
    private fun drainPeerNet() {
        peerNet.flip()
        try {
            while (peerNet.hasRemaining()) {
                appScratch.clear()
                val res = engine.unwrap(peerNet, appScratch)
                when (res.status) {
                    SSLEngineResult.Status.OK -> {
                        if (res.bytesProduced() > 0) {
                            val chunk = ByteArray(res.bytesProduced())
                            appScratch.flip()
                            appScratch.get(chunk)
                            pending.addLast(chunk)
                        }
                        if (res.handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_TASK) runTasks()
                    }
                    SSLEngineResult.Status.BUFFER_UNDERFLOW -> return
                    SSLEngineResult.Status.BUFFER_OVERFLOW -> growAppScratch()
                    SSLEngineResult.Status.CLOSED -> return
                }
            }
        } finally {
            peerNet.compact()
        }
    }

    /** 加密并写出一段应用数据 */
    @Throws(IOException::class)
    fun writeApp(data: ByteArray) {
        val src = ByteBuffer.wrap(data)
        while (src.hasRemaining()) {
            myNet.clear()
            val res = engine.wrap(src, myNet)
            when (res.status) {
                SSLEngineResult.Status.OK, SSLEngineResult.Status.CLOSED -> {
                    myNet.flip()
                    if (myNet.hasRemaining()) {
                        output.write(myNet.array(), 0, myNet.remaining())
                    }
                    if (res.handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_TASK) runTasks()
                }
                SSLEngineResult.Status.BUFFER_OVERFLOW ->
                    throw IOException("$tag: wrap overflow")
                SSLEngineResult.Status.BUFFER_UNDERFLOW ->
                    throw IOException("$tag: wrap underflow")
            }
        }
        output.flush()
    }

    /** 发送 close_notify（尽力而为） */
    fun shutdownOutput() {
        try {
            engine.closeOutbound()
            myNet.clear()
            engine.wrap(EMPTY, myNet)
            myNet.flip()
            if (myNet.hasRemaining()) {
                output.write(myNet.array(), 0, myNet.remaining())
                output.flush()
            }
        } catch (_: Throwable) {
        }
    }
}
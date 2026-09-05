// 由 huojiujian 开源免费使用，二改请备注来源；地址 https://github.com/huojiujian2

package com.example.qqminicodecapture.util

import java.io.BufferedReader
import java.io.InputStreamReader
import java.util.concurrent.atomic.AtomicBoolean

/**
 * 读取本进程 logcat 中指定 tag 的日志，转发到 [AppLogger]。
 *
 * tun2proxy 的 Rust 侧日志通过 android_logger 写入 logcat（tag 为 module path，
 * 形如 "tun2proxy::general_api"），但 AppLogger 只能看到 Kotlin 侧日志。
 * 本类用 `logcat` 子进程把 Rust 侧日志也收进 AppLogger，方便在 App 内排查。
 *
 * 注意：普通 App 只能读取自己 UID 的 logcat 条目；tun2proxy 与 App 同进程同 UID，
 * 因此可以读到。若设备禁止 logcat 子进程，本类会静默降级，不影响主流程。
 */
object LogcatReader {

    @Suppress("unused")
    private const val TAG = "LogcatReader"
    private val running = AtomicBoolean(false)
    private var thread: Thread? = null

    /** 需要捕获的 tag（tun2proxy 的 Rust 日志按 module_path 输出） */
    private val tags = arrayOf("tun2proxy")

    /**
     * logcat 子进程引用。
     *
     * ★ 关键修复：readLoop 里 BufferedReader.readLine() 是阻塞读，对它调用
     * interrupt() 没有任何效果 —— 线程会永远卡住，logcat 子进程也永不销毁，
     * 每次"启动→停止"都泄漏一个子进程 + 一个线程。因此必须持有 Process
     * 引用，stop() 时 destroy()：子进程退出会关闭其 stdout 管道，
     * 父进程的 readLine() 随即读到 EOF 返回 null，readLoop 自然退出。
     */
    @Volatile private var process: Process? = null

    fun start() {
        if (!running.compareAndSet(false, true)) return
        thread = Thread({ readLoop() }, "logcat-reader").apply {
            isDaemon = true
            start()
        }
    }

    fun stop() {
        // 幂等：多次 stop 不会重复 destroy
        if (!running.compareAndSet(true, false)) return
        try { process?.destroy() } catch (_: Throwable) {}
        try { process?.inputStream?.close() } catch (_: Throwable) {}
        thread?.let { t ->
            try { t.interrupt() } catch (_: Throwable) {}
            // destroy 后 readLine 会立刻返回，给 readLoop 极短的退出窗口
            try { t.join(500) } catch (_: Throwable) {}
        }
        thread = null
        process = null
    }

    private fun readLoop() {
        var proc: Process? = null
        try {
            val cmd = mutableListOf("logcat", "-v", "time")
            tags.forEach { cmd.add("-s"); cmd.add(it) }
            proc = Runtime.getRuntime().exec(cmd.toTypedArray())
            process = proc
            val reader = BufferedReader(InputStreamReader(proc.inputStream))
            var line: String?
            while (running.get()) {
                line = reader.readLine() ?: break
                if (line.isNotBlank()) {
                    // 去掉 logcat 自带的时间戳前缀，避免重复
                    val clean = line.substringAfter(": ").ifBlank { line }
                    AppLogger.i("tun2proxy", clean)
                }
            }
        } catch (_: Throwable) {
            // logcat 不可用或被 stop() destroy 后：静默降级
        } finally {
            try { proc?.destroy() } catch (_: Throwable) {}
            process = null
            running.set(false)
        }
    }
}

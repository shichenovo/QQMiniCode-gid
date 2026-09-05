// 由 huojiujian 开源免费使用，二改请备注来源；地址 https://github.com/huojiujian2

package com.example.qqminicodecapture.util

import java.text.SimpleDateFormat
import java.util.ArrayDeque
import java.util.Date
import java.util.Locale

/**
 * 应用内日志收集器
 *
 * 在 App 运行期间实时记录所有关键事件和异常，
 * 供 UI 中的日志区域显示并支持一键复制。
 */
object AppLogger {

    private const val MAX_LOGS = 1500

    /**
     * 环形缓冲：只保留最近 [MAX_LOGS] 条。
     *
     * ★ 关键修复：原来是无上限的 mutableListOf，抓包期间每条连接都会产生日志，
     * 长时间运行会把内存吃满，最终 OOM 被系统杀进程。
     * 用 ArrayDeque 是为了让"丢弃最老一条"保持 O(1)（ArrayList.removeAt(0) 是 O(n)）。
     */
    private val logs = ArrayDeque<LogEntry>(MAX_LOGS)
    private var onLogUpdated: ((String) -> Unit)? = null

    data class LogEntry(
        val timestamp: Long = System.currentTimeMillis(),
        val level: String,      // I / W / E
        val tag: String,
        val message: String
    )

    /** 设置日志更新回调（通常由 UI 注册） */
    fun setOnLogUpdated(callback: ((String) -> Unit)?) {
        onLogUpdated = callback
    }

    /** 追加一条日志 */
    fun i(tag: String, msg: String) = add("I", tag, msg)
    fun w(tag: String, msg: String) = add("W", tag, msg)
    fun e(tag: String, msg: String) = add("E", tag, msg)

    private fun add(level: String, tag: String, msg: String) {
        val entry = LogEntry(level = level, tag = tag, message = msg)
        // ★ formatLog 必须在锁内调用：SimpleDateFormat 不是线程安全的，
        // 而 add() 会被多个 worker 线程并发调用（代理、tun2proxy、VPN、UI）。
        // 回调放在锁外，避免在持锁时执行 UI 代码导致死锁。
        val line = synchronized(logs) {
            logs.addLast(entry)
            while (logs.size > MAX_LOGS) logs.removeFirst()
            formatLog(entry)
        }
        onLogUpdated?.invoke(line)
    }

    /** 获取完整日志文本 */
    fun getFullLog(): String {
        synchronized(logs) {
            return logs.joinToString("\n") { formatLog(it) }
        }
    }

    /** 清空内存中的日志（UI 端需要自行清空 TextView） */
    fun clear() {
        synchronized(logs) { logs.clear() }
    }

    private val sdf = SimpleDateFormat("HH:mm:ss", Locale.getDefault())
    private fun formatLog(e: LogEntry): String {
        val time = sdf.format(Date(e.timestamp))
        return "$time [${e.level}][${e.tag}] ${e.message}"
    }
}
// 由 huojiujian 开源免费使用，二改请备注来源；地址 https://github.com/huojiujian2

package com.example.qqminicodecapture.util

import android.util.Log
import java.io.PrintWriter
import java.io.StringWriter

/**
 * 全局未捕获异常捕获器。
 *
 * 用途：在不熟悉的崩溃模式出现时，把未捕获异常完整堆栈写到 AppLogger，
 * 这样下次崩溃就能从 UI 日志区看到根因（而不是只能看 logcat）。
 *
 * 注意：仅记录 + 调用系统默认 handler（让进程照样终止，避免掩盖真正的崩溃）。
 */
object CrashReporter {

    fun install() {
        val default = Thread.getDefaultUncaughtExceptionHandler() ?: return
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            try {
                val sw = StringWriter()
                throwable.printStackTrace(PrintWriter(sw))
                val msg = "未捕获异常 [${thread.name}]: ${throwable.javaClass.name}: ${throwable.message}\n$sw"
                AppLogger.e("CRASH", msg)
                // ★ 同时写文件日志：进程被 native 端 SIGABRT/SIGKILL 时
                // AppLogger 的内存数据没机会刷出来，文件是 fsync 的能留痕。
                FileLog.crash("Uncaught", msg)
            } catch (_: Throwable) {
                // 兜底：万一 AppLogger / FileLog 也炸了，至少打到 logcat
                Log.e("CRASH", "uncaught", throwable)
            }
            default.uncaughtException(thread, throwable)
        }
    }
}
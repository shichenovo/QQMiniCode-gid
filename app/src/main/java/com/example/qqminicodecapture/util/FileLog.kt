// 由 huojiujian 开源免费使用，二改请备注来源；地址 https://github.com/huojiujian2

package com.example.qqminicodecapture.util

import android.content.Context
import android.util.Log
import java.io.File
import java.io.FileWriter
import java.io.PrintWriter
import java.io.StringWriter
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * 磁盘日志器 —— 把关键事件和崩溃信号持久化到 app 私有目录的文件。
 *
 * 为什么需要它：
 *  AppLogger 只在内存里，进程死了就没了。VPN 抓包场景下，如果 stop 时进程被
 *  native 端 SIGABRT/SIGKILL（典型如 fdsan double-close、tun2proxy 内部 panic），
 *  AppLogger 里的日志会全部丢失，根本没机会看到。文件日志是 fsync 的，崩溃后
 *  通过 adb pull 就能取证。
 *
 * 使用：
 *  FileLog.init(context)
 *  FileLog.i("StopTrace", "Tun2proxy.stop() 返回 0")
 *  FileLog.crash("StopTrace", "stop 流程异常", throwable)
 *
 * 输出路径：/data/data/<pkg>/files/logs/app-yyyymmdd.log（每天一个，append 模式）
 */
object FileLog {

    private const val TAG = "FileLog"
    private const val MAX_FILE_BYTES = 1_500_000L  // ~1.5MB 单文件上限

    @Volatile private var dir: File? = null
    private val sdf = SimpleDateFormat("yyyyMMdd", Locale.getDefault())
    private val ts = SimpleDateFormat("HH:mm:ss.SSS", Locale.getDefault())
    private val lock = Any()

    fun init(context: Context) {
        try {
            val d = File(context.filesDir, "logs").apply { mkdirs() }
            dir = d
            // 进程启动即写入一行标记，方便跨日志关联
            write("[BOOT] pid=${android.os.Process.myPid()} ts=${ts.format(Date())}")
        } catch (t: Throwable) {
            Log.e(TAG, "init 失败: ${t.message}", t)
        }
    }

    fun i(tag: String, msg: String) = write("I/$tag $msg")
    fun w(tag: String, msg: String) = write("W/$tag $msg")
    fun e(tag: String, msg: String) = write("E/$tag $msg")
    fun e(tag: String, msg: String, t: Throwable) = write("E/$tag $msg\n${stack(t)}")

    /** 专用：把 stop 流程的关键信号（before/after）写下来，下次崩能取证 */
    fun stopTrace(label: String) = write("STOP/$label ts=${ts.format(Date())}")

    /** 专用：崩前最后机会（未捕获异常 / native abort 前） */
    fun crash(tag: String, msg: String, t: Throwable? = null) {
        val body = t?.let { "\n${stack(it)}" } ?: ""
        write("CRASH/$tag $msg$body")
    }

    private fun stack(t: Throwable): String {
        val sw = StringWriter()
        t.printStackTrace(PrintWriter(sw))
        return sw.toString()
    }

    private fun write(line: String) {
        val d = dir ?: return
        synchronized(lock) {
            try {
                val name = "app-${sdf.format(Date())}.log"
                val f = File(d, name)
                if (f.exists() && f.length() > MAX_FILE_BYTES) {
                    // 简单轮转：超过上限就改名存档 + 新建
                    val archive = File(d, "app-${sdf.format(Date())}-${System.currentTimeMillis()}.log")
                    f.renameTo(archive)
                }
                FileWriter(f, true).use { w ->
                    w.write("${ts.format(Date())} $line\n")
                    w.flush()
                }
            } catch (t: Throwable) {
                Log.e(TAG, "write 失败: ${t.message}", t)
            }
        }
    }

    /** 把最近 N 天的日志拼成一段文本（用于 UI 复制 / adb 导出） */
    fun tail(maxBytes: Int = 200_000): String {
        val d = dir ?: return ""
        synchronized(lock) {
            val files = d.listFiles()?.sortedByDescending { it.lastModified() } ?: return ""
            val sb = StringBuilder()
            for (f in files) {
                if (sb.length >= maxBytes) break
                sb.append("===== ").append(f.name).append(" =====\n")
                sb.append(f.readText())
            }
            return sb.toString().takeLast(maxBytes)
        }
    }
}

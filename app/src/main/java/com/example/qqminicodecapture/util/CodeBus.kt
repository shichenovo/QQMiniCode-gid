// 由 huojiujian 开源免费使用，二改请备注来源；地址 https://github.com/huojiujian2

package com.example.qqminicodecapture.util

import android.content.Context
import android.content.Intent
import android.os.Handler
import android.os.Looper

/**
 * 抓包数据总线 —— 支持跨进程。
 *
 * 架构背景：CaptureVpnService 运行在独立的 ":vpn" 进程（tun2proxy 是 native 代码，
 * 停止时可能发生 native 层延迟崩溃，若与 UI 同进程会连界面一起杀掉）。
 * 因此所有"服务进程 → 界面进程"的事件都必须跨进程传递。
 *
 * 双通道设计：
 *  - 进程内：保留 listener + mainHandler.post（同进程场景仍可用，如降级单进程）
 *  - 跨进程：[broadcastXxx] 在发送时额外发一条显式包广播（setPackage），
 *    主进程 MainActivity 注册 [ACTION_*] receiver 接收，再回调 [onRemote] 驱动 UI。
 */
object CodeBus {

    /** 跨进程广播 Action（均为显式包广播，仅本应用可收） */
    const val ACTION_CODE = "com.example.qqminicodecapture.event.CODE"
    const val ACTION_VERSION = "com.example.qqminicodecapture.event.VERSION"
    const val ACTION_STATUS = "com.example.qqminicodecapture.event.STATUS"
    const val ACTION_ERROR = "com.example.qqminicodecapture.event.ERROR"
    const val ACTION_FRIENDS = "com.example.qqminicodecapture.event.FRIENDS"

    const val EXTRA_CODE = "extra_code"
    const val EXTRA_VERSION = "extra_version"
    const val EXTRA_RUNNING = "extra_running"
    const val EXTRA_MSG = "extra_msg"
    const val EXTRA_FRIENDS = "extra_friends"
    const val EXTRA_SELF_GID = "extra_self_gid"

    private val mainHandler = Handler(Looper.getMainLooper())
    private var onCode: ((String) -> Unit)? = null
    private var onVersion: ((String) -> Unit)? = null
    private var onStatus: ((Boolean) -> Unit)? = null
    private var onError: ((String) -> Unit)? = null
    private var onFriends: ((Long, String) -> Unit)? = null

    /** 发送广播用的 Context（各进程在 Service/Activity onCreate 时 attach） */
    @Volatile private var appContext: Context? = null

    fun attach(context: Context) {
        appContext = context.applicationContext
    }

    fun setOnCodeListener(l: (String) -> Unit)     { onCode = l }
    fun setOnVersionListener(l: (String) -> Unit)  { onVersion = l }
    fun setOnStatusListener(l: (Boolean) -> Unit) { onStatus = l }
    fun setOnErrorListener(l: (String) -> Unit)   { onError = l }
    fun setOnFriendsListener(l: (Long, String) -> Unit) { onFriends = l }

    // ---------------------------------------------------------- 发送

    fun broadcastCode(code: String) {
        postLocal { onCode?.invoke(code) }
        fire(ACTION_CODE) { it.putExtra(EXTRA_CODE, code) }
    }

    fun broadcastVersion(ver: String) {
        postLocal { onVersion?.invoke(ver) }
        fire(ACTION_VERSION) { it.putExtra(EXTRA_VERSION, ver) }
    }

    fun broadcastStatus(running: Boolean) {
        postLocal { onStatus?.invoke(running) }
        fire(ACTION_STATUS) { it.putExtra(EXTRA_RUNNING, running) }
    }

    fun broadcastError(msg: String) {
        postLocal { onError?.invoke(msg) }
        fire(ACTION_ERROR) { it.putExtra(EXTRA_MSG, msg) }
    }

    /** 抓包即解析：下行 WS 帧里解出好友列表（:vpn 进程 → 主进程 UI） */
    fun broadcastFriends(selfGid: Long, friendsJson: String) {
        postLocal { onFriends?.invoke(selfGid, friendsJson) }
        fire(ACTION_FRIENDS) { it.putExtra(EXTRA_SELF_GID, selfGid).putExtra(EXTRA_FRIENDS, friendsJson) }
    }

    // ---------------------------------------------------------- 接收端回调

    /**
     * 由 MainActivity 的 BroadcastReceiver 在收到跨进程事件后调用，
     * 切回主线程驱动本进程内的 listener，逻辑与单进程完全一致。
     */
    fun onRemoteAction(action: String, intent: Intent) {
        when (action) {
            ACTION_CODE -> {
                val code = intent.getStringExtra(EXTRA_CODE) ?: return
                postLocal { onCode?.invoke(code) }
            }
            ACTION_VERSION -> {
                val ver = intent.getStringExtra(EXTRA_VERSION) ?: return
                postLocal { onVersion?.invoke(ver) }
            }
            ACTION_STATUS -> {
                if (!intent.hasExtra(EXTRA_RUNNING)) return
                postLocal { onStatus?.invoke(intent.getBooleanExtra(EXTRA_RUNNING, false)) }
            }
            ACTION_ERROR -> {
                val msg = intent.getStringExtra(EXTRA_MSG) ?: return
                postLocal { onError?.invoke(msg) }
            }
            ACTION_FRIENDS -> {
                val gid = intent.getLongExtra(EXTRA_SELF_GID, 0L)
                val json = intent.getStringExtra(EXTRA_FRIENDS) ?: return
                postLocal { onFriends?.invoke(gid, json) }
            }
        }
    }

    // ---------------------------------------------------------- 私有

    private inline fun postLocal(crossinline block: () -> Unit) {
        mainHandler.post { runCatching { block() } }
    }

    /** 显式包广播：只发给本应用（receiver 用 RECEIVER_NOT_EXPORTED 即可收到） */
    private inline fun fire(action: String, fill: (Intent) -> Unit) {
        val ctx = appContext ?: return
        try {
            val i = Intent(action).setPackage(ctx.packageName)
            fill(i)
            ctx.sendBroadcast(i)
        } catch (t: Throwable) {
            // 进程刚启动/被回收时发送失败无害
        }
    }
}

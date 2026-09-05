// 由 huojiujian 开源免费使用，二改请备注来源；地址 https://github.com/huojiujian2

package com.example.qqminicodecapture.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.ServiceCompat
import com.example.qqminicodecapture.crypto.CaManager
import com.example.qqminicodecapture.crypto.CaTrustChecker
import com.example.qqminicodecapture.proxy.LocalProxyServer
import com.example.qqminicodecapture.ui.MainActivity
import com.example.qqminicodecapture.util.AppLogger
import com.example.qqminicodecapture.util.CodeBus
import com.example.qqminicodecapture.util.CrashReporter
import com.example.qqminicodecapture.util.FileLog
import com.example.qqminicodecapture.util.LogcatReader
import com.github.shadowsocks.bg.Tun2proxy
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean

/**
 * 抓包 VPN 服务（Reqable 同款架构）。
 *
 *   QQ 流量
 *     ↓ 路由进 VPN TUN
 *   TUN fd ──(JNI)──► tun2proxy（Rust 用户态 TCP/IP 栈）
 *     ↓ SOCKS5（虚拟 DNS，Fake-IP 模式）
 *   LocalProxyServer（Kotlin SOCKS5 服务器）
 *     ├─ gate-obt.nqf.qq.com → MitmTunnel（动态证书 + 双向 TLS 桥，提取 code）
 *     └─ 其它所有流量 → 原样透传（QQ 登录、聊天等不受任何影响）
 *
 * 关键修复：stopCapture 必须**幂等**，因为：
 *   - 用户在 Activity 上点"停止" → MainActivity 发 ACTION_STOP → onStartCommand 调 stopCapture
 *   - onRevoke（用户从系统设置关掉 VPN / 系统强制收回）→ 直接调 stopCapture
 *   - stopSelf() → onDestroy() → 又调 stopCapture
 * 三个路径同时触发的话旧实现会重复 stopForeground / 重复中断 logcat 子进程 → 崩溃。
 */
class CaptureVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.example.qqminicodecapture.START"
        const val ACTION_STOP  = "com.example.qqminicodecapture.STOP"

        /** 本地 SOCKS5 端口（tun2proxy 会把 TUN 流量转到这里） */
        const val SOCKS_PORT = 1080
        const val VPN_MTU    = 1500

        private const val CHANNEL_ID = "qq_capture_vpn"
        private const val NOTIF_ID   = 0x1001
        private const val TAG = "CaptureVpnService"

        @Volatile
        @JvmStatic
        var instance: CaptureVpnService? = null
    }

    init {
        // 全局崩溃拦截，让任何 worker 线程抛出的异常都写进 AppLogger 而不是直接干掉进程
        CrashReporter.install()
    }

    private var proxyServer: LocalProxyServer? = null
    private var tunThread: Thread? = null
    private var pfd: ParcelFileDescriptor? = null

    /** 业务态：当前是否处于抓包中 */
    @Volatile private var active = false

    /** 守护态：stopCapture 是否已经执行过（保证幂等） */
    private val stopped = AtomicBoolean(false)

    /** 前台通知是否已启动 */
    private var foregroundStarted = false

    override fun onCreate() {
        super.onCreate()
        instance = this
        // ★ 独立进程初始化：本服务跑在 ":vpn" 进程，静态对象（FileLog/CodeBus）
        // 与主进程互不相通，必须各自初始化。
        // FileLog 落盘日志用于崩溃取证（native 崩溃只记录在这里）。
        FileLog.init(applicationContext)
        CodeBus.attach(applicationContext)
        FileLog.stopTrace("CaptureVpnService.onCreate pid=${android.os.Process.myPid()}")
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        AppLogger.i(TAG, "onStartCommand action=${intent?.action ?: "null"} flags=$flags startId=$startId")
        FileLog.stopTrace("onStartCommand action=${intent?.action}")
        when (intent?.action) {
            ACTION_STOP -> {
                // ★ B 模式：停止抓包 ≠ 销毁 Service
                // 只清理 VPN/tun2proxy/proxy 资源，Service 保持存活，进程不退，
                // Activity 留在前台，通知更新为"待命"文案。
                // 绝不能调 stopSelf() —— 那会让进程整个退出。
                FileLog.stopTrace("onStartCommand.STOP.begin")
                stopCapture("ACTION_STOP")  // 异步：主线程微秒级返回，不阻塞
                FileLog.stopTrace("onStartCommand.STOP.mainThreadReturned")
                return START_NOT_STICKY
            }
            else -> startCapture()
        }
        return START_STICKY
    }

    private fun startCapture() {
        if (active) {
            AppLogger.i(TAG, "startCapture 已被调用但已在运行，忽略")
            return
        }
        active = true
        stopped.set(false)  // 重新启动时重置"已停止"标志

        LogcatReader.start()

        // ★ 关键修复：用 ServiceCompat.startForeground() 显式指定 foregroundServiceType。
        // targetSdk 34 + Android 14+ 上，旧 API startForeground(int, Notification) 不会传 type，
        // 系统会从 manifest 推断，但 manifest 里写了 dataSync|specialUse 时部分 ROM/新系统
        // 会因为推断歧义抛 MissingForegroundServiceTypeException 或 ForegroundServiceTypeException，
        // 直接干掉 Service 进程。显式传 type 是最稳的写法。
        // 注意：ServiceCompat.startForeground 同一个 ID 重复调是"更新通知"，不会抛错，
        // 所以即使 Service 已经在前台（stop 之后保留前台身份），再调一次只是换文案。
        try {
            val types = android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC or
                    android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            ServiceCompat.startForeground(this, NOTIF_ID, buildNotification(), types)
            foregroundStarted = true
        } catch (t: Throwable) {
            // Android 12+ 在某些场景下会抛 SecurityException（比如系统回收后）
            AppLogger.e(TAG, "startForeground 失败: ${t.message}")
            // 即使 startForeground 失败也要继续，否则 tun2proxy 跑起来没前台身份会被系统秒杀
        }
        FileLog.stopTrace("startCapture.foregroundSet")
        AppLogger.i(TAG, "正在启动抓包服务...")

        // ---- 1. 准备 CA 证书 ----
        val (caCert, caKey) = try {
            CaManager.ensureCa(this)
        } catch (t: Throwable) {
            AppLogger.e(TAG, "CA 初始化失败: ${t.message}")
            CodeBus.broadcastError("CA 初始化失败: ${t.message}")
            stopCapture("CA 初始化失败")
            return
        }

        // ---- 1.5 证书信任预检 ----
        try {
            when (val r = CaTrustChecker.check(caCert, caKey)) {
                is CaTrustChecker.Result.Trusted -> {
                    if (r.chainValidates) {
                        AppLogger.i(TAG, "✓ 证书预检通过：用户CA一致且叶子链校验OK，可以开始 MITM")
                    } else {
                        AppLogger.e(TAG, "⚠⚠ 证书已安装且一致，但叶子链 PKIX 校验失败：${r.detail}")
                    }
                }
                is CaTrustChecker.Result.Stale -> {
                    AppLogger.e(TAG, "⚠⚠⚠ 证书预检失败（旧CA）：${r.detail}")
                }
                is CaTrustChecker.Result.NotFound -> {
                    AppLogger.e(TAG, "⚠⚠⚠ 证书预检失败（未安装）：${r.detail}")
                }
                is CaTrustChecker.Result.Error -> {
                    AppLogger.w(TAG, "证书预检异常（不影响继续启动）：${r.detail}")
                }
            }
        } catch (t: Throwable) {
            AppLogger.w(TAG, "证书预检异常（不影响继续启动）: ${t.message}")
        }

        // ---- 2. 启动本地 SOCKS5 代理 ----
        try {
            proxyServer = LocalProxyServer(SOCKS_PORT, caCert, caKey) { s ->
                try { protect(s) } catch (_: Throwable) {}
            }.also { it.start() }
        } catch (t: Throwable) {
            AppLogger.e(TAG, "SOCKS5 代理启动失败: ${t.message}")
            CodeBus.broadcastError("SOCKS5 代理启动失败: ${t.message}")
            stopCapture("SOCKS5 代理启动失败")
            return
        }

        // ---- 3. 建立 VPN TUN ----
        val builder = Builder()
            .setSession("QQMiniCodeCapture")
            .setMtu(VPN_MTU)
            .addAddress("172.19.0.1", 24)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("8.8.8.8")
            .apply {
                try {
                    addAllowedApplication("com.tencent.mobileqq")
                    AppLogger.i(TAG, "VPN 仅接管 com.tencent.mobileqq")
                } catch (t: Throwable) {
                    AppLogger.w(TAG, "未找到 QQ（com.tencent.mobileqq），回退为接管全部应用: ${t.message}")
                }
            }

        val fd: Int
        try {
            val conn = builder.establish() ?: throw IOException("establish() 返回 null")
            // 把 fd 交给 tun2proxy（Rust）全权管理，Java 侧不再读写
            fd = conn.detachFd()
            // ★ 关键修复：detachFd() 之后这个 PFD 对象不再持有 fd 所有权，
            // 但 Android 10+ 的 fdsan 仍然追踪它。如果不立刻置 null，
            // GC 时 finalize 会触发 close()，fdsan 检测到该 fd 已被 Rust 端
            // close（close-fd-on-drop）后会 abort 进程 —— 这就是"一点停止就闪退"。
            // 参考：https://github.com/therealaleph/MasterHttpRelayVPN-RUST/pull/187
            //       https://github.com/xjasonlyu/tun2socks/pull/495
            pfd = null
            // conn 局部变量出作用域后，Java GC 会回收空 PFD 对象，不会再 close。
        } catch (t: Throwable) {
            AppLogger.e(TAG, "VPN 建立失败: ${t.message}")
            CodeBus.broadcastError("VPN 建立失败: ${t.message}")
            stopCapture("VPN 建立失败")
            return
        }
        AppLogger.i(TAG, "TUN 已建立 (fd=$fd, mtu=$VPN_MTU)，启动 tun2proxy...")

        // ---- 4. 启动 tun2proxy（阻塞运行在独立线程）----
        val worker = Thread({
            // verbosity 用 info 而非 trace：trace 会让 tun2proxy 对每个数据包都写日志
            //（再经 android_logger 进 logcat），既拖垮转发性能，也可能在停止瞬间制造
            // 日志洪峰。info 足够看清握手/关闭等关键事件。
            val cli = "tun2proxy-bin --tun-fd $fd --close-fd-on-drop true " +
                    "--proxy socks5://127.0.0.1:$SOCKS_PORT " +
                    "--dns virtual --verbosity info"
            AppLogger.i(TAG, "启动 tun2proxy: $cli")
            val ret = try {
                Tun2proxy.run(cli, VPN_MTU.toChar())
            } catch (t: Throwable) {
                AppLogger.e(TAG, "tun2proxy 运行异常: ${t.message}")
                -99
            }
            AppLogger.i(TAG, "tun2proxy 已退出 (code=$ret, active=$active)")
            FileLog.i(TAG, "tun2proxy 线程退出 code=$ret")
            // 如果是 tun2proxy 自己挂掉（不是我们主动 stop），通知 UI
            if (active && ret != 0) {
                CodeBus.broadcastError("tun2proxy 异常退出: $ret")
            }
        }, "tun2proxy")
        // ★ 关键修复：detachFd() 之后，fd 的所有权已经移交给 tun2proxy run 的
        // closeFdOnDrop。如果 Thread.start() 失败（OOM 等），fd 没人接管就会
        // 泄漏到进程死。用 ParcelFileDescriptor.adoptFd(fd) 拿回 fd 引用，
        // 然后 close() 显式释放，避免泄漏。
        try {
            worker.isDaemon = true
            worker.start()
            tunThread = worker
        } catch (t: Throwable) {
            AppLogger.e(TAG, "tun2proxy 线程启动失败: ${t.message}")
            try {
                ParcelFileDescriptor.adoptFd(fd).close()
            } catch (closeErr: Throwable) {
                AppLogger.w(TAG, "adoptFd($fd).close 失败: ${closeErr.message}")
            }
            stopCapture("Thread.start 失败")
            return
        }

        CodeBus.broadcastStatus(true)
        AppLogger.i(TAG, "抓包服务已启动")
    }

    /**
     * ★ 关键修复：stopCapture 幂等 + 全异步，主线程零阻塞
     *
     * 同一服务生命周期内可能被多个入口触发：
     *  1. 用户点"停止"按钮 → ACTION_STOP → onStartCommand（主线程）
     *  2. onRevoke()（系统回收 VPN 权限，主线程）
     *  3. onDestroy()（服务自然销毁，主线程）
     *
     * 每个入口都调 stopCapture，**只有第一次**真正执行清理。
     * 用 AtomicBoolean 保证线程安全。
     *
     * ★★ 核心修复：旧实现把 stopper.join(2000) + tunThread.join(4000) +
     * proxyServer.stop() + LogcatReader.stop() + 通知重建 + broadcastStatus
     * 全部放在主线程串行执行，最坏情况冻结主线程 ~6 秒，远超系统 ~5 秒
     * ANR 窗口，主进程被系统强杀 → VPN 和界面一起消失。
     *
     * 新实现：主线程只做 CAS + active=false + 捕获局部引用 + 启动清理线程，
     * 微秒级返回。所有阻塞操作（JNI stop、join、socket 关闭、logcat 杀进程、
     * 通知重建）全部在 "capture-stop" 后台线程执行。
     *
     * teardown 顺序（与 PR #187 一致）：
     *  1. 限时停 tun2proxy（side-thread + 2s join，JNI 阻塞在后台线程）
     *  2. join worker 线程（最多 4s，在后台线程）
     *  3. 停 SOCKS5 代理（无 fd 风险）
     *  4. 停 logcat 捕获
     *  5. pfd 已经是 null（启动时 detachFd 后立即清），不用碰
     *  6. 更新前台通知为"待命"
     *  7. 通知 UI（CodeBus 内部用 mainHandler.post 切主线程，线程安全）
     */
    private fun stopCapture(reason: String) {
        FileLog.stopTrace("stopCapture.begin reason=$reason")
        // CAS 保证整个清理块只执行一次
        if (!stopped.compareAndSet(false, true)) {
            AppLogger.i(TAG, "stopCapture($reason) 已执行过，跳过")
            FileLog.stopTrace("stopCapture.skip")
            return
        }

        AppLogger.i(TAG, "停止抓包服务 (原因: $reason)")
        active = false
        FileLog.stopTrace("stopCapture.active=false")

        // ★ 捕获局部引用，立即清空实例字段。
        // 这样即使 startCapture 在清理期间被调用，也不会读到旧引用。
        val localTunThread = tunThread
        val localProxy = proxyServer
        tunThread = null
        proxyServer = null

        // ★ 所有阻塞操作移到后台线程，主线程不再被 join() 阻塞
        val cleanupThread = Thread({
            // 1. 限时停 tun2proxy（side-thread + 2s join 防 JNI 阻塞）
            val stopper = Thread({
                try { Tun2proxy.stop() } catch (t: Throwable) {
                    AppLogger.w(TAG, "Tun2proxy.stop() 异常: ${t.message}")
                }
            }, "tun2proxy-stop")
            stopper.isDaemon = true
            stopper.start()
            try {
                stopper.join(2_000)
            } catch (t: Throwable) {
                AppLogger.w(TAG, "stopper.join 异常: ${t.message}")
            }
            if (stopper.isAlive) {
                AppLogger.w(TAG, "Tun2proxy.stop() 超过 2s 未返回，继续")
            }

            // 2. join worker 线程（最多 4s）
            try {
                localTunThread?.join(4_000)
            } catch (t: Throwable) {
                AppLogger.w(TAG, "tunThread.join() 异常: ${t.message}")
            }
            FileLog.stopTrace("stopCapture.workerJoined")

            // 3. 停止 SOCKS5 代理
            try { localProxy?.stop() } catch (t: Throwable) {
                AppLogger.w(TAG, "proxyServer.stop() 异常: ${t.message}")
            }
            FileLog.stopTrace("stopCapture.proxyStopped")

            // 4. 停止 logcat 捕获
            try { LogcatReader.stop() } catch (t: Throwable) {
                AppLogger.w(TAG, "LogcatReader.stop() 异常: ${t.message}")
            }

            // 5. pfd 已经是 null（启动时 detachFd 之后立即置 null），不做任何 close
            //    —— 让 Rust 端的 close-fd-on-drop 独自负责关 fd。
            //    这是防止 fdsan double-close abort 的关键。

            // 6. 通知更新：把"抓包中"换成"待命"文案。Service 仍保持前台身份，
            //    进程不会被系统杀，Activity 留在前台（B 模式要求）。
            //    ServiceCompat.startForeground 可以在任意线程调用。
            if (foregroundStarted) {
                try {
                    val types = android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC or
                            android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
                    // 同一 ID 重复 startForeground 在 Android 上是"更新通知"，不抛错。
                    ServiceCompat.startForeground(this, NOTIF_ID, buildNotification("待命"), types)
                    FileLog.stopTrace("stopCapture.notifUpdatedToStandby")
                } catch (t: Throwable) {
                    AppLogger.w(TAG, "更新待命通知失败: ${t.message}")
                }
                // foregroundStarted 保持 true（Service 仍在前台）
            }

            // 7. 通知 UI（CodeBus 内部用 mainHandler.post 切到主线程，线程安全）
            try {
                CodeBus.broadcastStatus(false)
            } catch (t: Throwable) {
                AppLogger.w(TAG, "broadcastStatus(false) 异常: ${t.message}")
            }
            FileLog.stopTrace("stopCapture.done")
            AppLogger.i(TAG, "抓包服务已停止")
        }, "capture-stop")
        cleanupThread.isDaemon = true
        cleanupThread.start()

        // ★ 主线程在此立即返回，不再被 join() 阻塞 —— ANR 根因消除
        FileLog.stopTrace("stopCapture.mainThreadReturned")
    }

    override fun onRevoke() {
        AppLogger.w(TAG, "onRevoke: VPN 被系统撤销")
        // 注意：onRevoke 时系统会自动调用 stopSelf()，但 stopSelf 会触发 onDestroy
        // 所以这里只调 stopCapture，不要重复 stopSelf
        stopCapture("onRevoke")
        super.onRevoke()
    }

    override fun onDestroy() {
        AppLogger.i(TAG, "onDestroy: 服务销毁")
        FileLog.stopTrace("onDestroy.begin")
        // onDestroy 也会调 stopCapture，但 stopCapture 是幂等的，第二次会立即返回
        stopCapture("onDestroy")
        FileLog.stopTrace("onDestroy.afterStopCapture")
        instance = null
        super.onDestroy()
        FileLog.stopTrace("onDestroy.afterSuper")
    }

    // ------------------------------------------------------------- 通知

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(NotificationManager::class.java)
            val ch = NotificationChannel(
                CHANNEL_ID,
                getString(com.example.qqminicodecapture.R.string.notification_channel_name),
                NotificationManager.IMPORTANCE_LOW
            )
            nm.createNotificationChannel(ch)
        }
    }

    private fun buildNotification(statusOverride: String? = null): Notification {
        val pi = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        val title = getString(com.example.qqminicodecapture.R.string.notification_title)
        val text  = statusOverride ?: getString(com.example.qqminicodecapture.R.string.notification_text)
        return builder
            .setContentTitle(title)
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_sys_download)
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
    }
}
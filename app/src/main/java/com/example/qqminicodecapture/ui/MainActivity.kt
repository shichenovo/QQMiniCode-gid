// 由 huojiujian 开源免费使用，二改请备注来源；地址 https://github.com/huojiujian2

package com.example.qqminicodecapture.ui

import android.Manifest
import android.app.AlertDialog
import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.view.View
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.example.qqminicodecapture.BuildConfig
import com.example.qqminicodecapture.R
import com.example.qqminicodecapture.crypto.CaManager
import com.example.qqminicodecapture.crypto.CaTrustChecker
import com.example.qqminicodecapture.util.AppLogger
import com.example.qqminicodecapture.util.CertExporter
import com.example.qqminicodecapture.util.CertInstallerGuide
import com.example.qqminicodecapture.util.CodeBus
import com.example.qqminicodecapture.util.FileLog
import com.example.qqminicodecapture.util.PanelSyncer
import com.example.qqminicodecapture.vpn.CaptureVpnService
import org.json.JSONArray
import org.json.JSONObject

/**
 * 主界面
 *
 *  - 顶部状态点 + 状态文字（"未启动 / 证书正常 / 证书异常 / 错误"）
 *  - 版本号卡片（含"复制版本号"按钮）
 *  - code 卡片
 *  - 复制 / 下载证书 / 检测证书 按钮
 *  - 启动/停止按钮（居中、较窄）
 *  - 调试版额外显示折叠日志区
 *
 * 状态点 + 文字：
 *  - 灰：未启动
 *  - 绿：证书正常
 *  - 黄：证书异常
 *  - 红：错误
 */
class MainActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "MainActivity"

        /** 日志面板最大字符数，超过后从中间裁掉一半，防止 TextView 无限膨胀 */
        private const val MAX_LOG_CHARS = 200_000

        /** 日志面板刷新周期：把高频日志攒起来批量刷新，而不是每条都 post 主线程 */
        private const val LOG_FLUSH_INTERVAL_MS = 300L
    }

    private lateinit var btnStartCapture: Button
    private lateinit var etCode: EditText
    private lateinit var btnCopy: Button
    private lateinit var btnDownloadCert: Button
    private lateinit var btnCheckCert: Button
    private lateinit var btnCopyVersion: Button
    private lateinit var statusDot: View
    private lateinit var tvStatusLabel: TextView
    private lateinit var tvVersion: TextView

    // ---- v2.1 抓包即解析：好友 GID ----
    private lateinit var tvGidStatus: TextView
    private lateinit var tvGidResult: TextView
    private lateinit var btnCopyGids: Button  // 唯一复制按钮：内容为 JSON 数组（可直接导入服务器）
    private lateinit var etLevelFilter: EditText // 等级过滤阈值（0=不过滤）
    private var lastActionableGids: List<Long> = emptyList()
    private var gidRawJson: String = ""
    private var mergedFriends: Map<Long, JSONObject> = emptyMap()
    private var lastSelfGid: Long = 0L

    // ---- v2.2 Bot 面板同步 ----
    private lateinit var etPanelUrl: EditText
    private lateinit var etPanelAccId: EditText
    private lateinit var etPanelUser: EditText
    private lateinit var etPanelPass: EditText
    private lateinit var cbAutoSync: CheckBox
    private lateinit var btnSyncPanel: Button
    private lateinit var tvPanelResult: TextView
    private var syncingNow: Boolean = false
    private var lastAutoSyncAt: Long = 0L
    private val autoSyncMinIntervalMs = 15_000L

    // 仅调试版存在的控件
    private var tvLog: TextView? = null
    private var logScroll: ScrollView? = null
    private var btnCopyLog: Button? = null
    private var btnClearLog: Button? = null

    // ── 日志面板节流缓冲 ──────────────────────────────────────────
    // ★ 关键修复：原来每条日志都 runOnUiThread{ append + post{fullScroll} }，
    // 也就是一条日志产生两个主线程消息。tun2proxy/代理在高流量下每秒能吐几百条
    // 日志，主线程消息队列被瞬间打爆 → ANR → 系统杀进程（表现就是"点停止就闪退"，
    // 因为停止瞬间会集中爆发一批关闭日志）。
    // 现在改成：日志先写入 StringBuilder，由主线程 Handler 每 300ms 统一刷一次屏。
    private val logBuffer = StringBuilder(16 * 1024)
    private val logFlushHandler = Handler(Looper.getMainLooper())
    private val logFlushRunnable = object : Runnable {
        override fun run() {
            flushLogPanel()
            logFlushHandler.postDelayed(this, LOG_FLUSH_INTERVAL_MS)
        }
    }

    private var isCapturing: Boolean = false
        set(value) {
            field = value
            // ★ 兜底：view 已 detach / Activity 已 finish 时 text setter 可能抛
            try {
                btnStartCapture.text = if (value) getString(R.string.btn_stop) else getString(R.string.btn_start)
            } catch (t: Throwable) {
                AppLogger.w(TAG, "btnStartCapture.text 设置失败: ${t.message}")
            }
        }

    /** 启动流程（权限申请）进行中标志，防止双击 */
    private var hasPendingStart = false

    /** 0=idle, 1=ok, 2=warn, 3=err */
    private var certState: Int = 0
        set(value) {
            field = value
            updateStatusDot()
        }

    private val vpnPermLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { res ->
        if (res.resultCode == RESULT_OK) {
            AppLogger.i(TAG, "VPN 权限已授予，启动服务...")
            startVpnService()
        } else {
            AppLogger.w(TAG, "VPN 权限被拒绝")
            Toast.makeText(this, R.string.vpn_prepare, Toast.LENGTH_LONG).show()
            isCapturing = false
        }
    }

    private val notifPermLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (granted) {
            AppLogger.i(TAG, "通知权限已授予")
            requestVpnAndStart()
        } else {
            AppLogger.w(TAG, "通知权限被拒绝，前台服务可能无法启动")
            Toast.makeText(this, "通知权限被拒绝，抓包服务可能无法正常启动", Toast.LENGTH_LONG).show()
            isCapturing = false
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // 进程启动即开文件日志（哪怕 stop 时被 SIGABRT 也能留痕取证）
        FileLog.init(applicationContext)
        FileLog.i(TAG, "MainActivity.onCreate")
        setContentView(R.layout.activity_main)

        // 注意：本地 Native 网关中转由 CaptureVpnService(:vpn 进程) 负责启动/停止，
        // 引擎 WebView 与桥通信走 127.0.0.1 回环，跨进程可达。

        btnStartCapture = findViewById(R.id.btnStartCapture)
        etCode          = findViewById(R.id.etCode)
        btnCopy         = findViewById(R.id.btnCopy)
        btnDownloadCert = findViewById(R.id.btnDownloadCert)
        btnCheckCert    = findViewById(R.id.btnCheckCert)
        btnCopyVersion  = findViewById(R.id.btnCopyVersion)
        statusDot       = findViewById(R.id.statusDot)
        tvStatusLabel   = findViewById(R.id.tvStatusLabel)
        tvVersion       = findViewById(R.id.tvVersion)

        // v2.1 好友 GID 控件
        tvGidStatus     = findViewById(R.id.tvGidStatus)
        tvGidResult     = findViewById(R.id.tvGidResult)
        btnCopyGids      = findViewById(R.id.btnCopyGidsJson)
        etLevelFilter    = findViewById(R.id.etLevelFilter)
        tvGidStatus.text = getString(R.string.gid_status_idle)
        tvGidResult.text = ""
        // 结果区限高可滚动，方便查看全部好友（不依赖外层 ScrollView，避免嵌套滚动冲突）
        tvGidResult.movementMethod = android.text.method.ScrollingMovementMethod()
        btnCopyGids.isEnabled = false
        // 等级过滤阈值变化 → 立即按最新阈值重新过滤已解析结果
        etLevelFilter.addTextChangedListener(object : android.text.TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
            override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
            override fun afterTextChanged(s: android.text.Editable?) {
                if (mergedFriends.isNotEmpty()) refreshGidUi()
            }
        })

        // v2.2 Bot 面板同步控件（回填上次保存的配置）
        etPanelUrl    = findViewById(R.id.etPanelUrl)
        etPanelAccId  = findViewById(R.id.etPanelAccId)
        etPanelUser   = findViewById(R.id.etPanelUser)
        etPanelPass   = findViewById(R.id.etPanelPass)
        cbAutoSync    = findViewById(R.id.cbAutoSync)
        btnSyncPanel  = findViewById(R.id.btnSyncPanel)
        tvPanelResult = findViewById(R.id.tvPanelResult)
        val panelCfg = PanelSyncer.loadConfig(this)
        etPanelUrl.setText(panelCfg.url)
        etPanelAccId.setText(panelCfg.accountId)
        etPanelUser.setText(panelCfg.username)
        etPanelPass.setText(panelCfg.password)
        cbAutoSync.isChecked = panelCfg.autoSync

        if (BuildConfig.DEBUG) {
            tvLog       = findViewById(R.id.tvLog)
            logScroll   = findViewById(R.id.logScroll)
            btnCopyLog  = findViewById(R.id.btnCopyLog)
            btnClearLog = findViewById(R.id.btnClearLog)
        }

        // 注册日志更新回调（仅调试版实际显示）：
        // 日志先攒进 StringBuilder 缓冲，由 Handler 每 300ms 统一刷屏。
        // （原实现每条日志都 runOnUiThread + post 滚动，日志一多就打爆主线程 → ANR。）
        tvLog?.text = ""
        AppLogger.setOnLogUpdated { line ->
            synchronized(logBuffer) { logBuffer.append(line).append('\n') }
        }
        if (BuildConfig.DEBUG) {
            logFlushHandler.post(logFlushRunnable)
        }

        // 应用启动即生成 CA 证书
        AppLogger.i(TAG, "应用启动，初始化 CA 证书...")
        val (caCert, _) = try {
            CaManager.ensureCa(applicationContext)
        } catch (t: Throwable) {
            AppLogger.e(TAG, "CA 证书初始化失败: ${t.message}")
            Log.e(TAG, "Failed to init CA", t)
            Toast.makeText(this, "证书初始化失败: ${t.message}", Toast.LENGTH_LONG).show()
            null
        } ?: return

        // 启动时自动做一次证书信任自检（后台执行）
        runCertCheck(silentOnTrusted = true)

        btnStartCapture.setOnClickListener { onStartStopClick() }
        findViewById<View>(R.id.btnGithub).setOnClickListener { openGithub() }
        btnCopy.setOnClickListener { copyCode() }
        btnDownloadCert.setOnClickListener { downloadCert() }
        btnCheckCert.setOnClickListener { runCertCheck(silentOnTrusted = false) }
        btnCopyVersion.setOnClickListener { copyVersion() }
        btnCopyLog?.setOnClickListener { copyLog() }
        btnClearLog?.setOnClickListener { clearLog() }

        // v2.1 抓包即解析：复制 GID / 复制 JSON 数组
        btnCopyGids.setOnClickListener { copyActionableGidsJson() }

        // v2.2 Bot 面板同步：手动同步按钮 + 自动同步开关
        btnSyncPanel.setOnClickListener { savePanelConfig(); syncToPanel(manual = true) }
        cbAutoSync.setOnCheckedChangeListener { _, _ -> savePanelConfig() }

        // ★ 跨进程事件通道：CaptureVpnService 跑在 ":vpn" 独立进程，
        // 抓到的 code/状态/错误/好友数据经广播回到主进程，由 receiver 驱动统一的事件方法。
        CodeBus.attach(applicationContext)
        CodeBus.setOnCodeListener { code -> onCodeEvent(code) }
        CodeBus.setOnVersionListener { ver -> onVersionEvent(ver) }
        CodeBus.setOnStatusListener { running -> onStatusEvent(running) }
        CodeBus.setOnErrorListener { msg -> onErrorEvent(msg) }
        CodeBus.setOnFriendsListener { selfGid, json -> onFriendsParsed(selfGid, json) }
        registerEventReceiver()
    }

    // ---------------- 跨进程事件接收（:vpn 服务进程 → 主进程 UI） ----------------

    private val eventReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val i = intent ?: return
            CodeBus.onRemoteAction(i.action ?: return, i)
        }
    }

    private fun registerEventReceiver() {
        val filter = IntentFilter().apply {
            addAction(CodeBus.ACTION_CODE)
            addAction(CodeBus.ACTION_VERSION)
            addAction(CodeBus.ACTION_STATUS)
            addAction(CodeBus.ACTION_ERROR)
            addAction(CodeBus.ACTION_FRIENDS)
        }
        try {
            // targetSdk 33+ 注册非系统广播必须显式声明导出性；RECEIVER_NOT_EXPORTED
            // 配合发送端 setPackage，只有本应用能收到。
            ContextCompat.registerReceiver(this, eventReceiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED)
        } catch (t: Throwable) {
            AppLogger.w(TAG, "registerReceiver(带flag)失败，回退普通注册: ${t.message}")
            runCatching { registerReceiver(eventReceiver, filter) }
        }
    }

    private fun onCodeEvent(code: String) {
        AppLogger.i(TAG, "捕获到 code: $code")
        try { etCode.setText(code) } catch (_: Throwable) {}
        // v2.1：好友 GID 走"抓包自动解析"，无需再用 code 手动拉取
    }

    // ---------------- v2.1 抓包即解析：好友 GID ----------------

    /** 服务器→客户端方向解析到的一批好友（可能来自 SyncAll / GetAll / GetGameFriends） */
    private fun onFriendsParsed(selfGid: Long, friendsJson: String) {
        try {
            AppLogger.i(TAG, "收到好友数据 ${friendsJson.length}B")
            lastSelfGid = selfGid
            val arr = try { JSONArray(friendsJson) } catch (_: Throwable) { return }
            val byGid = LinkedHashMap<Long, JSONObject>()
            for (i in 0 until arr.length()) {
                val o = arr.optJSONObject(i) ?: continue
                val gid = o.optLong("gid")
                if (gid <= 0) continue
                // 后到的覆盖先到的（GetGameFriends 比 SyncAll 字段更全）
                byGid[gid] = o
            }
            if (byGid.isEmpty()) return

            // 与已积累结果合并（一次抓包会话可能多帧分批返回）
            val merged = LinkedHashMap<Long, JSONObject>()
            for ((gid, o) in mergedFriends) merged[gid] = o
            for ((gid, o) in byGid) merged[gid] = o
            mergedFriends = merged
            gidRawJson = JSONArray(merged.values.toList()).toString()

            refreshGidUi()
        } catch (t: Throwable) {
            AppLogger.w(TAG, "解析好友数据异常: ${t.message}")
        }
    }

    /** 当前"等级过滤"阈值：≥1 生效，0/空 = 不过滤 */
    private fun levelThreshold(): Long =
        (etLevelFilter.text?.toString()?.toLongOrNull() ?: 0L).coerceAtLeast(0L)

    /** 依据最新 mergedFriends + 等级过滤阈值，刷新可操作 GID 与界面 */
    private fun refreshGidUi() {
        val merged = mergedFriends
        if (merged.isEmpty()) return
        val threshold = levelThreshold()

        // 排除自身（Login 响应动态提供）与内置 NPC（小果 10001）。
        // 注意：不同账号自身 gid 不同，只能依赖嗅探器从 Login 帧动态取出的 lastSelfGid，不可硬编码。
        val human = merged.values.filter { o ->
            val g = o.optLong("gid")
            g != lastSelfGid && g != 10001L
        }
        // 等级过滤：只保留 Lv ≥ 阈值的好友；等级未知(≤0)不过滤，避免误杀信息不全的老好友
        val actionable = if (threshold > 0) {
            human.filter { o ->
                val lv = o.optLong("level")
                lv <= 0L || lv >= threshold
            }
        } else {
            human
        }.sortedBy { it.optLong("gid") }

        val lvFilteredOut = if (threshold > 0) {
            human.count { o ->
                val lv = o.optLong("level")
                lv in 1 until threshold
            }
        } else 0

        val gids = actionable.map { it.optLong("gid") }
        lastActionableGids = gids

        val sb = StringBuilder()
        sb.append("已解析 ").append(merged.size)
            .append(" 位好友，可操作 ").append(gids.size).append(" 位")
        if (lastSelfGid > 0) sb.append("（已排除自身 gid=").append(lastSelfGid).append("）")
        if (lvFilteredOut > 0) sb.append("（已过滤 ").append(lvFilteredOut).append(" 位 Lv<").append(threshold).append("）")
        sb.append('\n')

        // 全量显示全部可操作好友（结果区限高可上下滚动，不再截断）
        if (actionable.isNotEmpty()) {
            for (f in actionable) {
                val name = f.optString("name", "")
                val lv = f.optLong("level")
                sb.append(f.optLong("gid"))
                if (name.isNotBlank()) sb.append("  ").append(name)
                if (lv > 0) sb.append("  Lv").append(lv)
                sb.append('\n')
            }
        } else {
            sb.append(if (threshold > 0)
                "（过滤后无好友，试试调低等级阈值）"
            else
                "（暂无真人好友，可到 QQ 农场加几个好友后再试）")
        }
        tvGidStatus.text = getString(R.string.gid_status_ready)
        tvGidResult.text = sb.toString()
        btnCopyGids.isEnabled = gids.isNotEmpty()
        // v2.2：开启自动同步时，解析出可操作好友即推送到 Bot 面板（内部有节流）
        if (gids.isNotEmpty()) maybeAutoSync()
    }

    /**
     * 复制"直接导入服务器"的 GID 列表（JSON 数组格式）：[gid, gid, ...]
     * 这就是 bot core 里 fetch-gid 输出的 actionableGids 同款格式，
     * 服务器从 JSON 文件 / 命令行参数 / API 直接读取。
     */
    private fun copyActionableGidsJson() {
        if (lastActionableGids.isEmpty()) {
            Toast.makeText(this, R.string.gid_empty_copy, Toast.LENGTH_SHORT).show()
            return
        }
        val arr = JSONArray()
        for (g in lastActionableGids) arr.put(g)
        val text = arr.toString()
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("qq_gids", text))
        AppLogger.i(TAG, "复制 GID(${lastActionableGids.size} 个)，长度=${text.length}")
        Toast.makeText(this, R.string.gid_copy_done, Toast.LENGTH_SHORT).show()
    }

    // ---------------- v2.2 Bot 面板好友 GID 同步 ----------------

    /** 保存面板配置（地址 / 账号 / 密码 / 自动同步开关） */
    private fun savePanelConfig() {
        PanelSyncer.saveConfig(
            this,
            PanelSyncer.Config(
                url = etPanelUrl.text?.toString() ?: "",
                accountId = etPanelAccId.text?.toString() ?: "1",
                username = etPanelUser.text?.toString() ?: "admin",
                password = etPanelPass.text?.toString() ?: "",
                autoSync = cbAutoSync.isChecked,
            )
        )
    }

    /**
     * 把当前可操作 GID 同步到 Bot 面板（后台线程执行，UI 线程回显结果）。
     * @param manual true=按钮手动同步（无条件执行）；false=解析后自动同步（带节流）
     */
    private fun syncToPanel(manual: Boolean) {
        if (syncingNow) {
            if (manual) Toast.makeText(this, "正在同步中，请稍候…", Toast.LENGTH_SHORT).show()
            return
        }
        val gids = lastActionableGids
        if (gids.isEmpty()) {
            if (manual) Toast.makeText(this, R.string.gid_empty_copy, Toast.LENGTH_SHORT).show()
            return
        }
        if (!manual) {
            val now = System.currentTimeMillis()
            if (now - lastAutoSyncAt < autoSyncMinIntervalMs) return
            lastAutoSyncAt = now
        }
        savePanelConfig()
        syncingNow = true
        btnSyncPanel.isEnabled = false
        tvPanelResult.text = getString(R.string.panel_sync_busy)
        Thread {
            val result = PanelSyncer.sync(gids, applicationContext)
            runOnUiThread {
                syncingNow = false
                btnSyncPanel.isEnabled = true
                tvPanelResult.text = (if (result.ok) "✓ " else "✗ ") + result.message
                if (result.ok) {
                    AppLogger.i(TAG, "面板同步成功: ${result.message}")
                } else {
                    AppLogger.w(TAG, "面板同步失败: ${result.message}")
                }
                Toast.makeText(
                    this,
                    if (result.ok) R.string.panel_sync_done else R.string.panel_sync_failed,
                    Toast.LENGTH_SHORT
                ).show()
            }
        }.start()
    }

    /** 解析到新好友后由 onFriendsParsed 调用的自动同步入口 */
    private fun maybeAutoSync() {
        if (cbAutoSync.isChecked) syncToPanel(manual = false)
    }

    private fun onVersionEvent(ver: String) {
        AppLogger.i(TAG, "捕获到版本号: $ver")
        try {
            tvVersion.text = ver
            tvVersion.setTextColor(ContextCompat.getColor(this, R.color.text_primary))
        } catch (_: Throwable) {}
    }

    private fun onStatusEvent(running: Boolean) {
        // ★ 防御性：isCapturing setter 会调 btnStartCapture.text，
        // 如果 Activity 已被 finish 且 view 已 detach 可能抛 IllegalStateException。
        try { isCapturing = running } catch (t: Throwable) {
            AppLogger.w(TAG, "更新 isCapturing 失败: ${t.message}")
        }
        if (running) {
            // 新一轮抓包：清空上一轮结果，等待新的好友数据
            mergedFriends = emptyMap()
            lastActionableGids = emptyList()
            gidRawJson = ""
            try {
                tvGidStatus.text = getString(R.string.gid_status_busy)
                tvGidResult.text = ""
                btnCopyGids.isEnabled = false
            } catch (_: Throwable) {}
        }
    }

    private fun onErrorEvent(msg: String) {
        AppLogger.e(TAG, "抓包错误: $msg")
        try {
            Toast.makeText(this, msg, Toast.LENGTH_LONG).show()
        } catch (t: Throwable) {
            // Activity 已死时 Toast 会抛 BadTokenException，吞掉即可
            AppLogger.w(TAG, "Toast 显示失败: ${t.message}")
        }
        try { isCapturing = false } catch (_: Throwable) {}
    }

    // ---------------- 启动/停止 ----------------

    private fun onStartStopClick() {
        // ★ click handler 第一行就打 trace，崩前能看到 click 是否被触发
        FileLog.stopTrace("onStartStopClick.enter isCapturing=$isCapturing")
        // ★ 立刻禁用按钮，防止双击导致 click 内部状态错乱触发 crash
        try { btnStartCapture.isEnabled = false } catch (_: Throwable) {}
        try {
            if (isCapturing) {
                AppLogger.i(TAG, "用户点击停止抓包")
                stopVpnService()
            } else {
                AppLogger.i(TAG, "用户点击启动抓包")
                if (Build.VERSION.SDK_INT >= 33 &&
                    ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                        != PackageManager.PERMISSION_GRANTED) {
                    AppLogger.i(TAG, "请求通知权限...")
                    notifPermLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                    return
                }
                requestVpnAndStart()
            }
        } catch (t: Throwable) {
            // ★ click handler 兜底：所有未捕获异常都吞掉 + 写文件 + 恢复按钮状态
            FileLog.crash("ClickHandler", "onStartStopClick 异常", t)
            try { Toast.makeText(this, "操作失败: ${t.message}", Toast.LENGTH_LONG).show() } catch (_: Throwable) {}
        } finally {
            // 无论成功失败都恢复按钮（如果 Activity 还在）
            try { btnStartCapture.isEnabled = true } catch (_: Throwable) {}
        }
        FileLog.stopTrace("onStartStopClick.exit")
    }

    private fun requestVpnAndStart() {
        AppLogger.i(TAG, "准备 VPN 权限检查...")
        val intent = VpnService.prepare(this)
        if (intent != null) {
            AppLogger.i(TAG, "需要用户授权 VPN 权限")
            vpnPermLauncher.launch(intent)
        } else {
            AppLogger.i(TAG, "VPN 权限已就绪，直接启动")
            startVpnService()
        }
    }

    private fun startVpnService() {
        AppLogger.i(TAG, "启动 CaptureVpnService...")
        val intent = Intent(this, CaptureVpnService::class.java).apply {
            action = CaptureVpnService.ACTION_START
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
        isCapturing = true
    }

    private fun stopVpnService() {
        AppLogger.i(TAG, "停止 CaptureVpnService...")
        FileLog.stopTrace("stopVpnService.begin")
        // 防御性：如果用户快速双击"停止"，第二次直接返回（避免重复发 intent）
        if (!isCapturing) {
            AppLogger.i(TAG, "stopVpnService: 未在运行，跳过")
            FileLog.stopTrace("stopVpnService.skip")
            return
        }
        val intent = Intent(this, CaptureVpnService::class.java).apply {
            action = CaptureVpnService.ACTION_STOP
        }
        try {
            // ★ 关键：stop 时必须用 startService，不能用 startForegroundService！
            //
            // Android 8+ 规定：用 startForegroundService() 启动的服务必须在 5 秒内调
            // startForeground()，否则系统抛 ForegroundServiceDidNotStartInTimeException
            // → RemoteServiceException → 进程被 SIGKILL。这就是之前"点停止 5 秒左右闪退"
            // 的真正根因（用户日志里 onDestroy.afterSuper 之后才崩，时间窗对得上）。
            //
            // start 时用 startForegroundService（首次启动必须提升为前台）。
            // stop 时服务已经在前台了，stop intent 只是发个消息让它取消前台并自停，
            // 不能再"再启动一次前台服务"，否则会触发上面的 5 秒契约。
            // 用 startService 不触发该契约；Service 收到 STOP action 后调
            // stopForeground() + stopSelf() 正常退出。
            startService(intent)
            FileLog.stopTrace("stopVpnService.startServiceSent")
        } catch (t: Throwable) {
            // 兜底：即使发送失败也把 UI 状态置为停止
            AppLogger.e(TAG, "停止服务 intent 发送失败: ${t.message}")
            FileLog.stopTrace("stopVpnService.startServiceFailed: ${t.message}")
        }
        isCapturing = false
        FileLog.stopTrace("stopVpnService.end isCapturing=false")
    }

    // ---------------- 状态点 + 状态文字 ----------------

    private fun updateStatusDot() {
        val (dot, color, label) = when (certState) {
            1 -> Triple(R.drawable.dot_ok,    R.color.state_ok,    R.string.state_ok)
            2 -> Triple(R.drawable.dot_warn,  R.color.state_warn,  R.string.state_warn)
            3 -> Triple(R.drawable.dot_err,   R.color.state_err,   R.string.state_err)
            else -> Triple(R.drawable.dot_unknown, R.color.state_idle, R.string.state_idle)
        }
        statusDot.setBackgroundResource(dot)
        tvStatusLabel.setText(label)
        tvStatusLabel.setTextColor(ContextCompat.getColor(this, color))
    }

    // ---------------- UI 行为 ----------------

    private fun copyCode() {
        val text = etCode.text.toString()
        if (text.isEmpty()) {
            Toast.makeText(this, "暂未捕获到 code", Toast.LENGTH_SHORT).show()
            return
        }
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("qq_code", text))
        AppLogger.i(TAG, "复制 code 到剪贴板: $text")
        Toast.makeText(this, R.string.copied, Toast.LENGTH_SHORT).show()
    }

    /** 打开项目 GitHub 主页（开源来源） */
    private fun openGithub() {
        try {
            val intent = Intent(Intent.ACTION_VIEW, Uri.parse(getString(R.string.github_url)))
            startActivity(intent)
            AppLogger.i(TAG, "打开 GitHub: ${getString(R.string.github_url)}")
        } catch (t: Throwable) {
            AppLogger.w(TAG, "打开 GitHub 失败: ${t.message}")
            Toast.makeText(this, "无法打开浏览器: ${t.message}", Toast.LENGTH_SHORT).show()
        }
    }

    private fun copyVersion() {
        val ver = tvVersion.text.toString()
        if (ver.isEmpty() || ver == getString(R.string.version_hint)) {
            Toast.makeText(this, "暂未捕获到版本号", Toast.LENGTH_SHORT).show()
            return
        }
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("qq_version", ver))
        AppLogger.i(TAG, "复制版本号到剪贴板: $ver")
        Toast.makeText(this, R.string.copied_version, Toast.LENGTH_SHORT).show()
    }

    private fun copyLog() {
        // 内存日志 + 落盘日志一起复制。落盘日志（FileLog）是 fsync 持久化的，
        // native 崩溃 / 进程被杀时内存日志会丢，但 FileLog 完整保留 STOP trace
        // 和未捕获异常堆栈 —— 这是定位"停止后闪退"的关键证据。
        val appLog = AppLogger.getFullLog()
        val fileLog = try { FileLog.tail(300_000) } catch (_: Throwable) { "" }
        val fullLog = buildString {
            append("===== 内存日志 =====\n")
            append(appLog).append('\n')
            append("\n===== 落盘日志(崩溃取证) =====\n")
            append(fileLog)
        }
        if (fullLog.isBlank()) {
            Toast.makeText(this, "日志为空", Toast.LENGTH_SHORT).show()
            return
        }
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("qq_capture_log", fullLog))
        AppLogger.i(TAG, "复制完整日志到剪贴板，长度=${fullLog.length}")
        Toast.makeText(this, "日志已复制到剪贴板", Toast.LENGTH_SHORT).show()
    }

    private fun clearLog() {
        AppLogger.clear()
        tvLog?.text = ""
        AppLogger.i(TAG, "日志已清空")
    }

    /**
     * 把缓冲日志批量刷到 TextView（只跑在主线程）。
     * 由 [logFlushRunnable] 每 300ms 调一次；Activity 销毁后 tvLog 为 null 直接返回。
     */
    private fun flushLogPanel() {
        val tv = tvLog ?: return
        val text = synchronized(logBuffer) {
            if (logBuffer.isEmpty()) return
            val s = logBuffer.toString()
            logBuffer.setLength(0)
            s
        }
        try {
            tv.append(text)
            // 上限裁剪：超过 MAX_LOG_CHARS 就从中间某行断开、丢掉前面一半，
            // 防止 TextView 无限膨胀把内存吃光（配合 AppLogger 环形缓冲双保险）
            if (tv.text.length > MAX_LOG_CHARS) {
                val s = tv.text.toString()
                val keepStart = s.length - MAX_LOG_CHARS / 2
                val cutAt = s.indexOf('\n', keepStart)
                tv.text = if (cutAt in 1 until s.length) s.substring(cutAt + 1) else s.substring(keepStart)
            }
            logScroll?.post { logScroll?.fullScroll(ScrollView.FOCUS_DOWN) }
        } catch (_: Throwable) {
            // TextView 已 detach / Activity 已销毁，静默忽略
        }
    }

    override fun onDestroy() {
        // 停掉日志定时刷新并解绑回调，避免 Activity 销毁后 Handler/AppLogger 仍持有
        // 本 Activity 的引用造成泄漏；日志线程此后写入的缓冲不再刷屏。
        logFlushHandler.removeCallbacks(logFlushRunnable)
        AppLogger.setOnLogUpdated(null)
        runCatching { unregisterReceiver(eventReceiver) }
        CodeBus.setOnCodeListener {}
        CodeBus.setOnVersionListener {}
        CodeBus.setOnStatusListener {}
        CodeBus.setOnErrorListener {}
        CodeBus.setOnFriendsListener { _, _ -> }
        super.onDestroy()
    }

    private fun downloadCert() {
        AppLogger.i(TAG, "用户点击下载证书")
        try {
            val pem = CaManager.readPem(applicationContext)
            val uri = CertExporter.exportToDownloads(this, pem)
            if (uri == null) {
                AppLogger.e(TAG, "导出证书到 Downloads 失败")
                Toast.makeText(this, R.string.cert_failed, Toast.LENGTH_LONG).show()
            } else {
                AppLogger.i(TAG, "证书已导出: $uri")
                Toast.makeText(this, R.string.cert_saved, Toast.LENGTH_LONG).show()
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    showInstallCertDialog()
                }
            }
        } catch (t: Throwable) {
            AppLogger.e(TAG, "读取证书失败: ${t.message}")
            Toast.makeText(this, "读取证书失败: ${t.message}", Toast.LENGTH_LONG).show()
        }
    }

    private fun showInstallCertDialog() {
        AlertDialog.Builder(this)
            .setTitle(R.string.install_cert_guide_title)
            .setMessage(R.string.install_cert_guide_text)
            .setPositiveButton(R.string.btn_open_settings) { _, _ ->
                AppLogger.i(TAG, "用户打开系统设置安装证书")
                val ok = CertInstallerGuide.openSecuritySettings(this)
                if (!ok) Toast.makeText(this, "无法打开系统设置", Toast.LENGTH_LONG).show()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    // ---------------- 证书信任自检 --------

    private fun runCertCheck(silentOnTrusted: Boolean) {
        AppLogger.i(TAG, "开始证书信任自检 (silentOnTrusted=$silentOnTrusted)...")
        Toast.makeText(this, R.string.cert_checking, Toast.LENGTH_SHORT).show()

        Thread({
            val result = try {
                val (caCert, caKey) = CaManager.ensureCa(applicationContext)
                CaTrustChecker.check(caCert, caKey)
            } catch (t: Throwable) {
                AppLogger.e(TAG, "证书自检异常: ${t.message}")
                CaTrustChecker.Result.Error("自检异常: ${t.message}")
            }
            runOnUiThread { showCertCheckResult(result, silentOnTrusted) }
        }, "cert-check").start()
    }

    private fun showCertCheckResult(result: CaTrustChecker.Result, silentOnTrusted: Boolean) {
        when (result) {
            is CaTrustChecker.Result.Trusted -> {
                certState = 1
                if (!result.chainValidates) {
                    AlertDialog.Builder(this)
                        .setTitle("证书已安装，但链校验失败")
                        .setMessage(
                            "用户 CA 已安装且与当前签名 CA 一致，但用其签发的叶子证书" +
                                    "未通过 PKIX 校验：\n\n${result.detail}\n\n" +
                                    "这属于证书构造问题，请把日志复制发给开发者。"
                        )
                        .setPositiveButton(android.R.string.ok, null)
                        .show()
                } else if (!silentOnTrusted) {
                    AlertDialog.Builder(this)
                        .setTitle("证书状态正常")
                        .setMessage("用户 CA 已安装且与当前签名 CA 一致，叶子证书链通过 PKIX 校验。\n\n${result.detail}")
                        .setPositiveButton(android.R.string.ok, null)
                        .show()
                } else {
                    AppLogger.i(TAG, "启动自检通过：证书已安装且一致，链校验 OK")
                }
            }
            is CaTrustChecker.Result.Stale -> {
                certState = 2
                AlertDialog.Builder(this)
                    .setTitle("检测到旧证书（CA 已轮换）")
                    .setMessage(
                        result.detail + "\n\n" +
                                "请到 系统设置 → 安全 → 加密与凭据 → 受信任的凭据 → 用户，" +
                                "删除旧的 QQMiniCodeCapture 证书，再回本 App 重新\"下载证书\"并安装。"
                    )
                    .setPositiveButton(R.string.btn_open_settings) { _, _ ->
                        CertInstallerGuide.openSecuritySettings(this)
                    }
                    .setNegativeButton(android.R.string.cancel, null)
                    .show()
            }
            is CaTrustChecker.Result.NotFound -> {
                certState = 2
                AlertDialog.Builder(this)
                    .setTitle("未检测到 CA 证书")
                    .setMessage(
                        result.detail + "\n\n" +
                                "请先点击\"下载证书\"，然后按引导安装到系统。"
                    )
                    .setPositiveButton(android.R.string.ok, null)
                    .show()
            }
            is CaTrustChecker.Result.Error -> {
                certState = 3
                AlertDialog.Builder(this)
                    .setTitle("证书自检失败")
                    .setMessage(result.detail)
                    .setPositiveButton(android.R.string.ok, null)
                    .show()
            }
        }
    }
}
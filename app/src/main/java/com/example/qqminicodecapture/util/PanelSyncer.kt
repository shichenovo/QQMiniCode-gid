// 由 huojiujian 开源免费使用，二改请备注来源；地址 https://github.com/huojiujian2
// 追加：Bot 面板好友 GID 同步（对接 qq-farm-bot 面板 /api/friend-known-gids/batch-add）

package com.example.qqminicodecapture.util

import android.content.Context
import android.content.SharedPreferences
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL

/**
 * Bot 面板「已知好友 GID」同步器
 *
 * 把抓包自动解析出的可操作好友 GID 增量合并到 qq-farm-bot 面板：
 *   1. POST {url}/api/login             （管理员账号密码 → token）
 *   2. POST {url}/api/friend-known-gids/batch-add （x-admin-token + x-account-id → 增量合并）
 *
 * 面板 batch-add 本身是增量合并（已存在的 GID 跳过并计入 addedCount），
 * 因此重复同步安全，可直接用「复制 GID」同款的 JSON 数字数组。
 */
object PanelSyncer {

    private const val TAG = "PanelSyncer"
    private const val PREFS = "panel_sync"
    private const val TIMEOUT_MS = 10_000

    /** 面板同步配置（SharedPreferences 持久化，仅本机） */
    data class Config(
        val url: String,       // 例如 http://103.117.137.115:3010
        val accountId: String, // 面板账号 id，如 "1"
        val username: String,  // 管理员账号，默认 admin
        val password: String,  // 管理员密码
        val autoSync: Boolean, // 解析到新好友后自动同步
    )

    fun prefs(ctx: Context): SharedPreferences =
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun loadConfig(ctx: Context): Config {
        val p = prefs(ctx)
        return Config(
            url = p.getString("url", "http://103.117.137.115:3010") ?: "",
            accountId = p.getString("accountId", "1") ?: "1",
            username = p.getString("username", "admin") ?: "admin",
            password = p.getString("password", "") ?: "",
            autoSync = p.getBoolean("autoSync", false),
        )
    }

    fun saveConfig(ctx: Context, cfg: Config) {
        prefs(ctx).edit()
            .putString("url", cfg.url.trim())
            .putString("accountId", cfg.accountId.trim())
            .putString("username", cfg.username.trim())
            .putString("password", cfg.password)
            .putBoolean("autoSync", cfg.autoSync)
            .apply()
    }

    data class SyncResult(val ok: Boolean, val message: String)

    /** 同步可操作 GID 到面板（调用方放到后台线程执行） */
    fun sync(gids: List<Long>, ctx: Context): SyncResult {
        val cfg = loadConfig(ctx)
        val base = normalizeUrl(cfg.url)
        if (base.isEmpty()) return SyncResult(false, "请先填写 Bot 面板地址")
        if (gids.isEmpty()) return SyncResult(false, "暂无可同步的好友 GID（先开抓包进一次农场）")

        // 1. 登录
        val token = tryLogin(base, cfg.username, cfg.password)
            ?: return SyncResult(false, "面板登录失败：请检查管理员账号/密码")
        // 2. 增量合并
        return tryBatchAdd(base, token, cfg.accountId, gids)
    }

    // ---------------- 内部实现 ----------------

    private fun normalizeUrl(raw: String): String {
        var s = raw.trim()
        if (s.isEmpty()) return ""
        if (!s.startsWith("http://") && !s.startsWith("https://")) s = "http://$s"
        while (s.endsWith("/")) s = s.dropLast(1)
        return s
    }

    private fun tryLogin(base: String, username: String, password: String): String? {
        if (username.isBlank() || password.isBlank()) return null
        return try {
            val body = JSONObject()
                .put("username", username)
                .put("password", password)
                .toString()
            val (code, resp) = httpPost("$base/api/login", body, headers = emptyMap())
            if (code in 200..299) {
                val data = JSONObject(resp).optJSONObject("data")
                data?.optString("token")?.takeIf { it.isNotBlank() }
            } else {
                AppLogger.w(TAG, "login http=$code resp=$resp")
                null
            }
        } catch (t: Throwable) {
            AppLogger.e(TAG, "login 异常: ${t.message}")
            null
        }
    }

    private fun tryBatchAdd(
        base: String,
        token: String,
        accountId: String,
        gids: List<Long>,
    ): SyncResult {
        return try {
            val arr = JSONArray()
            for (g in gids) arr.put(g)
            val body = JSONObject().put("gids", arr).toString()
            val headers = mapOf(
                "x-admin-token" to token,
                "x-account-id" to accountId,
            )
            val (code, resp) = httpPost("$base/api/friend-known-gids/batch-add", body, headers)
            if (code in 200..299) {
                val obj = JSONObject(resp)
                if (obj.optBoolean("ok", false)) {
                    val added = obj.optInt("addedCount", 0)
                    SyncResult(true, "同步成功：新增 $added 个，已有 ${gids.size - added} 个")
                } else {
                    SyncResult(false, "面板返回错误：${obj.optString("error", resp)}")
                }
            } else {
                SyncResult(false, "同步失败 HTTP $code：${truncate(resp, 160)}")
            }
        } catch (t: Throwable) {
            SyncResult(false, "同步异常：${t.message ?: t.javaClass.simpleName}")
        }
    }

    private fun httpPost(
        url: String,
        jsonBody: String,
        headers: Map<String, String>,
    ): Pair<Int, String> {
        val conn = URL(url).openConnection() as HttpURLConnection
        try {
            conn.requestMethod = "POST"
            conn.doOutput = true
            conn.connectTimeout = TIMEOUT_MS
            conn.readTimeout = TIMEOUT_MS
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setRequestProperty("Accept", "application/json")
            for ((k, v) in headers) conn.setRequestProperty(k, v)
            conn.outputStream.use { it.write(jsonBody.toByteArray(Charsets.UTF_8)) }
            val code = conn.responseCode
            val stream: InputStream? = if (code in 200..299) conn.inputStream else conn.errorStream
            val text = stream?.let { readAll(it) } ?: ""
            return code to text
        } finally {
            conn.disconnect()
        }
    }

    private fun readAll(stream: InputStream): String {
        val bos = ByteArrayOutputStream()
        val buf = ByteArray(4096)
        while (true) {
            val n = stream.read(buf)
            if (n < 0) break
            bos.write(buf, 0, n)
        }
        return bos.toString(Charsets.UTF_8.name())
    }

    private fun truncate(s: String, max: Int): String =
        if (s.length <= max) s else s.substring(0, max) + "..."
}

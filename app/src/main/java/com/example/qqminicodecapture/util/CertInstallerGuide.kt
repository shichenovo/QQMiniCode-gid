// 由 huojiujian 开源免费使用，二改请备注来源；地址 https://github.com/huojiujian2

package com.example.qqminicodecapture.util

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.Build
import android.provider.Settings

/**
 * 证书安装跳转助手
 *
 * Android 11+ 应用已无法通过 startActivityForResult 直接安装 CA 证书，
 * 必须把用户引导到系统设置（"加密与凭据"）。
 *
 * 不同厂商（MIUI/HyperOS/EMUI/ColorOS/OriginOS/FuntouchOS/OneUI...）
 * 的入口类名差异较大。这里列举几种常见跳转方式，按版本/厂商依次尝试。
 */
object CertInstallerGuide {

    private val KNOWN_CERT_SETTINGS: Array<ComponentName> = arrayOf(
        // 1. Android 原生（Android 12+）
        ComponentName(
            "com.android.settings",
            "com.android.settings.security.CredentialStorage"
        ),
        // 2. 部分设备的"安全"页入口
        ComponentName(
            "com.android.settings",
            "com.android.settings.Settings\$SecuritySettingsActivity"
        ),
        // 3. 小米 HyperOS / MIUI（独立页面）
        ComponentName(
            "com.miui.securitycenter",
            "com.miui.permcenter.autostart.AutoStartManagementActivity"
        ),
        // 4. 华为 EMUI / HarmonyOS
        ComponentName(
            "com.huawei.systemmanager",
            "com.huawei.systemmanager.optimize.process.ProtectActivity"
        ),
        // 5. OPPO ColorOS
        ComponentName(
            "com.coloros.safecenter",
            "com.coloros.safecenter.permission.startup.StartupAppListActivity"
        ),
        // 6. vivo OriginOS
        ComponentName(
            "com.vivo.permissionmanager",
            "com.vivo.permissionmanager.activity.BgStartUpManagerActivity"
        )
    )

    /**
     * 打开"加密与凭据"页面（Android 11+ 标准入口）
     */
    fun openSecuritySettings(context: Context): Boolean {
        val intents = listOfNotNull(
            try1(Settings.ACTION_SECURITY_SETTINGS),
            try1("android.settings.SECURITY_SETTINGS"),
            try1(Settings.ACTION_SETTINGS),
        )
        intents.forEach { i ->
            if (i != null) {
                try {
                    i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    context.startActivity(i)
                    return true
                } catch (_: Throwable) {}
            }
        }
        // 最后尝试厂商特定入口
        KNOWN_CERT_SETTINGS.forEach { c ->
            try {
                val i = Intent().apply {
                    component = c
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
                context.startActivity(i)
                return true
            } catch (_: Throwable) {}
        }
        return false
    }

    private fun try1(action: String): Intent? = Intent(action)

    /**
     * 判断是否需要"附近设备"权限（Android 12+ 的 Nearby devices）。
     * 本工具不强依赖该权限；当 VPN 在双机互通场景下可能被要求，
     * 故保留接口供后续扩展。
     */
    fun shouldRequestNearby(): Boolean = Build.VERSION.SDK_INT >= 31  // S 起 NEARBY_WIFI_DEVICES
}
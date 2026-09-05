// 由 huojiujian 开源免费使用，二改请备注来源；地址 https://github.com/huojiujian2

package com.example.qqminicodecapture.crypto

import android.content.Context
import android.util.Log
import com.example.qqminicodecapture.util.AppLogger
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Security
import java.security.cert.X509Certificate
import javax.security.auth.x500.X500Principal

/**
 * CA 证书与私钥管理
 *
 * 负责在 App 首次启动时生成 SHA-256 + RSA-2048 的自签 CA 证书，
 * 并持久化到 App 私有目录，供 SSLEngine 在 MITM 时签发动态服务端证书。
 *
 * 算法兼容性：
 *   - SHA-256 + RSA-2048 在 Android 13+ 系统中仍被认可为可信 CA 算法
 *   - 满足 Android 11 ~ Android 17 (API 30 ~ 37) 全段支持
 *
 * 修复要点：
 *   - 在 init 块中主动注册 BC Provider，避免 BKS 加载时找不到 Provider
 *   - ensurePemFile 不再依赖 Base64 辅助类，直接使用 Android 原生 Base64
 *   - readPem 改用更健壮的方式：每次重新确保 PEM 文件存在
 */
object CaManager {

    private const val TAG = "CaManager"

    private const val KS_PASSWORD = "qqminicode"           // keystore 密码（仅本地使用）
    private const val KS_FILE     = "ca_keystore.bks"       // BKS 密钥库文件名
    private const val PEM_FILE    = "QQMiniCodeCapture-CA.pem"

    private const val ALIAS       = "qqminicode-ca"
    private const val VALID_YEARS = 10

    // 在类加载时确保"完整版" BC Provider 已注册（Android 内置的是阉割版，不含签名算法）
    init {
        AppLogger.i(TAG, "CaManager 初始化，确保完整 BC Provider...")
        try {
            CertBuilder.ensureFullBcProvider()
            val p = Security.getProvider("BC")
            AppLogger.i(TAG, "当前 BC Provider 实现: ${p?.javaClass?.name ?: "未注册"}")
        } catch (t: Throwable) {
            AppLogger.e(TAG, "BC Provider 注册失败: ${t.message}")
            Log.e(TAG, "BC Provider registration failed", t)
        }
    }

    /**
     * 初始化：确保本地已存在 CA 证书与私钥。
     * 如果不存在则现场生成。
     *
     * @return Pair<X509Certificate, PrivateKey>，CA 与私钥
     */
    fun ensureCa(context: Context): Pair<X509Certificate, PrivateKey> {
        val baseDir = context.filesDir ?: throw IllegalStateException("filesDir is null")
        val ksFile  = File(baseDir, KS_FILE)
        val pemFile = File(baseDir, PEM_FILE)

        AppLogger.i(TAG, "ensureCa: ksFile=${ksFile.absolutePath}, exists=${ksFile.exists()}")

        // 1. 优先尝试加载已有证书
        if (ksFile.exists() && ksFile.length() > 0) {
            try {
                AppLogger.i(TAG, "尝试加载已有 BKS 密钥库...")
                val ks = KeyStore.getInstance("BKS", "BC")
                FileInputStream(ksFile).use {
                    ks.load(it, KS_PASSWORD.toCharArray())
                }
                val cert = ks.getCertificate(ALIAS) as X509Certificate
                val key  = ks.getKey(ALIAS, KS_PASSWORD.toCharArray()) as PrivateKey
                // 确保 PEM 文件存在（防止被用户误删后仍可导出）
                writePemFile(pemFile, cert)
                AppLogger.i(TAG, "成功加载已有 CA: ${cert.subjectX500Principal.name}")
                AppLogger.i(TAG, "当前 CA SHA-256 指纹: ${CaTrustChecker.sha256Fingerprint(cert)}")
                Log.i(TAG, "Loaded existing CA: ${cert.subjectX500Principal.name}")
                return Pair(cert, key)
            } catch (t: Throwable) {
                AppLogger.w(TAG, "加载已有密钥库失败: ${t.message}")
                Log.w(TAG, "Failed to load existing keystore, regenerating", t)
                // 删除损坏文件重新生成
                ksFile.delete()
                pemFile.delete()
            }
        }

        // 2. 生成新 CA（注意：一旦走到这里，旧 CA 就全部作废了！）
        AppLogger.w(TAG, "⚠⚠⚠ 正在生成【全新】CA！之前安装到系统的旧证书已全部失效，必须重新下载安装！")
        AppLogger.w(TAG, "⚠⚠⚠ 常见诱因：App 卸载重装 / 清除数据 / BKS 加载失败。请回主界面点\"检测证书信任状态\"确认。")
        AppLogger.i(TAG, "正在生成新的 SHA-256 + RSA-2048 CA 证书...")
        Log.i(TAG, "Generating new SHA-256 + RSA-2048 CA...")
        val (cert, key) = try {
            CertBuilder.selfSignCa(
                subject    = X500Principal("CN=QQMiniCodeCapture Local CA, O=QQMiniCodeCapture, C=CN"),
                validYears = VALID_YEARS
            )
        } catch (t: Throwable) {
            AppLogger.e(TAG, "CertBuilder.selfSignCa 生成失败: ${t.message}")
            throw t
        }

        // 3. 存入 BKS
        AppLogger.i(TAG, "保存 CA 到 BKS 密钥库...")
        val ks = KeyStore.getInstance("BKS", "BC")
        ks.load(null, null)
        ks.setKeyEntry(ALIAS, key, KS_PASSWORD.toCharArray(), arrayOf(cert))
        FileOutputStream(ksFile).use {
            ks.store(it, KS_PASSWORD.toCharArray())
        }

        // 4. 同时持久化 PEM 副本
        writePemFile(pemFile, cert)
        AppLogger.i(TAG, "CA 证书生成完成，已保存到: ${pemFile.name}")
        AppLogger.w(TAG, "新 CA SHA-256 指纹: ${CaTrustChecker.sha256Fingerprint(cert)}（请与系统已安装证书核对！）")

        return Pair(cert, key)
    }

    /**
     * 读取本地 PEM 字符串（用于导出/安装）
     * 每次调用都会确保 PEM 文件存在，避免因文件被删导致的读取失败。
     */
    fun readPem(context: Context): String {
        val baseDir = context.filesDir ?: throw IllegalStateException("filesDir is null")
        val pemFile = File(baseDir, PEM_FILE)
        AppLogger.i(TAG, "readPem: pemFile=${pemFile.absolutePath}, exists=${pemFile.exists()}")
        // 每次都通过 ensureCa 获取最新证书并确保 PEM 文件存在
        val (cert, _) = ensureCa(context)
        writePemFile(pemFile, cert)
        val content = pemFile.readText(Charsets.UTF_8)
        AppLogger.i(TAG, "readPem 成功，长度=${content.length}")
        return content
    }

    /**
     * 将 X509 证书写入 PEM 文件（总是覆盖写入，确保文件内容最新）
     */
    private fun writePemFile(pemFile: File, cert: X509Certificate) {
        val encoded = cert.encoded ?: throw IllegalStateException("cert.encoded returned null")
        val b64 = android.util.Base64.encodeToString(encoded, android.util.Base64.NO_WRAP)
        val pem = buildString {
            append("-----BEGIN CERTIFICATE-----\n")
            b64.chunked(64).forEach { append(it).append('\n') }
            append("-----END CERTIFICATE-----\n")
        }
        pemFile.writeText(pem, Charsets.UTF_8)
    }
}
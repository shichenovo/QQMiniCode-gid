// 由 huojiujian 开源免费使用，二改请备注来源；地址 https://github.com/huojiujian2

package com.example.qqminicodecapture.crypto

import com.example.qqminicodecapture.util.AppLogger
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.cert.CertPath
import java.security.cert.CertPathValidator
import java.security.cert.CertificateFactory
import java.security.cert.PKIXCertPathValidatorResult
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate

/**
 * CA 证书信任自检工具。
 *
 * 为什么需要它：
 *  App 的 CA 私钥保存在 filesDir（应用私有目录）。一旦 App 被卸载重装、
 *  "清除数据"，或 BKS 密钥库加载失败自动重生，CA 就会换成一把全新的；
 *  而系统"用户 CA 存储"里安装的还是旧证书。此时叶子证书的签发者已经
 *  对不上，客户端 TLS 校验必然报 SSLV3_ALERT_CERTIFICATE_UNKNOWN ——
 *  症状与"完全没装证书"一模一样，无法从报错本身区分。
 *
 *  本工具通过读取 AndroidCAStore（系统证书库，无需任何权限）完成三件事：
 *   1. 精确比对：用户存储中是否存在与当前 CA「主题 + 公钥」完全一致的证书
 *   2. 陈旧检测：存在同主题但公钥不同的旧 CA（说明重装后 CA 已轮换）
 *   3. 链路验证：用 CertPathValidator + 显式 TrustAnchor 集合做 PKIX 校验，
 *      证明证书构造本身可被任何信任用户 CA 的 App 接受
 *
 * 实现要点（踩过的坑，避免再次重蹈）：
 *  - 不要用 KeyStore.getInstance("BKS", "BC") 存锚点：Android 平台默认的
 *    CertPathValidator 可能不识别 BKS 类型的 KeyStore；用平台默认类型（JKS/PKCS12）
 *  - 不要用 TrustManagerFactory.init(CertPathTrustManagerParameters)：
 *    Android 平台的 TrustManagerFactorySpi 只接受 ApplicationConfigParameters，
 *    直接抛 "Only android.security.net.config.RootTrustManagerFactorySpi$ApplicationConfigParameters supported"
 *  - 正确做法：用 CertPathValidator.getInstance("PKIX").validate(certPath, PKIXParameters)
 *    手动构造 PKIX 校验，这是 Android 完全支持的、标准的 JDK API
 */
object CaTrustChecker {

    private const val TAG = "CaTrustChecker"

    sealed class Result {
        /** 用户存储中存在与当前 CA 完全一致的证书 */
        data class Trusted(val chainValidates: Boolean, val detail: String) : Result()
        /** 存在同主题旧证书但公钥不一致：App 数据被清除、CA 已轮换，需重新安装 */
        data class Stale(val detail: String) : Result()
        /** 用户存储中完全没有本 App 的 CA */
        data class NotFound(val detail: String) : Result()
        /** 读取证书存储失败 */
        data class Error(val detail: String) : Result()
    }

    /** 证书 SHA-256 指纹（十六进制小写） */
    fun sha256Fingerprint(cert: X509Certificate): String = try {
        MessageDigest.getInstance("SHA-256").digest(cert.encoded)
            .joinToString("") { "%02x".format(it) }
    } catch (_: Throwable) {
        "?"
    }

    /**
     * 执行完整自检。
     *
     * @param caCert  当前 App 内部使用的 CA 证书（签发叶子用的那把）
     * @param caKey   CA 私钥（用于现场签发一张测试叶子做链路验证）
     * @param testHost 测试叶子证书的域名（默认就是 MITM 目标域名）
     */
    fun check(
        caCert: X509Certificate,
        caKey: PrivateKey,
        testHost: String = "gate-obt.nqf.qq.com"
    ): Result {
        return try {
            val store = KeyStore.getInstance("AndroidCAStore")
            store.load(null)

            var exact: X509Certificate? = null
            var stale: X509Certificate? = null
            val aliases = store.aliases()
            while (aliases.hasMoreElements()) {
                val alias = aliases.nextElement()
                if (!alias.startsWith("user:")) continue   // 只关心用户安装的证书
                val c = store.getCertificate(alias) as? X509Certificate ?: continue
                val sameSubject = c.subjectX500Principal == caCert.subjectX500Principal
                val sameKey = c.publicKey.encoded.contentEquals(caCert.publicKey.encoded)
                if (sameSubject && sameKey) {
                    exact = c
                    break
                }
                if (sameSubject) stale = c
            }

            val fp = sha256Fingerprint(caCert)
            when {
                exact != null -> {
                    val chainOk = validateLeafChain(caCert, caKey, testHost)
                    AppLogger.i(TAG, "✓ 用户CA已安装且与当前签名CA一致 (指纹=$fp)")
                    Result.Trusted(
                        chainValidates = chainOk,
                        detail = "指纹=$fp, 叶子链PKIX校验=${if (chainOk) "通过" else "失败"}"
                    )
                }
                stale != null -> {
                    val msg = "用户存储中是【旧CA】(公钥不同)。当前CA指纹=$fp, " +
                            "已安装旧证书指纹=${sha256Fingerprint(stale)}。" +
                            "App 重装/清数据后 CA 已重新生成，请删除旧证书并重新安装新证书！"
                    AppLogger.e(TAG, "⚠ $msg")
                    Result.Stale(msg)
                }
                else -> {
                    val msg = "用户证书存储中未找到本 App 的 CA (当前指纹=$fp)，" +
                            "请先\"下载证书\"并安装到系统。"
                    AppLogger.e(TAG, "⚠ $msg")
                    Result.NotFound(msg)
                }
            }
        } catch (t: Throwable) {
            AppLogger.e(TAG, "读取系统证书存储失败: ${t.message}")
            Result.Error("读取系统证书存储失败: ${t.message}")
        }
    }

    /**
     * PKIX 校验叶子证书链，锚点 = 仅含"用户安装"证书。
     *
     * 关键：不用 TrustManagerFactory（Android 上 init 限制太多），
     *       直接用 CertPathValidator.getInstance("PKIX") + PKIXParameters，
     *       这是 JDK 标准 API，Android 平台 100% 支持。
     */
    private fun validateLeafChain(caCert: X509Certificate, caKey: PrivateKey, host: String): Boolean {
        return try {
            CertBuilder.ensureFullBcProvider()

            // 1. 现场签发一张测试叶子（走的就是 MITM 同一条代码路径，结果直接可信）
            val (leaf, _) = CertBuilder.issueLeaf(host, caCert, caKey)

            // 2. 构造 CertPath：[leaf, caCert]，顺序是"叶子在前，签发者在后"
            val factory = CertificateFactory.getInstance("X509")
            val certPath: CertPath = factory.generateCertPath(listOf(leaf, caCert))

            // 3. 收集所有"用户安装"证书作为唯一信任锚 —— 用 TrustAnchor 集合（不经过 KeyStore）
            val userStore = KeyStore.getInstance("AndroidCAStore")
            userStore.load(null)
            val anchors = HashSet<TrustAnchor>()
            val aliases = userStore.aliases()
            var anchorCount = 0
            while (aliases.hasMoreElements()) {
                val alias = aliases.nextElement()
                if (!alias.startsWith("user:")) continue
                userStore.getCertificate(alias)?.let {
                    if (it is X509Certificate) {
                        anchors.add(TrustAnchor(it, null))
                        anchorCount++
                    }
                }
            }
            if (anchorCount == 0) {
                AppLogger.e(TAG, "叶子链校验失败: 用户证书存储为空")
                return false
            }

            // 4. 本地 sanity：有效期 + 签名
            leaf.checkValidity()
            leaf.verify(caCert.publicKey)

            // 诊断：打印 issuer/subject 的 DER hex，方便排查链路不匹配
            AppLogger.i(TAG, "  leaf.issuer  DER: ${leaf.issuerX500Principal.encoded.joinToString("") { "%02x".format(it) }}")
            AppLogger.i(TAG, "  caCert.subject DER: ${caCert.subjectX500Principal.encoded.joinToString("") { "%02x".format(it) }}")
            AppLogger.i(TAG, "  issuer==subject: ${leaf.issuerX500Principal.encoded.contentEquals(caCert.subjectX500Principal.encoded)}")

            // 5. 标准 PKIX 校验 —— 这是 Android 完全支持的、标准的 JDK API
            //    注意：私 CA 无 CRL/OCSP，必须关闭吊销检查
            val params = PKIXParameters(anchors)
            params.isRevocationEnabled = false
            val validator = CertPathValidator.getInstance("PKIX")
            val result = validator.validate(certPath, params) as PKIXCertPathValidatorResult

            AppLogger.i(TAG, "✓ 叶子证书链(用户CA锚点, $anchorCount 个锚) PKIX 校验通过: $host")
            AppLogger.i(TAG, "  信任锚: ${result.trustAnchor.trustedCert.subjectX500Principal.name}")
            true
        } catch (t: Throwable) {
            AppLogger.e(TAG, "叶子证书链校验失败: ${t.message}")
            false
        }
    }
}
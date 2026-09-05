// 由 huojiujian 开源免费使用，二改请备注来源；地址 https://github.com/huojiujian2

package com.example.qqminicodecapture.crypto

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.Security
import java.security.cert.X509Certificate
import java.util.Date
import javax.security.auth.x500.X500Principal
import com.example.qqminicodecapture.util.AppLogger

/**
 * 证书构造工具（CA 自签 + MITM 叶子动态签发）
 *
 * 算法：SHA256 + RSA-2048
 *
 * 设计要点：
 *  - `selfSignCa(...)` 用于一次性生成应用级 CA（10 年有效）
 *  - `issueLeaf(...)` 用于每次 MITM 时针对目标域名动态签发叶子证书（1 年有效）
 *  - 叶子证书 SAN 必须包含目标主机名，否则 Android 13+ 校验会失败
 *  - 所有签名算法固定 SHA256WithRSA + BC provider，确保 Android 11~17 全段兼容
 */
object CertBuilder {

    init {
        ensureFullBcProvider()
    }

    private const val LOG_TAG = "CertBuilder"

    /**
     * 确保使用"完整的" BouncyCastle Provider。
     *
     * 关键背景：Android 系统自带一个阉割版 BC（com.android.org.bouncycastle），
     * 它不包含 SHA256WithRSA 等签名算法实现，如果直接使用会抛出：
     *   NoSuchAlgorithmException: no such algorithm: SHA256WITHRSA for provider BC
     *
     * 因此必须：
     *   1) 先检测当前注册的 "BC" 是不是完整版（org.bouncycastle.jce.provider.BouncyCastleProvider 实例）
     *   2) 如果是 Android 阉割版，先 removeProvider 再 addProvider 完整版
     */
    @Synchronized
    fun ensureFullBcProvider() {
        val existing = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)
        // 已经是完整版，直接返回
        if (existing is BouncyCastleProvider) return

        if (existing != null) {
            AppLogger.i(LOG_TAG, "检测到 Android 内置阉割版 BC（${existing.javaClass.name}），移除并替换为完整版...")
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
        }
        Security.addProvider(BouncyCastleProvider())
        val installed = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)
        AppLogger.i(LOG_TAG, "完整 BC Provider 已注册: ${installed?.javaClass?.name ?: "失败"}")
    }

    /**
     * 生成自签 CA
     */
    fun selfSignCa(
        subject: X500Principal,
        validYears: Int = 10
    ): Pair<X509Certificate, PrivateKey> {
        val kpg = KeyPairGenerator.getInstance("RSA", "BC")
        kpg.initialize(2048)
        val kp = kpg.generateKeyPair()

        val now  = System.currentTimeMillis()
        val from = Date(now - 60_000)
        val to   = Date(now + validYears * 365L * 24 * 3600 * 1000)
        val serial = (now / 1000) and 0x7FFFFFFF

        // 关键：必须用 getInstance(encoded) 从 DER 直接构造，不能用 X500Name(name) 从
        // RFC 2253 字符串重新解析 —— 那样会产生不同 DER 编码（如 PrintableString→UTF8String），
        // 导致 PKIX 链路校验时 leaf.issuer != caCert.subject → "subject/issuer name chaining check failed"
        val name = X500Name.getInstance(subject.encoded)
        val builder: X509v3CertificateBuilder = JcaX509v3CertificateBuilder(
            name,
            BigInteger.valueOf(serial.toLong()),
            from, to,
            name,
            kp.public
        )

        // CA 扩展
        builder.addExtension(Extension.basicConstraints, true, BasicConstraints(true))
        val ku = KeyUsage(KeyUsage.keyCertSign or KeyUsage.cRLSign)
        builder.addExtension(Extension.keyUsage, true, ku)
        builder.addExtension(
            Extension.extendedKeyUsage, false,
            ExtendedKeyUsage(arrayOf(KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth))
        )
        builder.addExtension(
            Extension.subjectKeyIdentifier, false,
            SubjectKeyIdentifier(kp.public.encoded)
        )

        val signer: ContentSigner = JcaContentSignerBuilder("SHA256WithRSA")
            .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(kp.private)
        val cert = JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .getCertificate(builder.build(signer))
        return Pair(cert, kp.private)
    }

    /**
     * 由已有 CA 签发叶子证书（MITM 时使用）。
     *
     * 返回 (叶子证书, 叶子私钥)：MITM 服务端 TLS 握手时两者必须配套使用。
     * 带缓存：RSA-2048 密钥对生成在手机上约需 100ms~1s，
     * 同一域名重复签发会拖垮抓包吞吐，Reqable 同样采用证书缓存策略。
     */
    private val leafCache =
        java.util.concurrent.ConcurrentHashMap<String, Pair<X509Certificate, PrivateKey>>()

    fun issueLeaf(
        cn: String,
        issuerCert: X509Certificate,
        issuerKey: PrivateKey
    ): Pair<X509Certificate, PrivateKey> {
        leafCache[cn]?.let { return it }

        val kpg = KeyPairGenerator.getInstance("RSA", "BC")
        kpg.initialize(2048)
        val kp = kpg.generateKeyPair()

        val now  = System.currentTimeMillis()
        val from = Date(now - 60_000)
        val to   = Date(now + 365L * 24 * 3600 * 1000)
        val serial = (now / 1000) and 0x7FFFFFFF

        // 关键修复：必须用 getInstance(encoded) 从 CA 证书的 DER 直接提取 issuer X500Name，
        // 不能用 X500Name(subjectX500Principal.name) 从 RFC 2253 字符串重新解析。
        // 后者会产生不同 DER 编码（PrintableString↔UTF8String 等），导致 PKIX 校验时
        // leaf.issuer DER ≠ caCert.subject DER → "subject/issuer name chaining check failed"
        val issuerName  = X500Name.getInstance(issuerCert.subjectX500Principal.encoded)
        val subjectName = X500Name("CN=$cn")

        val builder: X509v3CertificateBuilder = JcaX509v3CertificateBuilder(
            issuerName, BigInteger.valueOf(serial.toLong()),
            from, to, subjectName, kp.public
        )

        builder.addExtension(Extension.basicConstraints, true, BasicConstraints(false))
        val ku = KeyUsage(KeyUsage.digitalSignature or KeyUsage.keyEncipherment)
        builder.addExtension(Extension.keyUsage, true, ku)
        builder.addExtension(
            Extension.extendedKeyUsage, false,
            ExtendedKeyUsage(arrayOf(KeyPurposeId.id_kp_serverAuth))
        )
        builder.addExtension(
            Extension.subjectKeyIdentifier, false,
            SubjectKeyIdentifier(kp.public.encoded)
        )
        builder.addExtension(
            Extension.subjectAlternativeName, false,
            org.bouncycastle.asn1.x509.GeneralNames(
                org.bouncycastle.asn1.x509.GeneralName(
                    org.bouncycastle.asn1.x509.GeneralName.dNSName, cn
                )
            )
        )

        val signer: ContentSigner = JcaContentSignerBuilder("SHA256WithRSA")
            .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(issuerKey)
        val cert = JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .getCertificate(builder.build(signer))

        val pair = Pair(cert, kp.private)
        leafCache[cn] = pair
        return pair
    }
}
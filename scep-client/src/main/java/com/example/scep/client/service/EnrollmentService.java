package com.example.scep.client.service;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.RSAPublicKeySpec;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import com.example.scep.client.transport.ScepClient;
import com.example.scep.common.crypto.Crypto;
import com.example.scep.common.crypto.PemFiles;
import com.example.scep.common.protocol.enums.MessageTypeEnum;

/**
 * 客户端文件工作流：准备密钥、构造 CSR、调用协议客户端并保存证书。
 * <p>从客户端视角阅读：准备密钥 → 创建 CSR → 选择 CMS 身份 → 发送请求 → 保存证书。
 * CSR 与 CMS 的签名密钥分别选择，以支持“用旧身份申请新公钥证书”的换钥续期。</p>
 *
 * @author robin.li
 * @date 2026-11-20 21:52:59
 */
@Slf4j
public final class EnrollmentService {
    private static final int SERIAL_RADIX = 16;

    private EnrollmentService() {
    }

    /**
     * 准备注册/续期材料并保存结果，拒绝覆盖已存在的证书输出。
     *
     * @param options 显式类型的申请参数；续期身份与申请密钥分开保存
     * @param challenge 配置注入的初始注册口令；续期不使用，可以为 null
     * @return 已保存证书路径与序列号的中文说明
     * @throws Exception 配置、密钥/证书、网络请求或保存失败时抛出
     */
    public static String enroll(EnrollmentOptions options, String challenge) throws Exception {
        boolean renewalRequest = options.renewFrom() != null;
        log.info("开始证书申请，模式={}，端点={}，输出={}", renewalRequest ? "续期" : "注册", options.endpoint(),
                options.output().toAbsolutePath());
        // 先检查注册口令，配置缺失时不创建私钥，也不发起 HTTP 请求。
        if (options.renewFrom() == null && (challenge == null || challenge.isBlank())) {
            throw new IllegalArgumentException("首次注册必须配置 scep.client.challenge，可通过环境变量 SCEP_CHALLENGE 注入");
        }
        Path output = options.output();
        if (Files.exists(output)) {
            throw new IllegalArgumentException("输出证书已存在，请通过 --out 指定新文件");
        }
        X509Certificate trustedCa = PemFiles.certificate(options.ca());
        log.debug("已加载预配 CA，subject={}", trustedCa.getSubjectX500Principal().getName());
        ScepClient client = new ScepClient(options.endpoint(), trustedCa);
        Path keyPath = options.key();
        Path renewal = options.renewFrom();
        X509Certificate old = renewal == null ? null : PemFiles.certificate(renewal);
        // 旧身份私钥已经由配置/命令合并后明确指定，不能把换钥申请的新私钥误当成旧私钥。
        PrivateKey oldKey = old == null ? null : PemFiles.privateKey(options.signingKey());
        // pair 是申请的新证书所用密钥，oldKey 是续期身份私钥，两者可以不同。
        KeyPair pair;
        if (Files.exists(keyPath)) {
            PrivateKey privateKey = PemFiles.privateKey(keyPath);
            if (!(privateKey instanceof RSAPrivateCrtKey rsa)) {
                throw new IllegalArgumentException("需要包含 CRT 参数的 RSA 私钥");
            }
            // RSA CRT 私钥包含模数 n 和公钥指数 e，足够重建公钥，不必另存一份 public.key。
            PublicKey publicKey = KeyFactory.getInstance(Crypto.RSA_ALGORITHM)
                    .generatePublic(new RSAPublicKeySpec(rsa.getModulus(), rsa.getPublicExponent()));
            Crypto.requireRsa(publicKey);
            pair = new KeyPair(publicKey, privateKey);
            log.debug("复用已有申请私钥，路径={}", keyPath.toAbsolutePath());
        } else {
            pair = Crypto.rsa(Crypto.DEFAULT_RSA_BITS);
            // 新私钥先保存在本地，后续申请只发送公钥及签名，不把私钥交给 SCEP 服务端。
            PemFiles.create(keyPath, pair.getPrivate(), true);
            log.info("已生成申请私钥，路径={}", keyPath.toAbsolutePath());
        }
        X500Name subject = old == null ? new X500Name(options.subject())
                : X500Name.getInstance(old.getSubjectX500Principal().getEncoded());
        if (old != null && options.subject() != null && !subject.equals(new X500Name(options.subject()))) {
            throw new IllegalArgumentException("续期必须保持原证书主题不变");
        }
        // CSR 只含 subject、公钥、属性和签名；任何私钥都不会进入网络消息。
        JcaPKCS10CertificationRequestBuilder builder =
                new JcaPKCS10CertificationRequestBuilder(subject, pair.getPublic());
        if (old == null) {
            // 将口令写入 CSR 属性，后续整个 CSR 会被加密；不要把口令拼进 URL 或日志。
            builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword, new DERUTF8String(challenge));
        } else {
            // 续期沿用旧证书的 SAN，避免新 CSR 无意改变身份范围，触发服务端同身份策略拒绝。
            Extension san = new JcaX509CertificateHolder(old).getExtension(Extension.subjectAlternativeName);
            if (san != null) {
                builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, new Extensions(san));
            }
        }
        // 新私钥签 CSR，证明持有申请公钥的私钥；后续由 signingKey 签外层 CMS，证明提交身份。
        PKCS10CertificationRequest csr = builder.build(Crypto.signer(pair.getPrivate()));
        // 初次注册尚无正式证书，临时自签；续期直接携带旧证书，让服务端验证已获准的旧身份。
        X509Certificate identity = old == null ? Crypto.selfSigned(pair, subject) : old;
        PrivateKey signingKey = old == null ? pair.getPrivate() : oldKey;
        // 本地签一段随机数据，再用身份公钥验签，提前发现 --signing-key 与身份不匹配。
        // probe/proof 只用于本地检查，不是发往服务器的 SCEP nonce 或 CSR。
        Signature signature = Signature.getInstance(Crypto.RSA_SIGNATURE_ALGORITHM);
        byte[] probe = Crypto.randomBytes(Crypto.KEY_PROOF_BYTES);
        signature.initSign(signingKey);
        signature.update(probe);
        byte[] proof = signature.sign();
        signature.initVerify(identity.getPublicKey());
        signature.update(probe);
        if (!signature.verify(proof)) {
            throw new IllegalArgumentException("签名私钥与注册或续期身份不匹配");
        }
        // 两个分支都走 HTTP PKIOperation，只是外层签名属性 messageType 分别为 PKCSReq/RenewalReq。
        X509Certificate certificate = client.enroll(csr, signingKey, identity,
                old == null ? MessageTypeEnum.PKCS_REQ : MessageTypeEnum.RENEWAL_REQ);
        PemFiles.create(output, certificate, false);
        log.info("证书申请完成，模式={}，序列号={}，输出={}", renewalRequest,
                certificate.getSerialNumber().toString(SERIAL_RADIX), output.toAbsolutePath());
        return "证书已保存：" + output.toAbsolutePath() + "\n证书序列号：" + certificate.getSerialNumber().toString(SERIAL_RADIX);
    }

}

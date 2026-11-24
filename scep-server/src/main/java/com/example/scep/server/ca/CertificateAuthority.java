package com.example.scep.server.ca;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Date;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;

import com.example.scep.common.crypto.Crypto;
import com.example.scep.common.crypto.PemFiles;

/**
 * 本地文件 CA：管理签发者证书/私钥，把获准的 CSR 转成 X.509 证书并保存。
 *
 * <p>CA（Certificate Authority，证书颁发机构）用自己的私钥为“subject 与公钥的绑定”签名。
 * 客户端私钥不会被发送给 CA。本实现让同一对 CA 密钥兼任 SCEP 消息签名和解密，
 * 没有独立 RA（Registration Authority，注册机构）。</p>
 * <p>{@link #issue(PKCS10CertificationRequest, int, GeneralNames)} 假定服务层已经完成 CSR 验签和授权。
 * 文件记录只表示“本实例签发过”，不提供吊销状态查询。</p>
 *
 * @author robin.li
 * @date 2026-11-20 21:52:59
 */
@Slf4j
public final class CertificateAuthority {
    public static final String CERTIFICATE_FILE = "ca.pem";

    private static final String PRIVATE_KEY_FILE = "ca.key";

    private static final String ISSUED_DIRECTORY = "issued";

    private static final String CERTIFICATE_SUFFIX = ".pem";

    private static final int MAX_CA_VALIDITY_DAYS = 36500;

    private static final int SERIAL_RADIX = 16;

    private final Path depot;

    private final X509Certificate certificate;

    private final PrivateKey key;

    /**
     * 保存已经由 load 校验过的 CA 材料。
     *
     * @param depot       文件存储目录
     * @param certificate CA 证书
     * @param key         与证书公钥匹配的私钥
     */
    private CertificateAuthority(Path depot, X509Certificate certificate, PrivateKey key) {
        this.depot = depot;
        this.certificate = certificate;
        this.key = key;
    }

    /**
     * 显式生成自签根 CA，不覆盖已有证书或密钥。
     *
     * @param depot   输出目录，生成 ca.pem 和 ca.key
     * @param subject CA 的 X.500 名称，例如 "CN=Java SCEP CA,O=Example"
     * @param keyBits RSA 模数长度，2048..8192 位
     * @param days    CA 有效天数，1..36500
     * @throws Exception 配置无效、已有材料、密钥生成或文件写入失败时抛出
     */
    public static void initialize(Path depot, String subject, int keyBits, int days) throws Exception {
        log.info("开始初始化 CA，目录={}，subject={}，RSA 位数={}，有效期={} 天", depot.toAbsolutePath(), subject, keyBits,
                days);
        if (days < 1 || days > MAX_CA_VALIDITY_DAYS) {
            throw new IllegalArgumentException("CA 有效天数必须在 1～36500 之间");
        }
        Files.createDirectories(depot);
        // 不跟随符号链接检查目标是否已存在，已有链接也视为占用，避免覆盖或替换原来的 CA 身份。
        if (Files.exists(depot.resolve(CERTIFICATE_FILE), LinkOption.NOFOLLOW_LINKS)
                || Files.exists(depot.resolve(PRIVATE_KEY_FILE), LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalStateException("CA 已存在，不能覆盖：" + depot);
        }
        KeyPair pair = Crypto.rsa(keyBits);
        X500Name name = new X500Name(subject);
        Instant now = Instant.now();
        // 根 CA 是自签证书：issuer 和 subject 都是 name，证书公钥对应后面执行签名的本地私钥。
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(name, Crypto.serial(),
                Date.from(now.minusSeconds(Crypto.CLOCK_SKEW_SECONDS)), Date.from(now.plus(days, ChronoUnit.DAYS)),
                name, pair.getPublic());
        JcaX509ExtensionUtils extensions = new JcaX509ExtensionUtils();
        // BasicConstraints(0) 表示 CA=true、pathLenConstraint=0：常规证书链中不允许再接下级中间 CA。
        // digitalSignature/keyEncipherment 是它兼任 SCEP 签名者/接收者所需的用途。
        // addExtension 的第二个参数 true 表示 critical：证书使用方若不理解该扩展，应拒绝使用证书。
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(
                KeyUsage.keyCertSign | KeyUsage.cRLSign | KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        // SKI 标识本证书公钥，AKI 帮助找到签发者公钥；自签 CA 中二者指向同一对密钥。
        builder.addExtension(Extension.subjectKeyIdentifier, false,
                extensions.createSubjectKeyIdentifier(pair.getPublic()));
        builder.addExtension(Extension.authorityKeyIdentifier, false,
                extensions.createAuthorityKeyIdentifier(pair.getPublic()));
        X509Certificate cert = new JcaX509CertificateConverter().setProvider(Crypto.PROVIDER)
                .getCertificate(builder.build(Crypto.signer(pair.getPrivate())));
        // 完整写好临时材料后再发布。普通 I/O 失败仅回滚本次创建的密钥，绝不覆盖原文件。
        Path staging = Files.createTempDirectory(depot, ".ca-init-");
        boolean keyPublished = false;
        try {
            PemFiles.create(staging.resolve(PRIVATE_KEY_FILE), pair.getPrivate(), true);
            PemFiles.create(staging.resolve(CERTIFICATE_FILE), cert, false);
            // 不使用 REPLACE_EXISTING；发布时若目标已被其他初始化进程占用，应失败而不是替换它。
            Files.move(staging.resolve(PRIVATE_KEY_FILE), depot.resolve(PRIVATE_KEY_FILE));
            keyPublished = true;
            Files.move(staging.resolve(CERTIFICATE_FILE), depot.resolve(CERTIFICATE_FILE));
        } catch (Exception e) {
            if (keyPublished) {
                Files.deleteIfExists(depot.resolve(PRIVATE_KEY_FILE));
            }
            throw e;
        } finally {
            Files.deleteIfExists(staging.resolve(PRIVATE_KEY_FILE));
            Files.deleteIfExists(staging.resolve(CERTIFICATE_FILE));
            Files.deleteIfExists(staging);
        }
        log.info("CA 初始化完成，目录={}", depot.toAbsolutePath());
    }

    /**
     * 从 PEM 加载 CA 并检查有效期、RSA 参数、用途及证书与私钥的匹配关系。
     *
     * @param depot 包含 ca.pem 和 ca.key 的目录
     * @return 可用于当前实例签发与协议处理的 CA
     * @throws Exception 材料缺失、无效、不匹配或存储目录无法创建时抛出
     */
    public static CertificateAuthority load(Path depot) throws Exception {
        X509Certificate cert = PemFiles.certificate(depot.resolve(CERTIFICATE_FILE));
        PrivateKey key = PemFiles.privateKey(depot.resolve(PRIVATE_KEY_FILE));
        return load(cert, key, depot);
    }

    /**
     * 校验已读入的 CA 材料；材料可以来自 classpath，签发记录始终保存到可写目录。
     * @param cert CA 证书
     * @param key CA 私钥，必须与证书匹配
     * @param depot 外部数据目录，使用其 issued 子目录保存证书
     * @return 已验证、可以执行签发及 SCEP 解密的 CA
     * @throws Exception CA 无效、不匹配或记录目录不可写时抛出
     */
    public static CertificateAuthority load(X509Certificate cert, PrivateKey key, Path depot) throws Exception {
        log.info("加载 CA，subject={}，目录={}", cert.getSubjectX500Principal().getName(), depot.toAbsolutePath());
        // 资源读取与证书验证分离：不论文件来自 JAR 还是外部磁盘，执行相同的密码校验。
        cert.checkValidity();
        Crypto.requireRsa(cert.getPublicKey());
        boolean[] usage = cert.getKeyUsage();
        // KeyUsage 的数组下标按用途位排列：5=keyCertSign，0=digitalSignature，2=keyEncipherment。
        // 本实现让同一 CA 负责签证书、签 SCEP 响应和解请求，因此同时要求这三种用途。
        if (cert.getBasicConstraints() < 0 || usage == null || !usage[Crypto.KEY_CERT_SIGN_USAGE_INDEX]
                || !usage[Crypto.DIGITAL_SIGNATURE_USAGE_INDEX] || !usage[Crypto.KEY_ENCIPHERMENT_USAGE_INDEX]) {
            throw new IllegalArgumentException("CA 证书必须声明 CA=true，并包含证书签名、数字签名和密钥加密用途");
        }
        // 对随机内容做一次签名/验签，即可检查密钥匹配，无需比较或输出私钥参数。
        Signature signature = Signature.getInstance(Crypto.RSA_SIGNATURE_ALGORITHM);
        byte[] probe = Crypto.randomBytes(Crypto.KEY_PROOF_BYTES);
        signature.initSign(key);
        signature.update(probe);
        byte[] proof = signature.sign();
        signature.initVerify(cert);
        signature.update(probe);
        if (!signature.verify(proof)) {
            throw new IllegalArgumentException("CA 证书与私钥不匹配");
        }
        Files.createDirectories(depot.resolve(ISSUED_DIRECTORY));
        CertificateAuthority authority = new CertificateAuthority(depot, cert, key);
        log.info("CA 加载完成，序列号={}，签发记录目录={}", cert.getSerialNumber().toString(SERIAL_RADIX),
                depot.resolve(ISSUED_DIRECTORY).toAbsolutePath());
        return authority;
    }

    public X509Certificate certificate() {
        return certificate;
    }

    public PrivateKey key() {
        return key;
    }

    /**
     * 查询本地签发记录，除了序列号还比较整张证书，防止只凭同号误认身份。
     *
     * @param cert 请求签名者提交的旧证书
     * @return 本地有完全相同的证书时为 true；记录缺失或内容不同为 false
     * @throws IOException 已有记录损坏或读取失败时抛出，这属于服务故障
     * @throws Exception   证书元数据处理失败时抛出
     */
    public boolean isIssued(X509Certificate cert) throws Exception {
        // 文件名使用证书序列号定位候选记录；序列号属于 CA 的签发空间，与 SCEP transactionID 无关。
        Path path = depot.resolve(ISSUED_DIRECTORY)
                .resolve(cert.getSerialNumber().toString(SERIAL_RADIX) + CERTIFICATE_SUFFIX);
        if (Files.notExists(path, LinkOption.NOFOLLOW_LINKS)) {
            log.debug("未找到签发记录，序列号={}", cert.getSerialNumber().toString(SERIAL_RADIX));
            return false;
        }
        try {
            // 再比较完整 DER，不能仅凭文件存在或序列号相同，就认定它是本服务签发的那张证书。
            boolean issued = Arrays.equals(cert.getEncoded(), PemFiles.certificate(path).getEncoded());
            log.debug("检查签发记录，序列号={}，匹配={}", cert.getSerialNumber().toString(SERIAL_RADIX), issued);
            return issued;
        } catch (Exception e) {
            throw new IOException("无法读取已签发证书记录", e);
        }
    }

    /**
     * 签发固定权限的终端证书并保存，CSR 中的 CA/KeyUsage 不会被直接复制。
     *
     * <p>调用方必须先验证 CSR 签名、密钥长度及申请人的授权。此处只负责生成序列号、
     * 限制有效期、设置扩展、用 CA 签名及持久化。</p>
     *
     * @param csr  已验签且获准的 PKCS#10 请求，提供 subject 和公钥
     * @param days 新证书期望有效天数，实际到期时间不会超过 CA
     * @param san  服务层已经允许的 SAN，null 表示不添加该扩展
     * @return 已保存的 X.509 终端证书
     * @throws Exception CA 过期、证书构建/签名或文件保存失败时抛出
     */
    public X509Certificate issue(PKCS10CertificationRequest csr, int days, GeneralNames san) throws Exception {
        log.info("开始签发终端证书，subject={}，有效期={} 天，包含 SAN={}", csr.getSubject(), days, san != null);
        certificate.checkValidity();
        PublicKey publicKey = new JcaPKCS10CertificationRequest(csr).setProvider(Crypto.PROVIDER).getPublicKey();
        Instant now = Instant.now();
        Instant expiry = now.plus(days, ChronoUnit.DAYS);
        // 终端证书不能比签发它的 CA 更晚到期，否则即使自身仍在有效期内也无法建立有效链。
        if (expiry.isAfter(certificate.getNotAfter().toInstant())) {
            expiry = certificate.getNotAfter().toInstant();
        }
        // 向前宽限 5 分钟以容忍小幅时钟差，但证书有效期仍不能越过 CA 的边界。
        Instant start = now.minusSeconds(Crypto.CLOCK_SKEW_SECONDS);
        if (start.isBefore(certificate.getNotBefore().toInstant())) {
            start = certificate.getNotBefore().toInstant();
        }
        // issuer 来自 CA，subject/公钥来自获准的 CSR；证书内容由 CA 私钥签名，不需要申请者私钥。
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                X500Name.getInstance(certificate.getSubjectX500Principal().getEncoded()), Crypto.serial(),
                Date.from(start), Date.from(expiry), csr.getSubject(), publicKey);
        JcaX509ExtensionUtils extensions = new JcaX509ExtensionUtils();
        // BasicConstraints(false) 禁止充当 CA；KeyUsage 约束密码用途，EKU 进一步约束业务用途。
        // clientAuth 是本项目的签发模板，并不是 SCEP 协议只能申请这一类证书。
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth));
        builder.addExtension(Extension.subjectKeyIdentifier, false, extensions.createSubjectKeyIdentifier(publicKey));
        builder.addExtension(Extension.authorityKeyIdentifier, false,
                extensions.createAuthorityKeyIdentifier(certificate));
        // 这里只接受服务层已经批准的 SAN，不重新读取并无条件复制 CSR 中的扩展。
        if (san != null) {
            builder.addExtension(Extension.subjectAlternativeName, false, san);
        }
        // build 完成 X.509 证书自身的 CA 签名；SCEP 响应的外层签名稍后由 ScepCodec.success 生成。
        X509Certificate issued = new JcaX509CertificateConverter().setProvider(Crypto.PROVIDER)
                .getCertificate(builder.build(Crypto.signer(key)));
        // 保存的是公开证书；请求方私钥始终留在客户端。先保存再返回，避免未记录的“成功签发”。
        PemFiles.create(depot.resolve(ISSUED_DIRECTORY)
                .resolve(issued.getSerialNumber().toString(SERIAL_RADIX) + CERTIFICATE_SUFFIX), issued, false);
        log.info("终端证书签发完成，序列号={}，subject={}", issued.getSerialNumber().toString(SERIAL_RADIX),
                issued.getSubjectX500Principal().getName());
        return issued;
    }
}

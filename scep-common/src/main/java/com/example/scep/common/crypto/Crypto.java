package com.example.scep.common.crypto;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Java JCA/JCE 与 Bouncy Castle 的共用密码操作。
 * <p>JCA 提供 KeyPair、PrivateKey、Signature 等统一接口，Provider 提供具体算法实现。
 * 这里显式传入 BC Provider，不改变整个 JVM 的全局 Provider 顺序。</p>
 *
 * @author robin.li
 * @date 2026-11-20 21:52:59
 */
@Slf4j
public final class Crypto {
    public static final String RSA_ALGORITHM = "RSA";

    public static final String RSA_SIGNATURE_ALGORITHM = "SHA256withRSA";

    public static final String SHA256_ALGORITHM = "SHA-256";

    public static final int DEFAULT_RSA_BITS = 2048;

    private static final int MIN_RSA_BITS = 2048;

    private static final int MAX_RSA_BITS = 8192;

    /** 随机序列号保留符号位，保证 ASN.1 编码不超过 20 字节。 */
    private static final int SERIAL_RANDOM_BITS = 159;

    /** 证书生效时间向前宽限 5 分钟，容忍少量时钟差。 */
    public static final int CLOCK_SKEW_SECONDS = 300;

    /** 本地私钥匹配检查使用的随机数据长度，不是协议 nonce。 */
    public static final int KEY_PROOF_BYTES = 32;

    /** X509Certificate.getKeyUsage() 返回布尔数组的位下标，不能使用 BC 的位掩码值索引。 */
    public static final int DIGITAL_SIGNATURE_USAGE_INDEX = 0;

    public static final int KEY_ENCIPHERMENT_USAGE_INDEX = 2;

    public static final int KEY_CERT_SIGN_USAGE_INDEX = 5;

    /** 临时注册身份只使用一天。 */
    private static final int INITIAL_IDENTITY_VALIDITY_DAYS = 1;

    // 显式把 Provider 传给 BC 构建器，不调用 Security.addProvider 改变整个应用的密码算法选择顺序。
    public static final Provider PROVIDER = new BouncyCastleProvider();

    // nonce、内容标识和密钥生成需要密码学随机性；普通 Random 的可预测性不适合这些用途。
    private static final SecureRandom RANDOM = new SecureRandom();

    private Crypto() {
    }

    /**
     * 生成本项目允许长度的 RSA 密钥对。
     *
     * @param bits 模数位数，2048..8192
     * @return 公钥与私钥；只有公钥会写入 CSR
     * @throws IllegalArgumentException 位数超出项目策略时抛出
     * @throws GeneralSecurityException RSA 密钥生成失败时抛出
     */
    public static KeyPair rsa(int bits) throws GeneralSecurityException {
        if (bits < MIN_RSA_BITS || bits > MAX_RSA_BITS) {
            throw new IllegalArgumentException("RSA 密钥长度必须在 2048～8192 位之间");
        }
        KeyPairGenerator generator = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        // bits 指 RSA 模数位数；同一个 SecureRandom 可复用，但每次生成的密钥材料应独立。
        generator.initialize(bits, RANDOM);
        KeyPair pair = generator.generateKeyPair();
        log.debug("生成 RSA 密钥对，位数={}", bits);
        return pair;
    }

    /**
     * 检查密钥是否满足当前 RSA 实现的范围；这不是 SCEP 对所有实现的算法限制。
     *
     * @param key CSR 或签名证书中的公钥
     * @throws IllegalArgumentException 不是 RSA 或位数不在 2048..8192 时抛出
     */
    public static void requireRsa(PublicKey key) {
        if (!(key instanceof RSAPublicKey rsa) || rsa.getModulus().bitLength() < MIN_RSA_BITS
                || rsa.getModulus().bitLength() > MAX_RSA_BITS) {
            throw new IllegalArgumentException("仅支持 2048～8192 位 RSA 密钥");
        }
    }

    /**
     * 用密码学随机源生成 nonce、事务标识等材料，不能替换为 java.util.Random。
     *
     * @param size 字节数
     * @return 新分配的随机字节数组
     */
    public static byte[] randomBytes(int size) {
        byte[] bytes = new byte[size];
        RANDOM.nextBytes(bytes);
        return bytes;
    }

    /**
     * 生成正的随机证书序列号，以较大空间降低碰撞概率；不承担 SCEP transactionID 的作用。
     *
     * @return ASN.1 INTEGER 表示的正整数
     */
    public static BigInteger serial() {
        // 保证正数且控制编码长度；随机序列号用于证书标识，不用来判断申请是否已经获准。
        return new BigInteger(SERIAL_RANDOM_BITS, RANDOM).add(BigInteger.ONE);
    }

    /**
     * 构造 BC 的流式签名器，供 CSR、X.509 证书和 CMS 的构建器使用。
     *
     * @param key 执行签名的 RSA 私钥
     * @return 使用 SHA-256 摘要和 RSA 签名的 ContentSigner
     * @throws org.bouncycastle.operator.OperatorCreationException 无法构建签名器时抛出
     */
    public static ContentSigner signer(PrivateKey key) throws OperatorCreationException {
        // 构建器负责把待签名的 ASN.1 内容写入此签名器；SHA-256 计算摘要，RSA 私钥执行签名。
        return new JcaContentSignerBuilder(RSA_SIGNATURE_ALGORITHM).setProvider(PROVIDER).build(key);
    }

    /**
     * 生成初始注册使用的临时自签终端证书，不是向 CA 申请的最终证书。
     * <p>它让尚无正式证书的客户端能够签署 CMS，并让 CA 找到响应加密所需的公钥。
     * 自签名只证明密钥自洽，签发授权仍取决于 challenge 等外部策略。</p>
     *
     * @param key     客户端身份密钥对
     * @param subject 临时身份的 X.500 名称
     * @return 有效期约一天、允许签名和密钥加密的非 CA 证书
     * @throws Exception 证书扩展构建、编码或签名失败时抛出
     */
    public static X509Certificate selfSigned(KeyPair key, X500Name subject) throws Exception {
        Instant now = Instant.now();
        // issuer=subject 且使用自己的私钥签名；这是注册前的临时身份，不是 CA 授权的正式设备证书。
        JcaX509v3CertificateBuilder builder =
                new JcaX509v3CertificateBuilder(subject, serial(), Date.from(now.minusSeconds(CLOCK_SKEW_SECONDS)),
                        Date.from(now.plus(INITIAL_IDENTITY_VALIDITY_DAYS, ChronoUnit.DAYS)), subject, key.getPublic());
        // 允许签 CMS 与接收 RSA 密钥传输；禁止充当 CA，避免将临时身份误用为证书签发者。
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        X509Certificate certificate = new JcaX509CertificateConverter().setProvider(PROVIDER)
                .getCertificate(builder.build(signer(key.getPrivate())));
        log.debug("生成临时自签身份，subject={}，序列号={}", subject, certificate.getSerialNumber().toString(16));
        return certificate;
    }
}

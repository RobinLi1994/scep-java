package com.example.scep.server.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import javax.security.auth.x500.X500Principal;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;

import com.example.scep.common.crypto.Crypto;
import com.example.scep.common.protocol.ScepCodec;
import com.example.scep.common.protocol.ScepProtocolException;
import com.example.scep.common.protocol.enums.FailInfoEnum;
import com.example.scep.common.protocol.enums.MessageTypeEnum;
import com.example.scep.server.ca.CertificateAuthority;

/**
 * SCEP 服务端的业务入口：决定“这份通过密码校验的申请，是否允许签发”。
 *
 * <p>学习时可从 {@link #handle(byte[])} 顺序阅读：外层验签、内层解密、CSR 验签、
 * 注册或续期授权、签发、封装响应。CMS 解决消息保护，业务策略决定申请人可以获得什么身份。</p>
 * <p>初始注册依赖 challengePassword；续期依赖已签发旧证书及其私钥。
 * 静态 challenge、RSA 长度限制、SAN 默认关闭、续期窗口、同 subject/SAN 和文件记录检查
 * 是本项目的策略，不应理解为所有 SCEP 服务都必须采用的相同规则。</p>
 *
 * @author robin.li
 * @date 2026-11-20 21:52:59
 * @see ScepCodec
 * @see <a href="https://www.rfc-editor.org/rfc/rfc8894.html#section-2.4">RFC 8894 §2.4：签发授权</a>
 */
@Slf4j
public final class ScepService {
    /**
     * 终端证书有效期和续期窗口的部署策略上限，单位为天。
     */
    private static final int MAX_CERTIFICATE_DAYS = 3650;

    private final CertificateAuthority ca;

    private final byte[] challenge;

    private final int validityDays;

    private final int renewalDays;

    private final boolean allowSan;

    /**
     * 创建永久拒绝单 DES 的签发服务（RFC 8894 §2.9）。
     *
     * @param ca           已加载的 CA 及证书存储
     * @param challenge    初始注册的静态共享口令，必须非空白
     * @param validityDays 新证书有效天数
     * @param renewalDays  旧证书到期前多少天允许续期，0 表示不限制提前时间
     * @param allowSan     是否允许申请 Subject Alternative Name（主题备用名称）
     * @throws IllegalArgumentException 口令或天数配置无效时抛出
     */
    public ScepService(CertificateAuthority ca, String challenge, int validityDays, int renewalDays, boolean allowSan) {
        if (challenge == null || challenge.isBlank()) {
            throw new IllegalArgumentException("必须配置环境变量 SCEP_CHALLENGE 作为注册口令");
        }
        if (validityDays < 1 || validityDays > MAX_CERTIFICATE_DAYS || renewalDays < 0
                || renewalDays > MAX_CERTIFICATE_DAYS) {
            throw new IllegalArgumentException("证书有效天数必须为 1～3650，续期窗口必须为 0～3650 天");
        }
        this.ca = ca;
        this.challenge = challenge.getBytes(StandardCharsets.UTF_8);
        this.validityDays = validityDays;
        this.renewalDays = renewalDays;
        this.allowSan = allowSan;
    }

    /**
     * 比较完整 DN（Distinguished Name，主题可分辨名称），而不是只比较 CN。
     *
     * @param csr         待续期的证书申请
     * @param certificate 原身份的证书
     * @return 按 X500Principal 规范化规则且保留 RDN 层次顺序比较的结果
     * @throws Exception CSR subject 无法编码为 X.500 名称时抛出
     */
    private static boolean sameSubject(PKCS10CertificationRequest csr, X509Certificate certificate) throws Exception {
        // X500Principal 保留 RDN 顺序；BC 默认 X500Name.equals 会忽略 RDN 顺序。
        return new X500Principal(csr.getSubject().getEncoded()).equals(certificate.getSubjectX500Principal());
    }

    /**
     * 从 PKCS#10 的 PKCS#9 challengePassword 属性取口令；它不是 HTTP 参数或证书扩展。
     *
     * @param csr 已验证签名的申请
     * @return 用于口令比较的 UTF-8 字节
     * @throws IllegalArgumentException 口令缺失、重复、多值或不是 ASN.1 字符串时抛出
     */
    private static byte[] challenge(PKCS10CertificationRequest csr) {
        // challengePassword 位于 CSR 的 attributes 中；外层信封解密后才能读取，不从 URL 中取值。
        Attribute[] attributes = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_challengePassword);
        // 同一口令属性出现多次或含多个值会造成解释歧义，因此不会随意选择“第一个值”。
        if (attributes.length != 1 || attributes[0].getAttrValues().size() != 1
                || !(attributes[0].getAttrValues().getObjectAt(0) instanceof ASN1String value)) {
            throw new IllegalArgumentException("注册口令 challengePassword 缺失或重复");
        }
        return value.getString().getBytes(StandardCharsets.UTF_8);
    }

    /**
     * 从 CSR 的 extensionRequest 属性中提取 SAN，但不自动授予所申请的证书权限。
     *
     * @param csr 已验证签名的申请
     * @return 申请的 SAN，没有申请时为 null
     * @throws IllegalArgumentException 扩展请求存在歧义、无法解析或包含不支持的关键扩展时抛出
     */
    private static GeneralNames requestedSan(PKCS10CertificationRequest csr) {
        // extensionRequest 是 CSR 属性；它里面再装一组“希望写进新证书的 X.509 扩展”。
        Attribute[] requests = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        if (requests.length > 1 || (requests.length == 1 && requests[0].getAttrValues().size() != 1)) {
            throw new IllegalArgumentException("扩展申请 extensionRequest 重复");
        }
        Extensions extensions = csr.getRequestedExtensions();
        if (extensions == null) {
            // 没有扩展请求是合法情况，表示此次没有申请 SAN。
            return null;
        }
        // 未支持的关键扩展不可静默忽略。BasicConstraints/KeyUsage/EKU 由本服务固定。
        for (ASN1ObjectIdentifier oid : extensions.getCriticalExtensionOIDs()) {
            if (!oid.equals(Extension.basicConstraints) && !oid.equals(Extension.keyUsage)
                    && !oid.equals(Extension.extendedKeyUsage) && !oid.equals(Extension.subjectAlternativeName)) {
                throw new IllegalArgumentException("CSR 包含不支持的关键扩展");
            }
        }
        Extension extension = extensions.getExtension(Extension.subjectAlternativeName);
        // 这里只提取 SAN，允许与否由 handle 决定；CA 不会照搬 CSR 提出的全部证书权限。
        return extension == null ? null : GeneralNames.getInstance(extension.getParsedValue());
    }

    /**
     * 完成一次同步注册或续期；请求的 HTTP GET/POST 差异已由 Controller 消除。
     *
     * <p>无法可信解析的外层消息向上抛出异常；已解析的请求若不满足策略则返回签名失败响应。
     * 算法不支持返回 badAlg，找不到续期证书返回 badCertId，CSR 和授权策略拒绝返回 badRequest。
     * CMS 完整性错误只有在能够取得可信上下文时才可编码为 badMessageCheck；外层验签失败时
     * 不信任请求中的事务和接收者信息，因此继续向上抛出异常。存储和签发异常保留为服务故障。</p>
     *
     * @param encoded 外层 SignedData 二进制字节
     * @return 完整 CertRep；返回字节并不意味着签发成功，客户端仍要检查 pkiStatus
     * @throws IllegalArgumentException 外层消息或签名无效时抛出
     * @throws Exception                存储、CA 签发或响应编码失败时抛出
     */
    public byte[] handle(byte[] encoded) throws Exception {
        log.info("开始处理 SCEP 请求，报文大小={} 字节", encoded.length);
        // 1. CMS 验签仅证明请求由消息中那张证书的私钥持有者签名；该证书仍可能是自签的。
        ScepCodec.Message message = ScepCodec.decodeRequest(encoded);
        log.info("请求验签通过，transactionId={}，messageType={}，签名者={}", message.transactionId(),
                message.type().getCode(), message.signer().getSubjectX500Principal().getName());
        // 同一个 HTTP PKIOperation 可承载不同消息；本服务只处理初始注册 19 和续期 17。
        if (message.type() != MessageTypeEnum.PKCS_REQ && message.type() != MessageTypeEnum.RENEWAL_REQ) {
            return failure(message, FailInfoEnum.BAD_REQUEST);
        }
        byte[] decrypted;
        try {
            // 2. CSR（包括 challenge）在内层信封中，先由 CA 私钥解开内容密钥才能读取。
            decrypted = ScepCodec.decrypt(message.content(), ca.key(), ca.certificate());
        } catch (ScepProtocolException e) {
            // 解密算法不受支持属于 badAlg；失败原因只有在外层请求已验签时才进入签名回复。
            log.warn("SCEP 请求解密协议失败，transactionId={}，failInfo={}", message.transactionId(),
                    e.failInfo().getCode(), e);
            return failure(message, e.failInfo());
        } catch (Exception e) {
            // 密钥不匹配、填充错误等无法证明是算法协商问题，按 RFC 的 catch-all badRequest 返回。
            log.warn("SCEP 请求解密失败，transactionId={}", message.transactionId(), e);
            return failure(message, FailInfoEnum.BAD_REQUEST);
        }
        PKCS10CertificationRequest csr;
        GeneralNames san;
        try {
            // 3. CSR 自身也有签名：用“申请的新公钥”验证 PoP（Proof of Possession，私钥持有证明）。
            // 这与外层 CMS 验签是两次不同校验，尤其在换钥续期时不能互相替代。
            csr = new PKCS10CertificationRequest(decrypted);
            // 公钥来自申请本身；即使外层旧证书签名合法，也不能替代对新公钥的私钥持有证明。
            PublicKey publicKey = new JcaPKCS10CertificationRequest(csr).setProvider(Crypto.PROVIDER).getPublicKey();
            try {
                Crypto.requireRsa(publicKey);
            } catch (IllegalArgumentException e) {
                // CSR 的公钥算法或参数不在服务能力范围内，使用 badAlg，而不是笼统的 badRequest。
                log.warn("CSR 公钥算法或参数不受支持，transactionId={}", message.transactionId(), e);
                return failure(message, FailInfoEnum.BAD_ALG);
            }
            if (!csr.isSignatureValid(
                    new JcaContentVerifierProviderBuilder().setProvider(Crypto.PROVIDER).build(publicKey))) {
                return failure(message, FailInfoEnum.BAD_REQUEST);
            }
            if (csr.getSubject().getRDNs().length == 0) {
                throw new IllegalArgumentException("CSR 主题不能为空");
            }
            // 检查身份凭据当前有效且可用于签名；是否为本 CA 签发，在续期分支再判断。
            validateSigner(message.signer());
            san = requestedSan(csr);
            // SAN 可承载 DNS 名称等额外身份；开启开关只表示接受该字段，不等于完成设备归属核验。
            if (san != null && !allowSan) {
                throw new IllegalArgumentException("申请 SAN 需要显式开启对应授权策略");
            }
            if (message.type() == MessageTypeEnum.PKCS_REQ) {
                // 4a. 自签证书不能证明设备获准入网；这里的注册授权来自 CSR 中的共享口令。
                // 使用 MessageDigest.isEqual 比较口令字节，避免普通字符串比较按首个不同字符提前结束。
                if (!MessageDigest.isEqual(challenge, challenge(csr))) {
                    throw new IllegalArgumentException("注册口令不匹配");
                }
                // RFC 8894 建议初始签名身份与 CSR 同名（SHOULD），因此这里允许二者 subject 不同。
                // 初始身份与 CSR 必须使用同一公钥，让申请公钥持有者同时具备解密成功响应的能力。
                if (!Arrays.equals(publicKey.getEncoded(), message.signer().getPublicKey().getEncoded())) {
                    throw new IllegalArgumentException("首次注册的签名身份公钥必须与 CSR 公钥一致");
                }
                // 用证书自己的公钥验证证书签名，确认这是自签身份；它仍不是 CA 签发的可信终端证书。
                message.signer().verify(message.signer().getPublicKey(), Crypto.PROVIDER);
            } else {
                // 4b. 续期由旧身份授权；CSR 可以换公钥，但不能借续期扩大 subject/SAN 身份范围。
                validateRenewal(message.signer(), csr, san);
            }
        } catch (Exception e) {
            // CSR 格式、私钥证明和授权校验失败使用相同协议错误；不要通过响应暴露口令等细节。
            log.warn("SCEP 请求授权校验失败，transactionId={}", message.transactionId(), e);
            return failure(message, FailInfoEnum.BAD_REQUEST);
        }
        // 旧证书必须在本实例的签发记录中；“证书缺失”拒绝续期，“记录损坏”则作为服务故障向上抛出。
        if (message.type() == MessageTypeEnum.RENEWAL_REQ && !ca.isIssued(message.signer())) {
            // RFC 8894 的 badCertId 表示没有找到与续期条件匹配的证书，而不是一般授权拒绝。
            log.warn("续期证书无本地签发记录，transactionId={}，序列号={}", message.transactionId(),
                    message.signer().getSerialNumber().toString(16));
            return failure(message, FailInfoEnum.BAD_CERT_ID);
        }
        // 5. 先保存证书，再回复成功；本实现不做事务去重，重试成功可能产生另一张证书。
        X509Certificate issued = ca.issue(csr, validityDays, san);
        log.info("SCEP 请求处理成功，transactionId={}，证书序列号={}", message.transactionId(),
                issued.getSerialNumber().toString(16));
        return ScepCodec.success(message, issued, ca.certificate(), ca.key());
    }

    /**
     * 检查请求签名证书当前有效且适合终端签名；这一步尚不验证它由哪个 CA 签发。
     *
     * @param signer 外层 CMS 的签名证书
     * @throws Exception 证书过期、尚未生效、属于 CA 或显式禁止数字签名时抛出
     */
    private void validateSigner(X509Certificate signer) throws Exception {
        signer.checkValidity();
        boolean[] usage = signer.getKeyUsage();
        // BasicConstraints >= 0 表示 CA；KeyUsage[0] 是 digitalSignature，若显式声明则必须允许签名。
        // 这里允许旧客户端省略 KeyUsage 扩展，但不会把 CA 证书当作设备身份使用。
        if (signer.getBasicConstraints() >= 0 || (usage != null && !usage[Crypto.DIGITAL_SIGNATURE_USAGE_INDEX])) {
            throw new IllegalArgumentException("注册请求的签名证书无效");
        }
    }

    /**
     * 检查旧证书对续期的授权：当前 CA 签发、subject/SAN 保持一致、进入续期窗口。
     *
     * @param signer 已检查当前有效期的旧证书
     * @param csr    新的申请，可包含不同的公钥
     * @param san    从新 CSR 提取的 SAN，null 表示未申请
     * @throws Exception 旧证书签名、签发者、身份范围或续期时间不符合策略时抛出
     */
    private void validateRenewal(X509Certificate signer, PKCS10CertificationRequest csr, GeneralNames san)
            throws Exception {
        // 外层 CMS 已证明提交者持有旧私钥；这里再验证“旧证书本身确实由当前 CA 签署”。
        signer.verify(ca.certificate().getPublicKey(), Crypto.PROVIDER);
        if (!signer.getIssuerX500Principal().equals(ca.certificate().getSubjectX500Principal())) {
            throw new IllegalArgumentException("续期证书不是本 CA 记录中的已签发证书");
        }
        // 允许更换密钥，但不能凭已有证书把 subject 改成另一台设备或另一个用户。
        if (!sameSubject(csr, signer)) {
            throw new IllegalArgumentException("续期不能修改证书主题");
        }
        Extension oldExtension = new JcaX509CertificateHolder(signer).getExtension(Extension.subjectAlternativeName);
        // 当前策略比较 SAN 的 ASN.1 编码：即使仅重排列表，也不会被视为相同申请。
        byte[] oldSan = oldExtension == null ? null : oldExtension.getParsedValue().toASN1Primitive().getEncoded();
        byte[] newSan = san == null ? null : san.getEncoded();
        if (!Arrays.equals(oldSan, newSan)) {
            throw new IllegalArgumentException("续期不能修改主题备用名称 SAN");
        }
        // 例如 renewalDays=14，只允许在旧证书到期前 14 天内续期；0 表示取消“最早续期时间”限制。
        // 旧证书仍须当前有效，前面的 validateSigner 已拒绝过期证书。
        if (renewalDays > 0
                && Instant.now().isBefore(signer.getNotAfter().toInstant().minus(renewalDays, ChronoUnit.DAYS))) {
            throw new IllegalArgumentException("证书尚未进入允许续期的时间窗口");
        }
    }

    /**
     * 用 CA 身份签署协议拒绝结果，HTTP 层仍可以正常返回 200。
     *
     * @param message  已验签的请求，提供事务标识和 nonce
     * @param failInfo SCEP 协议失败原因枚举
     * @return CertRep FAILURE 编码
     * @throws Exception 失败响应本身无法签名或编码时抛出
     */
    private byte[] failure(ScepCodec.Message message, FailInfoEnum failInfo) throws Exception {
        return ScepCodec.failure(message, failInfo, ca.certificate(), ca.key());
    }
}

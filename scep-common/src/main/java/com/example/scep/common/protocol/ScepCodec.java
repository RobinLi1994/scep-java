package com.example.scep.common.protocol;

import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Set;

import lombok.extern.slf4j.Slf4j;
import lombok.Value;
import lombok.experimental.Accessors;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1PrintableString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSSignerDigestMismatchException;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.Store;

import com.example.scep.common.crypto.Crypto;
import com.example.scep.common.protocol.enums.FailInfoEnum;
import com.example.scep.common.protocol.enums.MessageTypeEnum;
import com.example.scep.common.protocol.enums.PkiStatusEnum;

/**
 * SCEP 消息编解码器：把 Java 的 CSR、证书转换为 HTTP 上传输的 CMS 二进制消息。
 *
 * <p>读本类时先区分三个概念：PKCS#10 是“申请签发什么证书”的 CSR；
 * CMS EnvelopedData 负责加密；CMS SignedData 负责签名。CMS 是 PKCS#7 的后继标准。
 * 对应本项目的实际消息结构如下：</p>
 * <pre>
 * 注册/续期请求：SignedData(客户端签名) → EnvelopedData(给 CA) → PKCS#10 CSR
 * 成功响应：    SignedData(CA 签名)     → EnvelopedData(给请求签名者) → 仅含证书的 SignedData
 * 失败响应：    SignedData(CA 签名，含失败属性，省略 eContent)
 * </pre>
 * <p>SCEP 的 transactionID、messageType 等属性在外层 signedAttrs 中，受到签名保护，
 * 但不属于加密的 CSR。它们与 HTTP 查询参数 operation 是不同层次的数据。
 * 输出统一使用 DER（ASN.1 的确定性二进制编码），便于不同协议实现之间互通。</p>
 *
 * <p>本类只处理密码消息；签名有效不等于允许签发，授权由
 * 服务端签发服务完成，common 不依赖服务端模块。</p>
 *
 * @author robin.li
 * @date 2026-11-20 21:52:59
 * @see <a href="https://www.rfc-editor.org/rfc/rfc8894.html#section-3">RFC 8894 §3：消息结构</a>
 */
@Slf4j
public final class ScepCodec {
    private ScepCodec() {
    }

    /**
     * 客户端先加密 CSR，再签名整个 SCEP 请求。
     *
     * @param csr    已由申请公钥对应私钥签名的 PKCS#10 请求
     * @param key    外层签名私钥；续期时是旧身份的私钥，可不同于 CSR 私钥
     * @param signer 外层签名证书，也是成功响应的加密接收者
     * @param ca     可信 CA 证书，用于加密请求内层
     * @param type   PKCS_REQ 为初始注册，RENEWAL_REQ 为续期；线上值由枚举 code 指定
     * @return 二进制请求及后续响应校验所需的事务上下文
     * @throws Exception CSR 编码、加密或签名失败时抛出
     */
    public static Request request(PKCS10CertificationRequest csr, PrivateKey key, X509Certificate signer,
            X509Certificate ca, MessageTypeEnum type) throws Exception {
        if (type == null || type == MessageTypeEnum.UNKNOWN) {
            throw new IllegalArgumentException("发送请求必须使用已知的 SCEP 消息类型");
        }
        // 每次调用创建新事务和新 nonce；二者只关联消息，不代表设备已获得签发授权。
        String transactionId = HexFormat.of().formatHex(Crypto.randomBytes(ScepConstants.TRANSACTION_ID_RANDOM_BYTES));
        byte[] nonce = Crypto.randomBytes(ScepConstants.NONCE_BYTES);
        log.debug("创建 SCEP 请求，messageType={}，transactionId={}，CSR 大小={} 字节", type.getCode(), transactionId,
                csr.getEncoded().length);
        // transactionID/messageType 是文本属性；nonce 是原始字节，必须使用不同的 ASN.1 类型。
        ASN1EncodableVector attributes = attributes(transactionId, type.getCode());
        add(attributes, ScepConstants.SENDER_NONCE, new DEROctetString(nonce));
        // 从内向外封装：CSR DER → 给 CA 的加密信封 → 客户端签名的 CMS。
        // 返回值同时保留本地 transactionId/nonce，收到响应后用它们校验，不能以响应值替代校验基准。
        byte[] encoded = sign(encrypt(csr.getEncoded(), ca, CMSAlgorithm.AES128_CBC), key, signer, attributes);
        log.debug("SCEP 请求编码完成，transactionId={}，报文大小={} 字节", transactionId, encoded.length);
        return new Request(encoded, transactionId, nonce);
    }

    /**
     * 先验证 SignedData，再读取 SCEP 属性；不在此阶段信任签名证书声明的身份。
     *
     * @param encoded HTTP 层解码得到的完整 CMS 字节
     * @return 带有已验签属性和加密内容的请求
     * @throws ScepProtocolException    CMS 完整性失败或算法不支持时携带 RFC 原因
     * @throws IllegalArgumentException 属性类型/数量或 nonce 长度无效时抛出
     */
    public static Message decodeRequest(byte[] encoded) {
        try {
            log.debug("开始解析 SCEP 请求，报文大小={} 字节", encoded.length);
            // 外层签名把属性与加密正文绑定起来；先验签，才能把下面读到的属性视为未被篡改。
            Verified verified = verify(encoded, null);
            String id = transactionId(verified.attributes);
            MessageTypeEnum type = MessageTypeEnum.fromCode(string(verified.attributes, ScepConstants.MESSAGE_TYPE));
            byte[] nonce = nonce(verified.attributes, ScepConstants.SENDER_NONCE);
            // 注册/续期必须携带加密 CSR；允许无正文的是 FAILURE 等响应，不是这里处理的申请。
            if (verified.content.length == 0) {
                throw new IllegalArgumentException("缺少加密内容");
            }
            // content 此时仍是密文；证书即使验签成功，也还要由服务层检查自签身份或旧证书授权。
            log.debug("SCEP 请求验签通过，transactionId={}，messageType={}，密文大小={} 字节", id, type.getCode(),
                    verified.content.length);
            return new Message(id, type, nonce, verified.certificate, verified.content);
        } catch (ScepProtocolException e) {
            // 保留算法和 CMS 完整性分类，供服务端在能关联请求时签署拒绝响应。
            throw e;
        } catch (Exception e) {
            // 保留 cause，交给最终处理边界记录堆栈，避免重复打印。
            throw new IllegalArgumentException("SCEP 请求签名或报文格式无效", e);
        }
    }

    /**
     * 从外层 CMS 提取生成失败响应所需的最小上下文，不执行签名验证。
     *
     * <p>该入口只允许把结构有效的 transactionID、messageType 和 senderNonce 用于关联拒绝响应，
     * 不得把返回对象当作已验签请求参与解密、授权或签发。</p>
     *
     * @param encoded HTTP 层解码得到的完整 CMS 字节
     * @return 可用于生成 CertRep FAILURE 的响应上下文
     * @throws IllegalArgumentException CMS 或响应属性无法解析时抛出
     */
    public static ResponseContext decodeResponseContext(byte[] encoded) {
        try {
            CMSSignedData data = new CMSSignedData(encoded);
            if (!CMSObjectIdentifiers.data.getId().equals(data.getSignedContentTypeOID())) {
                throw new IllegalArgumentException("CMS 签名内容类型必须为 id-data");
            }
            Collection<SignerInformation> signers = data.getSignerInfos().getSigners();
            if (signers.size() != 1) {
                throw new IllegalArgumentException("CMS 必须且只能有一个签名者");
            }
            AttributeTable attributes = signers.iterator().next().getSignedAttributes();
            String transactionId = transactionId(attributes);
            // messageType 即使尚未验签也必须存在且使用协议规定的 PrintableString 类型。
            string(attributes, ScepConstants.MESSAGE_TYPE);
            return new ResponseContext(transactionId, nonce(attributes, ScepConstants.SENDER_NONCE));
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("SCEP 响应上下文无法解析", e);
        }
    }

    /**
     * 解开 EnvelopedData：接收者的 RSA 私钥解开内容密钥，再由内容密钥解密正文。
     *
     * @param encoded   EnvelopedData 编码，而非外层 SignedData
     * @param key       接收者私钥：服务端解请求用 CA 私钥，客户端解响应用身份私钥
     * @param recipient 接收者证书，用于从 RecipientInfos 找到对应的密钥传输项
     * @return 内层明文：请求中是 CSR，成功响应中是证书集合
     * @throws ScepProtocolException 算法不支持时携带 badAlg 原因
     * @throws Exception             接收者不匹配或内容解密失败时抛出
     */
    public static byte[] decrypt(byte[] encoded, PrivateKey key, X509Certificate recipient) throws Exception {
        log.debug("开始解密 CMS 信封，密文大小={} 字节，接收者主题={}", encoded.length,
                recipient.getSubjectX500Principal().getName());
        CMSEnvelopedData envelope = new CMSEnvelopedData(encoded);
        // 加密信封的内容类型也属于协议结构，不能只验证外层 SignedData 后直接解密。
        EnvelopedData structure = EnvelopedData.getInstance(envelope.toASN1Structure().getContent());
        if (!CMSObjectIdentifiers.data.equals(structure.getEncryptedContentInfo().getContentType())) {
            throw new IllegalArgumentException("加密信封的内容类型必须为 id-data");
        }
        // 这里读取的是“正文的对称加密算法”，与外层签名使用的 SHA256withRSA 是两回事。
        ASN1ObjectIdentifier algorithm = envelope.getContentEncryptionAlgorithm().getAlgorithm();
        if (!Set.of(CMSAlgorithm.AES128_CBC, CMSAlgorithm.AES192_CBC, CMSAlgorithm.AES256_CBC,
                CMSAlgorithm.DES_EDE3_CBC).contains(algorithm)) {
            throw new ScepProtocolException(FailInfoEnum.BAD_ALG, "不支持该内容加密算法；禁止使用单 DES");
        }
        // 一个 CMS 信封可以有多个接收者条目；按证书标识找到属于当前接收者的加密内容密钥。
        RecipientInformation info = envelope.getRecipientInfos().get(new JceKeyTransRecipientId(recipient));
        if (info == null) {
            throw new IllegalArgumentException("未找到与证书匹配的 CMS 接收者");
        }
        // BC 先用 RSA 私钥恢复内容密钥，再用内容密钥解密正文；RSA 不直接加密整份 CSR。
        byte[] content = info.getContent(new JceKeyTransEnvelopedRecipient(key).setProvider(Crypto.PROVIDER));
        log.debug("CMS 信封解密完成，明文大小={} 字节", content.length);
        return content;
    }

    /**
     * 构造 CertRep SUCCESS：先包装证书集合，再加密给请求签名者，最后由 CA 签名。
     *
     * @param request 原请求，提供事务、nonce 及响应接收者
     * @param issued  已签发的终端证书
     * @param ca      响应签名证书
     * @param key     CA 的响应签名私钥
     * @return 完整响应的 DER 编码
     * @throws Exception 证书封装、加密或签名失败时抛出
     */
    public static byte[] success(Message request, X509Certificate issued, X509Certificate ca, PrivateKey key)
            throws Exception {
        log.info("生成 SCEP 成功响应，transactionId={}，证书序列号={}", request.transactionId(),
                issued.getSerialNumber().toString(16));
        // “退化 SignedData”只用 certificates 字段装证书，没有 signerInfo 和业务正文。
        // 它本身不额外签名；各 X.509 证书有 CA 签名，外层响应还会再签一次。
        CMSSignedDataGenerator bag = new CMSSignedDataGenerator();
        bag.addCertificate(new JcaX509CertificateHolder(issued));
        // CMSAbsentContent 表示没有业务正文，证书本体放在 SignedData 的 certificates 集合中。
        byte[] certificates = bag.generate(new CMSAbsentContent()).toASN1Structure().getEncoded(ASN1Encoding.DER);
        ASN1EncodableVector attributes = responseAttributes(request.transactionId, request.nonce,
                PkiStatusEnum.SUCCESS);
        // 使用 AES-128-CBC 加密给原请求签名者；换钥续期时接收者仍是旧证书，须用旧私钥解密。
        // 最外层由 CA 签名，让客户端校验这个结果确实来自预先信任的 CA。
        byte[] response = sign(encrypt(certificates, request.signer, CMSAlgorithm.AES128_CBC), key, ca, attributes);
        log.debug("SCEP 成功响应编码完成，transactionId={}，报文大小={} 字节", request.transactionId(), response.length);
        return response;
    }

    /**
     * 构造仍受 CA 签名保护的失败响应，省略 eContent 和加密信封。
     *
     * @param request  原请求，用于回显事务标识及 nonce
     * @param failInfo 协议失败原因；服务端应按具体错误选择 badAlg、badCertId 或 badRequest 等值
     * @param ca       响应签名证书
     * @param key      CA 私钥
     * @return CertRep FAILURE 的 DER 编码
     * @throws Exception 响应签名或编码失败时抛出
     */
    public static byte[] failure(Message request, FailInfoEnum failInfo, X509Certificate ca, PrivateKey key)
            throws Exception {
        return failure(new ResponseContext(request.transactionId, request.nonce), failInfo, ca, key);
    }

    /**
     * 只用事务关联字段生成 CertRep FAILURE，允许字段来自尚未通过 CMS 验签的请求。
     *
     * @param request 只包含事务标识和请求 nonce 的响应上下文
     * @param failInfo SCEP 协议失败原因
     * @param ca       响应签名证书
     * @param key      CA 私钥
     * @return CertRep FAILURE 的 DER 编码
     * @throws Exception 响应签名或编码失败时抛出
     */
    public static byte[] failure(ResponseContext request, FailInfoEnum failInfo, X509Certificate ca, PrivateKey key)
            throws Exception {
        if (failInfo == null || failInfo == FailInfoEnum.UNKNOWN) {
            throw new IllegalArgumentException("发送失败响应必须使用已知的失败原因");
        }
        // pkiStatus=2 只说明失败，具体原因由 failInfo 表达；两者是不同 OID 对应的属性。
        ASN1EncodableVector attributes = responseAttributes(request.transactionId, request.nonce,
                PkiStatusEnum.FAILURE);
        add(attributes, ScepConstants.FAIL_INFO, new DERPrintableString(failInfo.getCode()));
        // false 让 CMS 省略 eContent；仍生成签名和事务属性，因此失败响应也能校验来源及归属。
        log.info("生成 SCEP 失败响应，transactionId={}，failInfo={}", request.transactionId(), failInfo.getCode());
        byte[] response = sign(new byte[0], key, ca, attributes, false);
        log.debug("SCEP 失败响应编码完成，transactionId={}，报文大小={} 字节", request.transactionId(), response.length);
        return response;
    }

    /**
     * 客户端按“验签 → 确认可信 CA → 绑定请求 → 检查状态 → 解密 → 验证证书”读取响应。
     *
     * @param encoded      HTTP 返回的 CMS 字节
     * @param request      原始请求上下文，不能用响应中收到的值替代
     * @param trustedCa    预先信任的 CA；当前实现要求响应签名者就是这张证书
     * @param recipientKey 原请求签名者的私钥；换钥续期仍用旧私钥解密
     * @param expectedKey  CSR 中申请认证的公钥；换钥续期时是新公钥
     * @return 已验证 CA 签名、有效期且公钥匹配的终端证书；subject 由客户端上层校验
     * @throws IllegalArgumentException 响应 nonce、状态或 FAILURE/PENDING 内容结构不符合协议时抛出
     * @throws ScepFailureException     收到签名和事务校验均通过的 FAILURE 时抛出
     * @throws Exception                消息不可信、不匹配、状态不支持或解密失败时抛出
     */
    public static X509Certificate readResponse(byte[] encoded, Request request, X509Certificate trustedCa,
            PrivateKey recipientKey, PublicKey expectedKey) throws Exception {
        log.debug("开始解析 SCEP 响应，transactionId={}，报文大小={} 字节", request.transactionId(), encoded.length);
        // 1. 响应使用本地预置信任证书匹配 SID 并验签；服务端无需重复携带这张 CA。
        // 本实现采用单 CA 固定信任，不从网络报文自动引入新 CA 或 RA 信任。
        Verified verified = verify(encoded, trustedCa);
        trustedCa.checkValidity();
        // verify 已直接使用 trustedCa 验签，返回的证书也来自 trustedCa，无需再比较同一张证书。
        // 2. CertRep 的 messageType 是 3；事务 ID 和回显 nonce 必须匹配本地保存的请求。
        // 这能拒绝与当前请求不匹配的响应，但不等于服务端已经实现重试去重。
        String messageType = string(verified.attributes, ScepConstants.MESSAGE_TYPE);
        String transactionId = string(verified.attributes, ScepConstants.TRANSACTION_ID);
        byte[] recipientNonce = nonce(verified.attributes, ScepConstants.RECIPIENT_NONCE);
        byte[] senderNonce = nonce(verified.attributes, ScepConstants.SENDER_NONCE);
        if (!MessageTypeEnum.CERT_REP.getCode().equals(messageType) || !request.transactionId.equals(transactionId)
                || !MessageDigest.isEqual(request.nonce, recipientNonce)
                || MessageDigest.isEqual(request.nonce, senderNonce)) {
            throw new IllegalArgumentException("响应类型、事务标识或接收者随机数与请求不匹配");
        }
        String status = string(verified.attributes, ScepConstants.PKI_STATUS);
        // 3. 先确认响应可信且属于本次申请，再读取失败原因；HTTP 200 不意味着签发成功。
        PkiStatusEnum pkiStatus = PkiStatusEnum.fromCode(status);
        if (pkiStatus == PkiStatusEnum.FAILURE || pkiStatus == PkiStatusEnum.PENDING) {
            // RFC 8894 §3.3.2.2/§3.3.2.3 要求 FAILURE/PENDING 省略 pkcsPKIEnvelope，即外层不能有 eContent。
            if (verified.contentPresent) {
                throw new IllegalArgumentException("FAILURE 或 PENDING 响应不得包含 pkcsPKIEnvelope");
            }
        }
        if (pkiStatus == PkiStatusEnum.FAILURE) {
            throw new ScepFailureException(string(verified.attributes, ScepConstants.FAIL_INFO));
        }
        // 本客户端没有待审批状态机；PENDING=3 在这里明确报不支持，不会被当成成功继续解密。
        if (pkiStatus != PkiStatusEnum.SUCCESS) {
            throw new IllegalArgumentException("不支持该 SCEP 状态：" + status);
        }
        if (!verified.contentPresent || verified.content.length == 0) {
            throw new IllegalArgumentException("SUCCESS 响应必须包含 pkcsPKIEnvelope");
        }
        // 接收者证书来自已签名的原始请求，续期换钥时仍使用旧密钥解密。
        X509Certificate recipient = decodeRequest(request.encoded).signer;
        byte[] data = decrypt(verified.content, recipientKey, recipient);
        // 4. 解密得到的是“仅含证书的 CMS”，还要取出其中的 X.509 证书，不能把它直接当证书 DER。
        CMSSignedData bag = new CMSSignedData(data);
        // RFC 8894 §3.4：证书包是退化 SignedData，signerInfos 为空且 eContent 必须缺失。
        // “没有内容”与“存在一个长度为 0 的 OCTET STRING”不同，后者仍属于非法证书包。
        if (!CMSObjectIdentifiers.data.getId().equals(bag.getSignedContentTypeOID()) || bag.getSignedContent() != null
                || bag.getSignerInfos().size() != 0) {
            throw new IllegalArgumentException("成功响应必须包含无正文、无签名者的 id-data 证书包");
        }
        Collection<X509CertificateHolder> certificates = bag.getCertificates().getMatches(null);
        for (X509CertificateHolder holder : certificates) {
            X509Certificate cert =
                    new JcaX509CertificateConverter().setProvider(Crypto.PROVIDER).getCertificate(holder);
            // 5. 从证书包中选择申请公钥对应的终端证书；避免误取 CA 证书或其他设备的证书。
            if (cert.getBasicConstraints() < 0
                    && Arrays.equals(expectedKey.getEncoded(), cert.getPublicKey().getEncoded())) {
                // 外层响应签名和证书自身签名是两层校验；subject 是否匹配由 ScepClient.enroll 继续检查。
                cert.verify(trustedCa.getPublicKey(), Crypto.PROVIDER);
                cert.checkValidity();
                log.info("SCEP 响应校验通过，transactionId={}，证书序列号={}", request.transactionId(),
                        cert.getSerialNumber().toString(16));
                return cert;
            }
        }
        throw new IllegalArgumentException("响应中没有与申请公钥匹配的终端证书");
    }

    /**
     * 校验外层 CMS 的消息摘要和签名，不执行 CA 信任链或注册授权判断。
     *
     * @param encoded       外层 SignedData 编码
     * @param trustedSigner 响应的预置信任 CA；请求传 null，要求报文携带身份凭证
     * @return 签名者、已签名属性和封装内容
     * @throws Exception 内容类型、签名者数量、算法或签名不符合要求时抛出
     */
    private static Verified verify(byte[] encoded, X509Certificate trustedSigner) throws Exception {
        // 构造器只完成 CMS 解析，并不代表签名已通过；真正的密码学检查在下方 signer.verify。
        CMSSignedData data = new CMSSignedData(encoded);
        // 外层 SignedData 的 eContentType 应是 id-data；里面的字节才是另一个 CMS EnvelopedData。
        if (!CMSObjectIdentifiers.data.getId().equals(data.getSignedContentTypeOID())) {
            throw new IllegalArgumentException("CMS 签名内容类型必须为 id-data");
        }
        // RFC 8894 FAILURE/PENDING 没有 eContent；给 BC 提供空内容以验证签名和 messageDigest。
        // 这只是验签时的本地输入，不是在收到的网络消息中补造加密信封。
        boolean contentPresent = data.getSignedContent() != null;
        if (!contentPresent) {
            data = new CMSSignedData(new CMSProcessableByteArray(new byte[0]), encoded);
        }
        Collection<SignerInformation> signers = data.getSignerInfos().getSigners();
        // 一个 SCEP 消息只接受一个 SignerInfo，避免出现“究竟以谁的签名和属性为准”的歧义。
        if (signers.size() != 1) {
            throw new IllegalArgumentException("CMS 必须且只能有一个签名者");
        }
        SignerInformation signer = signers.iterator().next();
        // 这是本项目接受的摘要算法集合；SHA-1 仅供兼容，生成的新消息统一用 SHA-256。
        if (!Set.of(NISTObjectIdentifiers.id_sha256.getId(), OIWObjectIdentifiers.idSHA1.getId())
                .contains(signer.getDigestAlgOID())) {
            throw new ScepProtocolException(FailInfoEnum.BAD_ALG, "不支持该摘要算法");
        }
        X509CertificateHolder holder;
        if (trustedSigner == null) {
            // 注册请求中的自签身份还未建立信任，必须由请求自己携带，之后再由服务层授权。
            holder = matchingCertificate(data.getCertificates(), signer);
        } else {
            holder = new JcaX509CertificateHolder(trustedSigner);
            // 只用预配的证书验签仍需检查 SID，防止标识与实际验签身份不一致。
            if (!signer.getSID().match(holder)) {
                throw new IllegalArgumentException("响应签名者标识与可信 CA 不匹配");
            }
        }
        // Holder 是 BC 的证书编码模型；转成 JCA X509Certificate 后便于读取公钥和做后续证书校验。
        X509Certificate cert = new JcaX509CertificateConverter().setProvider(Crypto.PROVIDER).getCertificate(holder);
        try {
            Crypto.requireRsa(cert.getPublicKey());
        } catch (IllegalArgumentException e) {
            throw new ScepProtocolException(FailInfoEnum.BAD_ALG, "签名证书使用了不支持的公钥算法或参数");
        }
        // BC 检查签名，并在有 signedAttrs 时核对 messageDigest 与正文摘要；通过不代表签名者已获授权。
        try {
            if (!signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(Crypto.PROVIDER).build(cert))) {
                throw new ScepProtocolException(FailInfoEnum.BAD_MESSAGE_CHECK, "CMS 签名验证失败");
            }
        } catch (CMSSignerDigestMismatchException e) {
            // BC 对正文摘要不匹配抛异常，对签名值不匹配返回 false；两者都是 CMS 完整性错误。
            throw new ScepProtocolException(FailInfoEnum.BAD_MESSAGE_CHECK, "CMS 正文摘要验证失败", e);
        }
        // SCEP 将 messageType、transactionID、nonce 等协议字段放在 signedAttrs 中，必须受签名保护。
        // 普通 CMS 可以采用不带 signedAttrs 的形式，但缺少这些属性的消息不能作为本项目的 SCEP 消息处理。
        if (signer.getSignedAttributes() == null) {
            throw new IllegalArgumentException("缺少受签名保护的属性");
        }
        // 此处只返回“验签通过的内容”；证书信任、属性类型及业务授权由上层继续检查。
        return new Verified(cert, signer.getSignedAttributes(), (byte[])data.getSignedContent().getContent(),
                contentPresent);
    }

    /**
     * 依照 SignerIdentifier 查找验签证书，不能直接取证书集合中的第一张。
     *
     * @param certificates CMS 携带的证书集合
     * @param signer       包含签名及签名者标识的 SignerInfo
     * @return 唯一匹配的证书
     * @throws IllegalArgumentException 没有匹配证书或存在歧义时抛出
     */
    @SuppressWarnings("unchecked")
    private static X509CertificateHolder matchingCertificate(Store<X509CertificateHolder> certificates,
            SignerInformation signer) {
        // SID（SignerIdentifier）标识签名证书；证书集合没有保证第一张就是签名者。
        Collection<X509CertificateHolder> matches = certificates.getMatches(signer.getSID());
        if (matches.size() != 1) {
            throw new IllegalArgumentException("缺少签名证书或存在多张匹配的签名证书");
        }
        return matches.iterator().next();
    }

    /**
     * 使用混合加密创建 CMS 信封，RSA 传输内容密钥，AES 等对称算法加密正文。
     *
     * @param content   内层明文字节
     * @param recipient 接收者证书，其公钥用于包装内容密钥
     * @param algorithm 对称内容加密算法的 OID
     * @return EnvelopedData 的 DER 编码
     * @throws Exception 密钥包装、内容加密或编码失败时抛出
     */
    private static byte[] encrypt(byte[] content, X509Certificate recipient, ASN1ObjectIdentifier algorithm)
            throws Exception {
        CMSEnvelopedDataGenerator generator = new CMSEnvelopedDataGenerator();
        // 接收者证书提供 RSA 公钥及接收者标识；BC 用它包装本次随机生成的对称内容密钥。
        generator.addRecipientInfoGenerator(
                new JceKeyTransRecipientInfoGenerator(recipient).setProvider(Crypto.PROVIDER));
        // 内容加密器生成密钥及所需 IV，算法参数与包装后的密钥一起写进信封，供接收者解密。
        return generator
                .generate(new CMSProcessableByteArray(content),
                        new JceCMSContentEncryptorBuilder(algorithm).setProvider(Crypto.PROVIDER).build())
                .toASN1Structure().getEncoded(ASN1Encoding.DER);
    }

    /**
     * 签名并携带正文，用于注册/续期请求及成功响应。
     *
     * @param content     待封装的加密信封
     * @param key         签名私钥
     * @param certificate 签名证书
     * @param attributes  SCEP 自定义签名属性
     * @return 带 eContent 的 SignedData 编码
     * @throws Exception 签名或编码失败时抛出
     */
    private static byte[] sign(byte[] content, PrivateKey key, X509Certificate certificate,
            ASN1EncodableVector attributes) throws Exception {
        return sign(content, key, certificate, attributes, true);
    }

    /**
     * 生成外层 CMS 签名，BC 同时生成 contentType、messageDigest 等标准签名属性。
     *
     * @param content     待签名的内容；失败响应使用空数组
     * @param key         签名私钥
     * @param certificate 随消息携带的签名证书；携带证书不代表接收方自动信任它
     * @param attributes  SCEP 自定义签名属性
     * @param attached    是否在 SignedData 中携带 eContent
     * @return SignedData 的 DER 编码
     * @throws Exception 签名或编码失败时抛出
     */
    private static byte[] sign(byte[] content, PrivateKey key, X509Certificate certificate,
            ASN1EncodableVector attributes, boolean attached) throws Exception {
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        JcaSignerInfoGeneratorBuilder builder = new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().setProvider(Crypto.PROVIDER).build());
        // 有 signedAttrs 时签名保护属性集合；messageDigest 属性把正文摘要绑定到这份签名。
        builder.setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(new AttributeTable(attributes)));
        // ContentSigner 使用发送者私钥；证书用于在 SignerInfo 中关联这次签名所对应的公钥身份。
        generator.addSignerInfoGenerator(builder.build(Crypto.signer(key), certificate));
        // 携带公钥证书以便对方验签，不携带私钥，也不要求对方无条件信任这张证书。
        generator.addCertificate(new JcaX509CertificateHolder(certificate));
        // attached=true 将加密信封装入 eContent；false 用于没有加密正文的失败响应。
        return generator.generate(new CMSProcessableByteArray(content), attached).toASN1Structure()
                .getEncoded(ASN1Encoding.DER);
    }

    /**
     * 创建所有请求/响应共用的事务属性，字段值必须编码成 PrintableString。
     *
     * @param id   事务标识
     * @param type 消息类型的十进制字符串
     * @return 可继续追加的 ASN.1 属性集合
     */
    private static ASN1EncodableVector attributes(String id, String type) {
        ASN1EncodableVector attributes = new ASN1EncodableVector();
        // 字段看起来像数字也必须按协议编码为 PrintableString，例如 "19" 不是 ASN.1 INTEGER 19。
        add(attributes, ScepConstants.TRANSACTION_ID, new DERPrintableString(id, true));
        add(attributes, ScepConstants.MESSAGE_TYPE, new DERPrintableString(type, true));
        return attributes;
    }

    /**
     * 将响应与原请求绑定：复用 transactionID，把请求 senderNonce 放入 recipientNonce。
     *
     * @param transactionId 原始请求的事务标识
     * @param nonce         原始请求的 senderNonce
     * @param status        SUCCESS 或 FAILURE，线上值由独立的状态枚举指定
     * @return CertRep 公共属性；响应另生成自己的 senderNonce
     */
    private static ASN1EncodableVector responseAttributes(String transactionId, byte[] nonce, PkiStatusEnum status) {
        // 3 在 messageType 中表示 CertRep，与 pkiStatus 中 3=PENDING 不是同一含义。
        ASN1EncodableVector attributes = attributes(transactionId, MessageTypeEnum.CERT_REP.getCode());
        add(attributes, ScepConstants.PKI_STATUS, new DERPrintableString(status.getCode()));
        // 将“对方发送的随机数”放到 recipientNonce；本响应自己的 senderNonce 则重新随机生成。
        add(attributes, ScepConstants.RECIPIENT_NONCE, new DEROctetString(nonce));
        add(attributes, ScepConstants.SENDER_NONCE, new DEROctetString(Crypto.randomBytes(ScepConstants.NONCE_BYTES)));
        return attributes;
    }

    /**
     * CMS Attribute 的值是 SET OF；即使只有一个值也必须包进 DERSet。
     *
     * @param attributes 待追加的属性集合
     * @param oid        属性类型
     * @param value      已使用正确 ASN.1 类型编码的单个值
     */
    private static void add(ASN1EncodableVector attributes, ASN1ObjectIdentifier oid, ASN1Encodable value) {
        attributes.add(new Attribute(oid, new DERSet(value)));
    }

    /**
     * 读取唯一单值属性，拒绝重复字段，避免不同解析器对同一消息产生不同解释。
     *
     * @param attributes 已签名属性集合
     * @param oid        待读取的属性类型
     * @return 唯一的 ASN.1 属性值
     * @throws IllegalArgumentException 属性缺失、重复或包含多个值时抛出
     */
    private static ASN1Encodable value(AttributeTable attributes, ASN1ObjectIdentifier oid) {
        // 先检查同一 OID 出现了几次；只调用 get(oid) 可能掩盖消息中存在的重复属性。
        if (attributes == null || attributes.getAll(oid).size() != 1) {
            throw new IllegalArgumentException("属性缺失或重复：" + oid);
        }
        Attribute attribute = attributes.get(oid);
        // Attribute 的值在 ASN.1 中是一个集合，本项目读取的 SCEP 字段要求集合中恰好一个值。
        if (attribute.getAttrValues().size() != 1) {
            throw new IllegalArgumentException("属性包含多个值：" + oid);
        }
        return attribute.getAttrValues().getObjectAt(0);
    }

    /**
     * 严格按 PrintableString 读取 SCEP 文本属性。
     *
     * @param attributes 已签名属性集合
     * @param oid        文本属性的 OID
     * @return 字符串内容
     * @throws IllegalArgumentException 属性数量或 ASN.1 类型无效时抛出
     */
    private static String string(AttributeTable attributes, ASN1ObjectIdentifier oid) {
        // getInstance 按 ASN.1 类型解析，不能用 toString() 代替，否则错误类型也可能被当成合法文本。
        String text = ASN1PrintableString.getInstance(value(attributes, oid)).getString();
        if (!ASN1PrintableString.isPrintableString(text)) {
            throw new IllegalArgumentException("属性包含非法 PrintableString 字符：" + oid);
        }
        return text;
    }

    /**
     * 读取可安全回显的事务标识，事务标识本身不提供签发授权。
     *
     * @param attributes CMS 的 signedAttrs 字段
     * @return 非空且不超过本实现长度上限的 transactionID
     * @throws IllegalArgumentException 属性缺失、重复或格式不符时抛出
     */
    private static String transactionId(AttributeTable attributes) {
        String id = string(attributes, ScepConstants.TRANSACTION_ID);
        if (id.isBlank() || id.length() > ScepConstants.MAX_TRANSACTION_ID_LENGTH) {
            throw new IllegalArgumentException("事务标识 transactionID 为空或过长");
        }
        return id;
    }

    /**
     * 读取 nonce 的原始 16 字节值；nonce 不是文本，也不应进行字符串编码转换。
     *
     * @param attributes 已签名属性集合
     * @param oid        senderNonce 或 recipientNonce 的 OID
     * @return nonce 字节
     * @throws IllegalArgumentException 属性数量、类型或长度无效时抛出
     */
    private static byte[] nonce(AttributeTable attributes, ASN1ObjectIdentifier oid) {
        // OCTET STRING 存放二进制随机数；十六进制/Base64 只适合显示，不能改变协议内的字节表示。
        byte[] bytes = ASN1OctetString.getInstance(value(attributes, oid)).getOctets();
        if (bytes.length != ScepConstants.NONCE_BYTES) {
            throw new IllegalArgumentException("随机数 nonce 必须为 16 字节");
        }
        return bytes;
    }

    /**
     * 客户端等待响应时保留的请求上下文，数组防御性复制防止校验基准被意外修改。
     * <p>Lombok 生成只读访问方法；数组 getter 必须手写，不能把内部数组交给调用方。</p>
     *
     * @author robin.li
     * @date 2026-11-20 21:52:59
     */
    @Value
    @Accessors(fluent = true)
    public static class Request {
        byte[] encoded;

        String transactionId;

        byte[] nonce;

        /**
         * 保存数组快照；final 只能禁止重新赋值，不能阻止修改数组内容。
         *
         * @param encoded       完整的外层 SignedData
         * @param transactionId 发送时的事务标识
         * @param nonce         发送时的 senderNonce
         */
        public Request(byte[] encoded, String transactionId, byte[] nonce) {
            this.encoded = encoded.clone();
            this.transactionId = transactionId;
            this.nonce = nonce.clone();
        }

        /**
         * @return 请求编码的副本，调用方修改它不会改变保存的校验上下文
         */
        public byte[] encoded() {
            return encoded.clone();
        }

        /**
         * @return senderNonce 的副本，防止响应比对基准被外部修改
         */
        public byte[] nonce() {
            return nonce.clone();
        }

        /**
         * 保留数组按引用比较的原有语义；不能让自动生成的深比较改变对象相等性。
         */
        @Override
        public boolean equals(Object other) {
            if (this == other) {
                return true;
            }
            if (!(other instanceof Request)) {
                return false;
            }
            Request that = (Request)other;
            return encoded == that.encoded && Objects.equals(transactionId, that.transactionId) && nonce == that.nonce;
        }

        /**
         * 与 equals 的数组引用比较保持一致，不对字节内容计算散列。
         */
        @Override
        public int hashCode() {
            return Objects.hash(encoded, transactionId, nonce);
        }
    }

    /**
     * 服务端已完成外层验签、尚未完成解密和授权的请求。
     *
     * @author robin.li
     * @date 2026-11-20 21:52:59
     */
    @Value
    @Accessors(fluent = true)
    public static class Message {
        /**
         * 已签名的事务标识。
         */
        String transactionId;

        /**
         * 已签名的消息类型。
         */
        MessageTypeEnum type;

        /**
         * 请求的 senderNonce。
         */
        byte[] nonce;

        /**
         * 用于验签的证书；此时尚不能认定其身份可信。
         */
        X509Certificate signer;

        /**
         * 外层 eContent 中的 EnvelopedData 编码，尚不是 CSR。
         */
        byte[] content;

        /**
         * 事务标识、枚举和证书按值比较，数组仍按引用比较，保持已有调用约定。
         */
        @Override
        public boolean equals(Object other) {
            if (this == other) {
                return true;
            }
            if (!(other instanceof Message)) {
                return false;
            }
            Message that = (Message)other;
            return Objects.equals(transactionId, that.transactionId) && Objects.equals(type, that.type)
                    && nonce == that.nonce && Objects.equals(signer, that.signer) && content == that.content;
        }

        /**
         * 与 equals 使用相同的字段及数组引用。
         */
        @Override
        public int hashCode() {
            return Objects.hash(transactionId, type, nonce, signer, content);
        }
    }

    /**
     * 生成拒绝响应所需的最小请求上下文；其中字段可能来自尚未验签的 CMS 属性。
     */
    @Value
    @Accessors(fluent = true)
    public static class ResponseContext {
        String transactionId;

        byte[] nonce;

        /**
         * 保存 nonce 快照，避免响应属性依赖的字节被外部修改。
         *
         * @param transactionId 请求事务标识
         * @param nonce          请求 senderNonce
         */
        private ResponseContext(String transactionId, byte[] nonce) {
            this.transactionId = transactionId;
            this.nonce = nonce.clone();
        }

        /**
         * @return senderNonce 的副本
         */
        public byte[] nonce() {
            return nonce.clone();
        }
    }

    /**
     * CMS 验签结果；“Verified”仅表示签名和摘要校验通过，不表示证书链或业务授权通过。
     *
     * @author robin.li
     * @date 2026-11-20 21:52:59
     */
    @Value
    private static class Verified {
        /**
         * 与 SignerInfo 匹配的证书。
         */
        X509Certificate certificate;

        /**
         * 受到签名保护的属性。
         */
        AttributeTable attributes;

        /**
         * 外层封装内容；无 eContent 的响应在验签时使用空数组作为摘要输入。
         */
        byte[] content;

        /**
         * 是否真的存在 eContent；区分“内容缺失”和“存在空内容”。
         */
        boolean contentPresent;
    }
}

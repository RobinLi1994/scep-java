package com.example.scep.server;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.stream.Stream;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.example.scep.common.crypto.Crypto;
import com.example.scep.common.protocol.ScepCodec;
import com.example.scep.common.protocol.ScepFailureException;
import com.example.scep.common.protocol.enums.MessageTypeEnum;
import com.example.scep.server.ca.CertificateAuthority;
import com.example.scep.server.service.ScepService;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 协议行为示例集：使用真实 CA、RSA、CSR 和 CMS，适合单步调试注册与续期。
 *
 * @author robin.li
 * @date 2026-11-20 21:52:59
 */
class ScepServiceTest {
    @TempDir
    Path depot;

    CertificateAuthority ca;

    ScepService service;

    KeyPair key;

    X509Certificate self;

    /**
     * 每个测试使用独立 CA 和客户端身份，避免签发记录在用例之间相互影响。
     * @throws Exception 测试 CA、密钥或自签身份创建失败时抛出
     */
    @BeforeEach
    void setup() throws Exception {
        CertificateAuthority.initialize(depot, "CN=Test CA", 2048, 3650);
        ca = CertificateAuthority.load(depot);
        service = new ScepService(ca, "test-secret", 365, 14, false);
        key = Crypto.rsa(2048);
        self = Crypto.selfSigned(key, new X500Name("CN=device-01"));
    }

    /**
     * 构造真实 PKCS#10 请求，私钥只用于签名，不包含在 CSR 中。
     * @param key 申请密钥对
     * @param subject 申请的主题名称
     * @param challenge 注册口令，null 时不写入该属性
     * @return 已签名的 CSR
     * @throws Exception CSR 构建或签名失败时抛出
     */
    static PKCS10CertificationRequest csr(KeyPair key, String subject, String challenge) throws Exception {
        JcaPKCS10CertificationRequestBuilder builder =
                new JcaPKCS10CertificationRequestBuilder(new X500Name(subject), key.getPublic());
        if (challenge != null) {
            builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword, new DERUTF8String(challenge));
        }
        return builder.build(Crypto.signer(key.getPrivate()));
    }

    /**
     * 为当前测试身份构造初始注册请求。
     * @param challenge 本次放入 CSR 的口令
     * @return CMS 请求和事务上下文
     * @throws Exception CSR 或 CMS 创建失败时抛出
     */
    ScepCodec.Request request(String challenge) throws Exception {
        return ScepCodec.request(csr(key, "CN=device-01", challenge), key.getPrivate(), self, ca.certificate(),
                MessageTypeEnum.PKCS_REQ);
    }

    /**
     * 完成一次真实注册，供续期等测试取得有效旧身份。
     * @return 经过客户端验证的签发证书
     * @throws Exception 注册或响应校验失败时抛出
     */
    X509Certificate enroll() throws Exception {
        ScepCodec.Request request = request("test-secret");
        return ScepCodec.readResponse(service.handle(request.encoded()), request, ca.certificate(), key.getPrivate(),
                key.getPublic());
    }

    /**
     * 从成功注册看证书的 subject、公钥、用途和持久化；重新加载 CA 后记录仍可识别。
     * @throws Exception 测试所需密码或 I/O 操作异常时由 JUnit 报告
     */
    @Test
    void enrollsAndPersistsAnEndEntityCertificate() throws Exception {
        X509Certificate cert = enroll();
        cert.verify(ca.certificate().getPublicKey());
        assertEquals("CN=device-01", cert.getSubjectX500Principal().getName());
        assertArrayEquals(key.getPublic().getEncoded(), cert.getPublicKey().getEncoded());
        // -1 表示非 CA；下面的 OID 是 clientAuth，证明签发模板没有给申请者 CA 权限。
        assertEquals(-1, cert.getBasicConstraints());
        assertEquals(List.of("1.3.6.1.5.5.7.3.2"), cert.getExtendedKeyUsage());
        assertTrue(ca.isIssued(cert));
        assertTrue(CertificateAuthority.load(depot).isIssued(cert));
    }

    /**
     * 验签通过仍可能授权失败；错误口令应得到签名 FAILURE，且不落盘签发证书。
     * @throws Exception 测试所需密码或 I/O 操作异常时由 JUnit 报告
     */
    @Test
    void wrongChallengeReturnsSignedFailureWithoutIssuing() throws Exception {
        ScepCodec.Request request = request("wrong");
        ScepFailureException failure =
                assertThrows(ScepFailureException.class, () -> ScepCodec.readResponse(service.handle(request.encoded()),
                        request, ca.certificate(), key.getPrivate(), key.getPublic()));
        assertEquals("2", failure.failInfo());
        // 仅收到失败码还不够：还要确认错误口令没有在服务端留下任何已签发证书。
        try (Stream<Path> files = Files.list(depot.resolve("issued"))) {
            assertEquals(0, files.count());
        }
    }

    /**
     * CMS 签名无效时只回复签名拒绝结果，并验证服务端没有签发证书。
     * @throws Exception 测试所需密码或 I/O 操作异常时由 JUnit 报告
     */
    @Test
    void returnsSignedFailureWithoutIssuingForInvalidSignature() throws Exception {
        ScepCodec.Request request = request("test-secret");
        byte[] encoded = request.encoded();
        encoded[encoded.length - 1] ^= 1;
        assertSignedFailure(encoded, request, "1");
        try (Stream<Path> files = Files.list(depot.resolve("issued"))) {
            assertEquals(0, files.count());
        }
    }

    /** 正文摘要与 CMS 签名属性不匹配时，仍回复可验签的 badMessageCheck。 */
    @Test
    void returnsSignedFailureForDigestMismatch() throws Exception {
        ScepCodec.Request request = request("test-secret");
        CMSSignedData cms = new CMSSignedData(request.encoded());
        AttributeTable attributes = cms.getSignerInfos().getSigners().iterator().next().getSignedAttributes()
                .remove(CMSAttributes.messageDigest).add(CMSAttributes.messageDigest, new DEROctetString(new byte[32]));
        byte[] encoded = ProtocolFixtures.sign((byte[])cms.getSignedContent().getContent(), key.getPrivate(), self,
                attributes, true);
        assertSignedFailure(encoded, request, "1");
    }

    /** 不在服务端允许列表中的 SHA-384 请求应收到可验签的 badAlg。 */
    @Test
    void returnsSignedFailureForUnsupportedOuterDigest() throws Exception {
        ScepCodec.Request request = request("test-secret");
        CMSSignedData cms = new CMSSignedData(request.encoded());
        AttributeTable attributes = cms.getSignerInfos().getSigners().iterator().next().getSignedAttributes()
                .remove(CMSAttributes.messageDigest);
        byte[] encoded = ProtocolFixtures.sign((byte[])cms.getSignedContent().getContent(),
                new JcaContentSignerBuilder("SHA384withRSA").setProvider(Crypto.PROVIDER).build(key.getPrivate()),
                self, attributes, true);
        assertSignedFailure(encoded, request, "0");
    }

    /**
     * 验证服务端签署的拒绝响应仍通过客户端的 CA 验签、事务及 nonce 校验。
     * @param encoded 发送给服务端的请求
     * @param request 客户端原始事务上下文
     * @param code 预期的协议失败码
     * @throws Exception 请求处理失败时抛出
     */
    private void assertSignedFailure(byte[] encoded, ScepCodec.Request request, String code) throws Exception {
        byte[] response = service.handle(encoded);
        ScepFailureException failure = assertThrows(ScepFailureException.class,
                () -> ScepCodec.readResponse(response, request, ca.certificate(), key.getPrivate(), key.getPublic()));
        assertEquals(code, failure.failInfo());
    }

    /**
     * 初始注册要求 CMS 身份公钥与 CSR 公钥一致，防止把身份和申请密钥混用。
     * @throws Exception 测试所需密码或 I/O 操作异常时由 JUnit 报告
     */
    @Test
    void rejectsSignerAndCsrKeyMismatch() throws Exception {
        KeyPair other = Crypto.rsa(2048);
        ScepCodec.Request request = ScepCodec.request(csr(other, "CN=device-01", "test-secret"), key.getPrivate(), self,
                ca.certificate(), MessageTypeEnum.PKCS_REQ);
        assertThrows(ScepFailureException.class, () -> ScepCodec.readResponse(service.handle(request.encoded()),
                request, ca.certificate(), key.getPrivate(), other.getPublic()));
    }

    /**
     * 初始自签身份与 CSR 的 subject 可以不同，但最终证书 subject 仍来自获准的 CSR。
     * @throws Exception 测试所需密码或 I/O 操作异常时由 JUnit 报告
     */
    @Test
    void acceptsInitialSignerWithDifferentSubject() throws Exception {
        X509Certificate identity = Crypto.selfSigned(key, new X500Name("CN=SCEP SIGNER,O=scep-client"));
        ScepCodec.Request request = ScepCodec.request(csr(key, "CN=device-01", "test-secret"), key.getPrivate(),
                identity, ca.certificate(), MessageTypeEnum.PKCS_REQ);
        X509Certificate cert = ScepCodec.readResponse(service.handle(request.encoded()), request, ca.certificate(),
                key.getPrivate(), key.getPublic());
        assertEquals("CN=device-01", cert.getSubjectX500Principal().getName());
    }

    /**
     * 换钥续期的关键示例：旧私钥签 CMS/解响应，新私钥签 CSR，旧证书授权替代 challenge。
     * @throws Exception 测试所需密码或 I/O 操作异常时由 JUnit 报告
     */
    @Test
    void renewsWithOldCertificateAndNewKeyWithoutChallenge() throws Exception {
        X509Certificate old = enroll();
        KeyPair newKey = Crypto.rsa(2048);
        // CSR 由新私钥签名且不带 challenge；外层 CMS 由旧私钥签名并携带旧证书。
        ScepCodec.Request request = ScepCodec.request(csr(newKey, "CN=device-01", null), key.getPrivate(), old,
                ca.certificate(), MessageTypeEnum.RENEWAL_REQ);
        // 测试中将提前续期限制设为 0，不用等旧证书接近到期即可验证换钥流程。
        ScepService renewalService = new ScepService(ca, "test-secret", 365, 0, false);
        // 用旧私钥解密响应，同时要求新证书包含新公钥；这两个参数刻意来自不同的密钥对。
        X509Certificate renewed = ScepCodec.readResponse(renewalService.handle(request.encoded()), request,
                ca.certificate(), key.getPrivate(), newKey.getPublic());
        assertNotEquals(old.getSerialNumber(), renewed.getSerialNumber());
        assertTrue(ca.isIssued(renewed));
    }

    /**
     * 续期要同时满足本项目的时间窗口和身份约束；合法旧证书不是任意改名的授权。
     * @throws Exception 测试所需密码或 I/O 操作异常时由 JUnit 报告
     */
    @Test
    void rejectsEarlyRenewalAndSubjectChange() throws Exception {
        X509Certificate old = enroll();
        ScepCodec.Request early = ScepCodec.request(csr(key, "CN=device-01", null), key.getPrivate(), old,
                ca.certificate(), MessageTypeEnum.RENEWAL_REQ);
        assertThrows(ScepFailureException.class, () -> ScepCodec.readResponse(service.handle(early.encoded()), early,
                ca.certificate(), key.getPrivate(), key.getPublic()));
        ScepCodec.Request changed = ScepCodec.request(csr(key, "CN=other-device", null), key.getPrivate(), old,
                ca.certificate(), MessageTypeEnum.RENEWAL_REQ);
        ScepService openWindow = new ScepService(ca, "test-secret", 365, 0, false);
        assertThrows(ScepFailureException.class, () -> ScepCodec.readResponse(openWindow.handle(changed.encoded()),
                changed, ca.certificate(), key.getPrivate(), key.getPublic()));
    }

    /**
     * 带正确口令的自签证书仍不能充当旧身份发起续期，注册与续期走不同授权路径。
     * @throws Exception 测试所需密码或 I/O 操作异常时由 JUnit 报告
     */
    @Test
    void rejectsSelfSignedRenewalEvenWithChallenge() throws Exception {
        ScepCodec.Request request = ScepCodec.request(csr(key, "CN=device-01", "test-secret"), key.getPrivate(), self,
                ca.certificate(), MessageTypeEnum.RENEWAL_REQ);
        assertThrows(ScepFailureException.class, () -> ScepCodec.readResponse(service.handle(request.encoded()),
                request, ca.certificate(), key.getPrivate(), key.getPublic()));
    }

    /**
     * 分别检查事务、nonce 和可信 CA，防止把其他请求或其他签发者的响应当成本次结果。
     * @throws Exception 测试所需密码或 I/O 操作异常时由 JUnit 报告
     */
    @Test
    void responseIsBoundToTransactionNonceAndTrustedCa() throws Exception {
        ScepCodec.Request request = request("test-secret");
        byte[] response = service.handle(request.encoded());
        ScepCodec.Request unrelated = request("test-secret");
        assertThrows(IllegalArgumentException.class,
                () -> ScepCodec.readResponse(response, unrelated, ca.certificate(), key.getPrivate(), key.getPublic()));
        ScepCodec.Request wrongNonce = new ScepCodec.Request(request.encoded(), request.transactionId(), new byte[16]);
        assertThrows(IllegalArgumentException.class, () -> ScepCodec.readResponse(response, wrongNonce,
                ca.certificate(), key.getPrivate(), key.getPublic()));
        ScepCodec.Request wrongId = new ScepCodec.Request(request.encoded(), "other-transaction", request.nonce());
        assertThrows(IllegalArgumentException.class,
                () -> ScepCodec.readResponse(response, wrongId, ca.certificate(), key.getPrivate(), key.getPublic()));
        assertThrows(IllegalArgumentException.class,
                () -> ScepCodec.readResponse(response, request, self, key.getPrivate(), key.getPublic()));
    }

    /**
     * CA 是信任根，重复初始化不能覆盖；重启加载必须保持同一身份。
     * @throws Exception 测试所需密码或 I/O 操作异常时由 JUnit 报告
     */
    @Test
    void refusesToOverwriteCaAndRetainsTheSameIdentityOnReload() throws Exception {
        byte[] keyBefore = Files.readAllBytes(depot.resolve("ca.key"));
        assertThrows(Exception.class, () -> CertificateAuthority.initialize(depot, "CN=Other", 2048, 3650));
        assertArrayEquals(keyBefore, Files.readAllBytes(depot.resolve("ca.key")));
        assertArrayEquals(ca.certificate().getEncoded(), CertificateAuthority.load(depot).certificate().getEncoded());
    }

    /**
     * 配置缺失应阻止服务构造，避免初始注册意外成为无口令签发。
     */
    @Test
    void rejectsEmptyChallengeConfiguration() {
        assertThrows(IllegalArgumentException.class, () -> new ScepService(ca, "", 365, 14, false));
    }

    /**
     * 检查错误码不会区分解密失败和明文不合法；这不是对所有时间侧信道的验证。
     * @throws Exception 测试所需密码或 I/O 操作异常时由 JUnit 报告
     */
    @Test
    void cryptoAndPlaintextFailuresHaveIndistinguishableProtocolErrors() throws Exception {
        byte[] malformedEnvelope = ProtocolFixtures.sign(new byte[] {1, 2, 3}, key.getPrivate(), self,
                ProtocolFixtures.requestAttributes(), true);
        byte[] malformedCsr = ProtocolFixtures.sign(
                ProtocolFixtures.encrypt(new byte[] {1, 2, 3}, ca.certificate(), CMSAlgorithm.AES128_CBC),
                key.getPrivate(), self, ProtocolFixtures.requestAttributes(), true);
        assertEquals("2", ProtocolFixtures.failInfo(service.handle(malformedEnvelope)));
        assertEquals("2", ProtocolFixtures.failInfo(service.handle(malformedCsr)));
    }

    /**
     * 相同 CN/OU/O 的不同排列仍可能是不同 DN，续期必须保留 RDN 层次顺序。
     * @throws Exception 测试所需密码或 I/O 操作异常时由 JUnit 报告
     */
    @Test
    void rejectsRenewalWithReorderedDistinguishedNameHierarchy() throws Exception {
        X500Name name = new X500Name("CN=device-01,OU=Devices,O=Example");
        ScepCodec.Request initial = ScepCodec.request(csr(key, name.toString(), "test-secret"), key.getPrivate(),
                Crypto.selfSigned(key, name), ca.certificate(), MessageTypeEnum.PKCS_REQ);
        X509Certificate old = ScepCodec.readResponse(service.handle(initial.encoded()), initial, ca.certificate(),
                key.getPrivate(), key.getPublic());
        ScepCodec.Request changed = ScepCodec.request(csr(key, "O=Example,OU=Devices,CN=device-01", null),
                key.getPrivate(), old, ca.certificate(), MessageTypeEnum.RENEWAL_REQ);
        ScepService openWindow = new ScepService(ca, "test-secret", 365, 0, false);
        assertThrows(ScepFailureException.class, () -> ScepCodec.readResponse(openWindow.handle(changed.encoded()),
                changed, ca.certificate(), key.getPrivate(), key.getPublic()));
    }

    /**
     * FAILURE 无加密正文，但其状态和失败原因仍必须通过外层签名验证。
     * @throws Exception 测试所需密码或 I/O 操作异常时由 JUnit 报告
     */
    @Test
    void failureOmitsContentAndClientAcceptsIndependentlySignedDetachedFailure() throws Exception {
        ScepCodec.Request request = request("wrong");
        byte[] failure = service.handle(request.encoded());
        CMSSignedData cms = new CMSSignedData(failure);
        assertNull(cms.getSignedContent(), "CertRep FAILURE must omit eContent");
        byte[] independent = ProtocolFixtures.sign(new byte[0], ca.key(), ca.certificate(),
                cms.getSignerInfos().getSigners().iterator().next().getSignedAttributes(), false);
        ScepFailureException denied = assertThrows(ScepFailureException.class, () -> ScepCodec.readResponse(independent,
                request, ca.certificate(), key.getPrivate(), key.getPublic()));
        assertEquals("2", denied.failInfo());
    }

    /**
     * 旧证书记录损坏应暴露为服务存储故障，不能返回误导客户端的策略拒绝。
     * @throws Exception 测试所需密码或 I/O 操作异常时由 JUnit 报告
     */
    @Test
    void corruptRenewalStorageIsAServiceFailure() throws Exception {
        X509Certificate old = enroll();
        Files.writeString(depot.resolve("issued").resolve(old.getSerialNumber().toString(16) + ".pem"), "broken");
        ScepCodec.Request renewal = ScepCodec.request(csr(key, "CN=device-01", null), key.getPrivate(), old,
                ca.certificate(), MessageTypeEnum.RENEWAL_REQ);
        ScepService openWindow = new ScepService(ca, "test-secret", 365, 0, false);
        assertThrows(IOException.class, () -> openWindow.handle(renewal.encoded()));
    }

    /**
     * 目标证书路径已被符号链接占用时，初始化不得留下新私钥或覆盖已有路径。
     * @throws Exception 测试所需密码或 I/O 操作异常时由 JUnit 报告
     */
    @Test
    void caInitializationDoesNotLeaveAKeyWhenCertificatePathIsOccupied() throws Exception {
        Assumptions.assumeTrue(Files.getFileStore(depot).supportsFileAttributeView("posix"));
        Path other = Files.createDirectory(depot.resolve("other"));
        Files.createSymbolicLink(other.resolve("ca.pem"), other.resolve("missing.pem"));
        assertThrows(Exception.class, () -> CertificateAuthority.initialize(other, "CN=Other", 2048, 3650));
        assertFalse(Files.exists(other.resolve("ca.key")));
        assertTrue(Files.isSymbolicLink(other.resolve("ca.pem")));
    }

    /**
     * 正确 CMS 签名不代替 CSR 验签；有效外层中的损坏 CSR 也必须被拒绝。
     * @throws Exception 测试所需密码或 I/O 操作异常时由 JUnit 报告
     */
    @Test
    void invalidCsrProofOfPossessionInsideValidCmsIsRejected() throws Exception {
        byte[] invalid = csr(key, "CN=device-01", "test-secret").getEncoded();
        invalid[invalid.length - 1] ^= 1;
        byte[] envelope = ProtocolFixtures.encrypt(invalid, ca.certificate(), CMSAlgorithm.AES128_CBC);
        byte[] message =
                ProtocolFixtures.sign(envelope, key.getPrivate(), self, ProtocolFixtures.requestAttributes(), true);
        assertEquals("2", ProtocolFixtures.failInfo(service.handle(message)));
    }

    /**
     * 使用独立信封构造器确认单 DES 永久禁用，不提供兼容开关。
     * @throws Exception 测试所需密码或 I/O 操作异常时由 JUnit 报告
     */
    @Test
    void singleDesIsAlwaysRejectedWithBadAlgorithm() throws Exception {
        byte[] envelope = ProtocolFixtures.encrypt(csr(key, "CN=device-01", "test-secret").getEncoded(),
                ca.certificate(), OIWObjectIdentifiers.desCBC);
        byte[] message =
                ProtocolFixtures.sign(envelope, key.getPrivate(), self, ProtocolFixtures.requestAttributes(), true);
        assertEquals("0", ProtocolFixtures.failInfo(service.handle(message)));

    }

    /**
     * 构造带扩展申请的 CSR，检查服务是否区分“客户想要的权限”和“实际授予的权限”。
     * @param key 申请密钥对
     * @param dns DNS SAN，null 表示不申请
     * @param requestCa 是否刻意申请 CA=true 以验证权限限制
     * @return 已签名的 CSR
     * @throws Exception 扩展构建或签名失败时抛出
     */
    static PKCS10CertificationRequest csrWithExtensions(KeyPair key, String dns, boolean requestCa) throws Exception {
        JcaPKCS10CertificationRequestBuilder builder =
                new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=device-01"), key.getPublic());
        builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword, new DERUTF8String("test-secret"));
        ExtensionsGenerator extensions = new ExtensionsGenerator();
        if (dns != null) {
            extensions.addExtension(Extension.subjectAlternativeName, false,
                    new GeneralNames(new GeneralName(GeneralName.dNSName, dns)));
        }
        if (requestCa) {
            extensions.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        }
        builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions.generate());
        return builder.build(Crypto.signer(key.getPrivate()));
    }

    /**
     * CSR 扩展只是申请；即便请求 CA=true，签发模板也只能给终端 clientAuth 权限。
     * @throws Exception 测试所需密码或 I/O 操作异常时由 JUnit 报告
     */
    @Test
    void csrCannotEscalateToCaPrivileges() throws Exception {
        ScepCodec.Request request = ScepCodec.request(csrWithExtensions(key, null, true), key.getPrivate(), self,
                ca.certificate(), MessageTypeEnum.PKCS_REQ);
        X509Certificate cert = ScepCodec.readResponse(service.handle(request.encoded()), request, ca.certificate(),
                key.getPrivate(), key.getPublic());
        assertEquals(-1, cert.getBasicConstraints());
        assertFalse(cert.getKeyUsage()[5]);
        assertEquals(List.of("1.3.6.1.5.5.7.3.2"), cert.getExtendedKeyUsage());
    }

    /**
     * SAN 代表额外身份，默认拒绝；开放后续期仍不能增加、移除或修改它。
     * @throws Exception 测试所需密码或 I/O 操作异常时由 JUnit 报告
     */
    @Test
    void sanRequiresOptInAndRenewalMustPreserveIt() throws Exception {
        ScepCodec.Request initial = ScepCodec.request(csrWithExtensions(key, "device.example", false), key.getPrivate(),
                self, ca.certificate(), MessageTypeEnum.PKCS_REQ);
        assertEquals("2", ProtocolFixtures.failInfo(service.handle(initial.encoded())));
        ScepService sanService = new ScepService(ca, "test-secret", 365, 0, true);
        X509Certificate old = ScepCodec.readResponse(sanService.handle(initial.encoded()), initial, ca.certificate(),
                key.getPrivate(), key.getPublic());
        assertEquals("device.example", old.getSubjectAlternativeNames().iterator().next().get(1));
        ScepCodec.Request preserved = ScepCodec.request(csrWithExtensions(key, "device.example", false),
                key.getPrivate(), old, ca.certificate(), MessageTypeEnum.RENEWAL_REQ);
        assertTrue(ca.isIssued(ScepCodec.readResponse(sanService.handle(preserved.encoded()), preserved,
                ca.certificate(), key.getPrivate(), key.getPublic())));
        ScepCodec.Request removed = ScepCodec.request(csr(key, "CN=device-01", null), key.getPrivate(), old,
                ca.certificate(), MessageTypeEnum.RENEWAL_REQ);
        ScepCodec.Request changed = ScepCodec.request(csrWithExtensions(key, "other.example", false), key.getPrivate(),
                old, ca.certificate(), MessageTypeEnum.RENEWAL_REQ);
        assertEquals("2", ProtocolFixtures.failInfo(sanService.handle(removed.encoded())));
        assertEquals("2", ProtocolFixtures.failInfo(sanService.handle(changed.encoded())));
        X509Certificate noSan = enroll();
        ScepCodec.Request added = ScepCodec.request(csrWithExtensions(key, "device.example", false), key.getPrivate(),
                noSan, ca.certificate(), MessageTypeEnum.RENEWAL_REQ);
        assertEquals("2", ProtocolFixtures.failInfo(sanService.handle(added.encoded())));
    }

    /**
     * 通过 CA 签名校验的旧证书若不在本实例签发记录中，应返回 RFC 8894 的 badCertId。
     * @throws Exception 测试所需密码或 I/O 操作异常时由 JUnit 报告
     */
    @Test
    void missingRenewalRecordIsDenied() throws Exception {
        X509Certificate old = enroll();
        Files.delete(depot.resolve("issued").resolve(old.getSerialNumber().toString(16) + ".pem"));
        ScepCodec.Request renewal = ScepCodec.request(csr(key, "CN=device-01", null), key.getPrivate(), old,
                ca.certificate(), MessageTypeEnum.RENEWAL_REQ);
        assertEquals("4",
                ProtocolFixtures.failInfo(new ScepService(ca, "test-secret", 365, 0, false).handle(renewal.encoded())));
    }
}

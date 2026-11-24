package com.example.scep.server;

import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1PrintableString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import com.example.scep.common.crypto.Crypto;
import com.example.scep.common.protocol.ScepCodec;
import com.example.scep.common.protocol.ScepConstants;
import com.example.scep.common.protocol.ScepFailureException;
import com.example.scep.common.protocol.enums.FailInfoEnum;
import com.example.scep.common.protocol.enums.MessageTypeEnum;
import com.example.scep.server.ca.CertificateAuthority;
import com.example.scep.server.service.ScepService;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 审核问题回归：使用独立 BC 报文证明互通边界，避免编码器与解析器共同掩盖错误。
 * @author robin.li
 * @date 2026-11-22 09:45:39
 */
class ProtocolRegressionTest {
    @TempDir
    Path depot;

    CertificateAuthority ca;

    ScepService service;

    KeyPair key;

    X509Certificate identity;

    ScepCodec.Request request;

    byte[] validResponse;

    X509Certificate issued;

    /** 每个测试准备独立可信 CA、客户端身份及真实成功响应。 */
    @BeforeEach
    void setup() throws Exception {
        CertificateAuthority.initialize(depot, "CN=Regression CA", 2048, 365);
        ca = CertificateAuthority.load(depot);
        service = new ScepService(ca, "test-secret", 30, 0, false);
        key = Crypto.rsa(2048);
        identity = Crypto.selfSigned(key, new X500Name("CN=device-01"));
        request = ScepCodec.request(ScepServiceTest.csr(key, "CN=device-01", "test-secret"), key.getPrivate(), identity,
                ca.certificate(), MessageTypeEnum.PKCS_REQ);
        validResponse = service.handle(request.encoded());
        issued = read(validResponse);
    }

    /** 按当前申请上下文读取响应，所有测试都保留真实签名、事务和 nonce 校验。 */
    private X509Certificate read(byte[] response) throws Exception {
        return ScepCodec.readResponse(response, request, ca.certificate(), key.getPrivate(), key.getPublic());
    }

    /** 枚举重构不能改变线上编码；用 BC 直接读取已签名属性，而不是用同一枚举自证。 */
    @Test
    void preservesLiteralWireValues() throws Exception {
        AttributeTable requestAttributes = new CMSSignedData(request.encoded()).getSignerInfos().getSigners().iterator()
                .next().getSignedAttributes();
        AttributeTable successAttributes =
                new CMSSignedData(validResponse).getSignerInfos().getSigners().iterator().next().getSignedAttributes();
        ASN1ObjectIdentifier messageType = new ASN1ObjectIdentifier("2.16.840.1.113733.1.9.2");
        ASN1ObjectIdentifier pkiStatus = new ASN1ObjectIdentifier("2.16.840.1.113733.1.9.3");
        assertEquals("19", ASN1PrintableString
                .getInstance(requestAttributes.get(messageType).getAttrValues().getObjectAt(0)).getString());
        assertEquals("3", ASN1PrintableString
                .getInstance(successAttributes.get(messageType).getAttrValues().getObjectAt(0)).getString());
        assertEquals("0", ASN1PrintableString
                .getInstance(successAttributes.get(pkiStatus).getAttrValues().getObjectAt(0)).getString());
    }

    /** 未知 messageType 的外层签名仍可信，应收到可验签的 badRequest，不能退化成解析失败。 */
    @Test
    void returnsSignedFailureForUnknownMessageType() throws Exception {
        AttributeTable attributes = new CMSSignedData(request.encoded()).getSignerInfos().getSigners().iterator().next()
                .getSignedAttributes().remove(ScepConstants.MESSAGE_TYPE)
                .add(ScepConstants.MESSAGE_TYPE, new DERPrintableString("99"));
        byte[] encoded = ProtocolFixtures.sign(ScepCodec.decodeRequest(request.encoded()).content(), key.getPrivate(),
                identity, attributes, true);
        assertEquals(MessageTypeEnum.UNKNOWN, ScepCodec.decodeRequest(encoded).type());
        ScepFailureException failure = assertThrows(ScepFailureException.class, () -> read(service.handle(encoded)));
        assertEquals("2", failure.failInfo());
    }

    /** 未知失败原因仍是失败，并保留线上原始码供排查，不会变成成功。 */
    @Test
    void retainsUnknownFailureCode() throws Exception {
        AttributeTable attributes = responseAttributes(request).remove(ScepConstants.PKI_STATUS)
                .add(ScepConstants.PKI_STATUS, new DERPrintableString("2"))
                .add(ScepConstants.FAIL_INFO, new DERPrintableString("99"));
        byte[] encoded = ProtocolFixtures.sign(new byte[0], ca.key(), ca.certificate(), attributes, false);
        ScepFailureException failure = assertThrows(ScepFailureException.class, () -> read(encoded));
        assertEquals("99", failure.failInfo());
        assertTrue(failure.getMessage().contains("未知失败原因"));
    }

    /** PENDING 和扩展状态都应明确拒绝，不能继续尝试按 SUCCESS 解密证书包。 */
    @ParameterizedTest
    @ValueSource(strings = {"3", "99"})
    void rejectsPendingAndUnknownStatus(String status) throws Exception {
        AttributeTable attributes = responseAttributes(request).remove(ScepConstants.PKI_STATUS)
                .add(ScepConstants.PKI_STATUS, new DERPrintableString(status));
        byte[] encoded = ProtocolFixtures.sign(new byte[0], ca.key(), ca.certificate(), attributes, false);
        IllegalArgumentException failure = assertThrows(IllegalArgumentException.class, () -> read(encoded));
        assertEquals("不支持该 SCEP 状态：" + status, failure.getMessage());
    }

    /** 响应必须带新的 16 字节 senderNonce，不能省略、截断或复用请求 nonce。 */
    @Test
    void requiresFreshResponseSenderNonce() throws Exception {
        AttributeTable missing = responseAttributes(request).remove(ScepConstants.SENDER_NONCE);
        byte[] missingNonce = ProtocolFixtures.sign(new byte[0], ca.key(), ca.certificate(), missing, false);
        assertThrows(IllegalArgumentException.class, () -> read(missingNonce));

        AttributeTable shortNonce = responseAttributes(request).remove(ScepConstants.SENDER_NONCE)
                .add(ScepConstants.SENDER_NONCE, new DEROctetString(new byte[15]));
        byte[] invalidLength = ProtocolFixtures.sign(new byte[0], ca.key(), ca.certificate(), shortNonce, false);
        assertThrows(IllegalArgumentException.class, () -> read(invalidLength));

        AttributeTable reused = responseAttributes(request).remove(ScepConstants.SENDER_NONCE)
                .add(ScepConstants.SENDER_NONCE, new DEROctetString(request.nonce()));
        byte[] reusedNonce = ProtocolFixtures.sign(new byte[0], ca.key(), ca.certificate(), reused, false);
        assertThrows(IllegalArgumentException.class, () -> read(reusedNonce));
    }

    /** FAILURE/PENDING 必须省略外层 eContent；存在空内容也不能当作省略处理。 */
    @ParameterizedTest
    @ValueSource(strings = {"2", "3"})
    void rejectsFailureAndPendingWithContent(String status) throws Exception {
        AttributeTable attributes = responseAttributes(request).remove(ScepConstants.PKI_STATUS)
                .add(ScepConstants.PKI_STATUS, new DERPrintableString(status));
        byte[] encoded = ProtocolFixtures.sign(new byte[0], ca.key(), ca.certificate(), attributes, true);
        IllegalArgumentException failure = assertThrows(IllegalArgumentException.class, () -> read(encoded));
        assertEquals("FAILURE 或 PENDING 响应不得包含 pkcsPKIEnvelope", failure.getMessage());
    }

    /** 仅删除未签名的 certificates 字段，签名本身仍可用本地可信 CA 验证。 */
    @Test
    void acceptsResponseWithoutEmbeddedCa() throws Exception {
        CMSSignedData stripped =
                CMSSignedData.replaceCertificatesAndCRLs(new CMSSignedData(validResponse), null, null, null);
        assertTrue(stripped.getCertificates().getMatches(null).isEmpty());
        assertEquals(issued, read(stripped.getEncoded()));
    }

    /** 无 eContent 的失败响应省略 CA 后，仍应完成验签并报告原 failInfo。 */
    @Test
    void acceptsSignedFailureWithoutEmbeddedCa() throws Exception {
        byte[] failure = ScepCodec.failure(ScepCodec.decodeRequest(request.encoded()), FailInfoEnum.BAD_REQUEST,
                ca.certificate(), ca.key());
        byte[] stripped =
                CMSSignedData.replaceCertificatesAndCRLs(new CMSSignedData(failure), null, null, null).getEncoded();
        ScepFailureException result = assertThrows(ScepFailureException.class, () -> read(stripped));
        assertEquals("2", result.failInfo());
    }

    /** 请求方的身份尚未预配置，所以请求仍必须携带自己的签名证书。 */
    @Test
    void rejectsRequestWithoutIdentity() throws Exception {
        byte[] stripped = CMSSignedData
                .replaceCertificatesAndCRLs(new CMSSignedData(request.encoded()), null, null, null).getEncoded();
        assertThrows(IllegalArgumentException.class, () -> ScepCodec.decodeRequest(stripped));
    }

    /** 不附带证书不能绕过 SignerIdentifier 与可信 CA 的绑定。 */
    @Test
    void rejectsUnknownResponseSignerWithoutCertificate() throws Exception {
        CMSSignedData original = new CMSSignedData(validResponse);
        byte[] forged = ProtocolFixtures.sign((byte[])original.getSignedContent().getContent(), key.getPrivate(),
                identity, original.getSignerInfos().getSigners().iterator().next().getSignedAttributes(), true);
        byte[] stripped =
                CMSSignedData.replaceCertificatesAndCRLs(new CMSSignedData(forged), null, null, null).getEncoded();
        assertThrows(Exception.class, () -> read(stripped));
    }

    /** 签名证书来自本地也必须验签，不能只匹配 SID 就接受正文。 */
    @Test
    void rejectsTamperedResponseWithoutCertificate() throws Exception {
        byte[] stripped = CMSSignedData.replaceCertificatesAndCRLs(new CMSSignedData(validResponse), null, null, null)
                .getEncoded();
        stripped[stripped.length - 1] ^= 1;
        assertThrows(Exception.class, () -> read(stripped));
    }

    /** CSR 内容正确，但加密信封宣称的内容类型错误时也应拒绝。 */
    @Test
    void rejectsWrongRequestEnvelopeContentType() throws Exception {
        byte[] wrongType = envelope(ScepServiceTest.csr(key, "CN=device-01", "test-secret").getEncoded(),
                ca.certificate(), CMSObjectIdentifiers.signedData);
        byte[] message = ProtocolFixtures.sign(wrongType, key.getPrivate(), identity,
                ProtocolFixtures.requestAttributes(), true);
        CMSSignedData result = new CMSSignedData(service.handle(message));
        assertEquals("2",
                ASN1PrintableString.getInstance(result.getSignerInfos().getSigners().iterator().next()
                        .getSignedAttributes().get(ScepConstants.PKI_STATUS).getAttrValues().getObjectAt(0))
                        .getString());
    }

    /** 客户端和服务端共用信封校验：响应也必须声明 id-data。 */
    @Test
    void rejectsWrongResponseEnvelopeContentType() throws Exception {
        CMSSignedDataGenerator bag = certificateBag();
        byte[] response = response(bag.generate(new CMSAbsentContent()).getEncoded(), CMSObjectIdentifiers.signedData,
                request, identity, ca);
        assertThrows(IllegalArgumentException.class, () -> read(response));
    }

    /** 退化 SignedData 的 eContent 必须缺失，连空字节正文也不是“缺失”。 */
    @Test
    void rejectsCertificateBagWithContent() throws Exception {
        for (byte[] content : new byte[][] {new byte[0], new byte[] {1, 2, 3}}) {
            byte[] bag = certificateBag().generate(new CMSProcessableByteArray(content), true).getEncoded();
            byte[] response = response(bag, CMSObjectIdentifiers.data, request, identity, ca);
            assertThrows(IllegalArgumentException.class, () -> read(response));
        }
    }

    /** 内层只负责装证书，不应另带 SignerInfo，签名由最外层负责。 */
    @Test
    void rejectsCertificateBagWithSigner() throws Exception {
        CMSSignedDataGenerator bag = certificateBag();
        bag.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().setProvider(Crypto.PROVIDER).build())
                .build(Crypto.signer(ca.key()), ca.certificate()));
        byte[] response = response(bag.generate(new CMSAbsentContent()).getEncoded(), CMSObjectIdentifiers.data,
                request, identity, ca);
        assertThrows(IllegalArgumentException.class, () -> read(response));
    }

    /** 即使没有正文，内层 SignedData 的 eContentType 也必须是 id-data。 */
    @Test
    void rejectsCertificateBagWithWrongContentType() throws Exception {
        byte[] bag = certificateBag().generate(new CMSAbsentContent(CMSObjectIdentifiers.signedData)).getEncoded();
        byte[] response = response(bag, CMSObjectIdentifiers.data, request, identity, ca);
        assertThrows(IllegalArgumentException.class, () -> read(response));
    }

    /** 准备合法证书集合，由各测试分别改变其结构而不改变证书。 */
    private CMSSignedDataGenerator certificateBag() throws Exception {
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        generator.addCertificate(new JcaX509CertificateHolder(issued));
        return generator;
    }

    private static byte[] envelope(byte[] plaintext, X509Certificate recipient, ASN1ObjectIdentifier contentType)
            throws Exception {
        CMSEnvelopedDataGenerator generator = new CMSEnvelopedDataGenerator();
        generator.addRecipientInfoGenerator(
                new JceKeyTransRecipientInfoGenerator(recipient).setProvider(Crypto.PROVIDER));
        return generator
                .generate(new CMSProcessableByteArray(contentType, plaintext),
                        new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(Crypto.PROVIDER).build())
                .getEncoded();
    }

    private static AttributeTable responseAttributes(ScepCodec.Request request) {
        ASN1EncodableVector attributes = new ASN1EncodableVector();
        attributes.add(new Attribute(ScepConstants.MESSAGE_TYPE, new DERSet(new DERPrintableString("3"))));
        attributes.add(new Attribute(ScepConstants.PKI_STATUS, new DERSet(new DERPrintableString("0"))));
        attributes.add(new Attribute(ScepConstants.TRANSACTION_ID,
                new DERSet(new DERPrintableString(request.transactionId()))));
        attributes.add(new Attribute(ScepConstants.RECIPIENT_NONCE, new DERSet(new DEROctetString(request.nonce()))));
        attributes
                .add(new Attribute(ScepConstants.SENDER_NONCE, new DERSet(new DEROctetString(Crypto.randomBytes(16)))));
        return new AttributeTable(attributes);
    }

    private static byte[] response(byte[] bag, ASN1ObjectIdentifier contentType, ScepCodec.Request request,
            X509Certificate recipient, CertificateAuthority ca) throws Exception {
        return ProtocolFixtures.sign(envelope(bag, recipient, contentType), ca.key(), ca.certificate(),
                responseAttributes(request), true);
    }

}

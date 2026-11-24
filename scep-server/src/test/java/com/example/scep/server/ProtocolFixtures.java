package com.example.scep.server;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1PrintableString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import com.example.scep.common.crypto.Crypto;

/**
 * 用 BC 独立构造边界 CMS，避免生产编码器和解析器带着同一个错误互相验证。
 * <p>固定事务和全零 nonce 仅用作测试夹具，生产请求必须使用自己的新事务与随机 nonce。</p>
 *
 * @author robin.li
 * @date 2026-11-20 21:52:59
 */
final class ProtocolFixtures {
    private ProtocolFixtures() {
    }

    /**
     * 加密任意内容，让测试能构造“信封正确但明文不是有效 CSR”的消息。
     * @param bytes 内层明文，可能刻意损坏
     * @param recipient 接收者证书
     * @param algorithm 用于测试算法允许列表的加密 OID
     * @return CMS EnvelopedData 字节
     * @throws Exception 测试消息无法加密时抛出
     */
    static byte[] encrypt(byte[] bytes, X509Certificate recipient, ASN1ObjectIdentifier algorithm) throws Exception {
        CMSEnvelopedDataGenerator generator = new CMSEnvelopedDataGenerator();
        generator.addRecipientInfoGenerator(
                new JceKeyTransRecipientInfoGenerator(recipient).setProvider(Crypto.PROVIDER));
        return generator.generate(new CMSProcessableByteArray(bytes),
                new JceCMSContentEncryptorBuilder(algorithm).setProvider(Crypto.PROVIDER).build()).getEncoded();
    }

    /**
     * 为自定义信封或空内容签名，用于独立检查服务器和客户端的校验分支。
     * @param bytes 待签内容
     * @param key 签名私钥
     * @param certificate 签名证书
     * @param attributes 测试指定的属性
     * @param attached 是否携带 eContent
     * @return CMS SignedData 字节
     * @throws Exception 签名或编码失败时抛出
     */
    static byte[] sign(byte[] bytes, PrivateKey key, X509Certificate certificate, AttributeTable attributes,
            boolean attached) throws Exception {
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        JcaSignerInfoGeneratorBuilder builder = new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().setProvider(Crypto.PROVIDER).build());
        builder.setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(attributes));
        generator.addSignerInfoGenerator(builder.build(Crypto.signer(key), certificate));
        generator.addCertificate(new JcaX509CertificateHolder(certificate));
        return generator.generate(new CMSProcessableByteArray(bytes), attached).getEncoded();
    }

    /**
     * 用明确的 OID 和固定测试值构造 PKCSReq 属性，避免依赖生产属性生成函数。
     * @return 固定事务、16 字节 nonce 和 messageType=19 的属性表
     */
    static AttributeTable requestAttributes() {
        ASN1EncodableVector values = new ASN1EncodableVector();
        values.add(new Attribute(new ASN1ObjectIdentifier("2.16.840.1.113733.1.9.2"),
                new DERSet(new DERPrintableString("19"))));
        values.add(new Attribute(new ASN1ObjectIdentifier("2.16.840.1.113733.1.9.7"),
                new DERSet(new DERPrintableString("independent-request"))));
        values.add(new Attribute(new ASN1ObjectIdentifier("2.16.840.1.113733.1.9.5"),
                new DERSet(new DEROctetString(new byte[16]))));
        return new AttributeTable(values);
    }

    /**
     * 直接读取错误码以断言测试结果；此辅助方法不验签，不能用于生产客户端。
     * @param response 由受测服务生成的 CertRep
     * @return failInfo 字符串
     * @throws Exception 响应无法解析或缺少失败属性时抛出
     */
    static String failInfo(byte[] response) throws Exception {
        SignerInformation info = new CMSSignedData(response).getSignerInfos().getSigners().iterator().next();
        return ASN1PrintableString.getInstance(info.getSignedAttributes()
                .get(new ASN1ObjectIdentifier("2.16.840.1.113733.1.9.4")).getAttrValues().getObjectAt(0)).getString();
    }
}

package com.example.scep.common.protocol;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * SCEP 编码与 HTTP 传输共用的常量；部署策略和密码策略由各自模块管理。
 *
 * @author robin.li
 * @date 2026-11-22 22:26:22
 */
public final class ScepConstants {
    /**
     * RFC 要求 nonce 为 16 字节。
     */
    public static final int NONCE_BYTES = 16;

    /**
     * 本客户端事务标识随机源长度；输出十六进制文本，不是证书序列号。
     */
    public static final int TRANSACTION_ID_RANDOM_BYTES = 24;

    /**
     * 本实现接收事务标识的长度上限。
     */
    public static final int MAX_TRANSACTION_ID_LENGTH = 256;

    /**
     * CMS 二进制报文的媒体类型。
     */
    public static final String PKI_MESSAGE_MEDIA_TYPE = "application/x-pki-message";

    /**
     * 单 CA 证书的 DER 响应媒体类型。
     */
    public static final String CA_CERT_MEDIA_TYPE = "application/x-x509-ca-cert";

    /**
     * URL 操作参数。
     */
    public static final String OPERATION_PARAMETER = "operation";

    /**
     * 能力发现的线上值；与 OperationEnum 共用，供要求编译期常量的路由注解引用。
     */
    public static final String GET_CA_CAPS_OPERATION = "GetCACaps";

    /**
     * CA 证书下载的线上值。
     */
    public static final String GET_CA_CERT_OPERATION = "GetCACert";

    /**
     * CMS 消息提交的线上值；注册与续期都使用此操作。
     */
    public static final String PKI_OPERATION = "PKIOperation";

    /**
     * GET 提交报文时使用的 Base64 参数。
     */
    public static final String MESSAGE_PARAMETER = "message";

    private static final ASN1ObjectIdentifier SCEP_ATTRIBUTE_ROOT = new ASN1ObjectIdentifier("2.16.840.1.113733.1.9");

    /**
     * PrintableString：19=PKCSReq、17=RenewalReq、3=CertRep；不是 ASN.1 INTEGER。
     */
    public static final ASN1ObjectIdentifier MESSAGE_TYPE = SCEP_ATTRIBUTE_ROOT.branch("2");

    /**
     * PrintableString：0=SUCCESS、2=FAILURE、3=PENDING；本项目不实现 PENDING 流程。
     */
    public static final ASN1ObjectIdentifier PKI_STATUS = SCEP_ATTRIBUTE_ROOT.branch("3");

    /**
     * PrintableString：失败原因；如 2=badRequest，与 pkiStatus 的数值属于不同枚举。
     */
    public static final ASN1ObjectIdentifier FAIL_INFO = SCEP_ATTRIBUTE_ROOT.branch("4");

    /**
     * OCTET STRING：本条消息发送者生成的 16 字节随机数。
     */
    public static final ASN1ObjectIdentifier SENDER_NONCE = SCEP_ATTRIBUTE_ROOT.branch("5");

    /**
     * OCTET STRING：响应回显请求的 senderNonce，供请求方检查消息关联。
     */
    public static final ASN1ObjectIdentifier RECIPIENT_NONCE = SCEP_ATTRIBUTE_ROOT.branch("6");

    /**
     * PrintableString：客户端指定的事务标识；它不是证书序列号，也不是授权凭据。
     */
    public static final ASN1ObjectIdentifier TRANSACTION_ID = SCEP_ATTRIBUTE_ROOT.branch("7");

    private ScepConstants() {
    }
}

package com.example.scep.common.protocol.enums;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * GetCACaps 的已知能力名称。未知能力仍由客户端保留为文本，便于兼容协议扩展。
 *
 * @author robin.li
 * @date 2026-11-22 22:26:22
 */
@Getter
@RequiredArgsConstructor
public enum CapabilityEnum {

    /**
     * AES 内容加密。
     */
    AES("AES"),
    /**
     * 三重 DES；与被禁止的单 DES 不同，仅接收旧端请求时兼容。
     */
    DES3("DES3"),
    /**
     * SHA-1 摘要；仅接收旧消息时兼容。
     */
    SHA1("SHA-1"),
    /**
     * SHA-256 摘要，本项目发送消息的算法。
     */
    SHA256("SHA-256"),
    /**
     * PKIOperation 支持 POST；未声明时客户端使用 GET。
     */
    POST_PKI_OPERATION("POSTPKIOperation"),
    /**
     * 允许已有证书续期。
     */
    RENEWAL("Renewal"),
    /**
     * 隐含 AES、SHA-256、POST，不能据此推断支持 Renewal。
     */
    SCEP_STANDARD("SCEPStandard");

    private final String code;
}

package com.example.scep.common.protocol.enums;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * CMS signedAttrs 中的 messageType（RFC 8894 §3.2.1.2），编码为 PrintableString。
 * <p>code 是线上协议值，与枚举的声明顺序无关；不能用 ordinal() 代替。</p>
 *
 * @author robin.li
 * @date 2026-11-22 22:26:22
 */
@Getter
@RequiredArgsConstructor
public enum MessageTypeEnum {
    /**
     * 证书响应。
     */
    CERT_REP("3"),
    /**
     * 用已有证书授权续期。
     */
    RENEWAL_REQ("17"),
    /**
     * 首次注册。
     */
    PKCS_REQ("19"),
    /**
     * 轮询待审批申请；本项目识别但不实现。
     */
    CERT_POLL("20"),
    /**
     * 查询证书；本项目识别但不实现。
     */
    GET_CERT("21"),
    /**
     * 查询吊销列表；本项目识别但不实现。
     */
    GET_CRL("22"),
    /**
     * 未识别的输入；仅用于解析结果，不能发送。
     */
    UNKNOWN("");

    private final String code;

    /**
     * 将线上值映射为领域枚举；未知值交由上层按协议返回拒绝。
     */
    public static MessageTypeEnum fromCode(String code) {
        for (MessageTypeEnum value : values()) {
            if (value.code.equals(code)) {
                return value;
            }
        }
        return UNKNOWN;
    }
}

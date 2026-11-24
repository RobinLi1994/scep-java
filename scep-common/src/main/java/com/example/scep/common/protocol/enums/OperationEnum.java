package com.example.scep.common.protocol.enums;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

import com.example.scep.common.protocol.ScepConstants;

/**
 * URL 中的 operation，区分 HTTP 操作；注册与续期都使用 PKIOperation。
 * <p>code 是线上协议值，与枚举的声明顺序无关；不能用 ordinal() 代替。</p>
 *
 * @author robin.li
 * @date 2026-11-22 22:26:22
 */
@Getter
@RequiredArgsConstructor
public enum OperationEnum {
    /**
     * 查询服务能力。
     */
    GET_CA_CAPS(ScepConstants.GET_CA_CAPS_OPERATION),
    /**
     * 获取 CA 证书；下载不等于信任。
     */
    GET_CA_CERT(ScepConstants.GET_CA_CERT_OPERATION),
    /**
     * 提交 CMS 协议消息。
     */
    PKI_OPERATION(ScepConstants.PKI_OPERATION),
    /**
     * 不支持的 HTTP 操作。
     */
    UNKNOWN("");

    private final String code;

    /**
     * 将线上值映射为领域枚举；未知值交由上层按协议返回拒绝。
     */
    public static OperationEnum fromCode(String code) {
        for (OperationEnum value : values()) {
            if (value.code.equals(code)) {
                return value;
            }
        }
        return UNKNOWN;
    }
}

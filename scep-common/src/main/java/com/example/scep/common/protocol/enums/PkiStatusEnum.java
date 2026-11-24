package com.example.scep.common.protocol.enums;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * CertRep 的 pkiStatus，与 HTTP 状态码和 messageType 分属不同含义。
 * <p>code 是线上协议值，与枚举的声明顺序无关；不能用 ordinal() 代替。</p>
 *
 * @author robin.li
 * @date 2026-11-22 22:26:22
 */
@Getter
@RequiredArgsConstructor
public enum PkiStatusEnum {
    /**
     * 签发成功，需要继续解密并检查证书。
     */
    SUCCESS("0"),
    /**
     * 申请失败，具体原因在 failInfo 中。
     */
    FAILURE("2"),
    /**
     * 等待审批；本客户端不实现轮询。
     */
    PENDING("3"),
    /**
     * 未知状态，客户端必须拒绝。
     */
    UNKNOWN("");

    private final String code;

    /**
     * 将线上值映射为领域枚举；未知值交由上层按协议返回拒绝。
     */
    public static PkiStatusEnum fromCode(String code) {
        for (PkiStatusEnum value : values()) {
            if (value.code.equals(code)) {
                return value;
            }
        }
        return UNKNOWN;
    }
}

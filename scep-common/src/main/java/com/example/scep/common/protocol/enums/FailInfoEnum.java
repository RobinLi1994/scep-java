package com.example.scep.common.protocol.enums;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * CertRep FAILURE 的失败原因（RFC 8894 §3.2.1.4）；不携带内部异常或注册口令。
 *
 * @author robin.li
 * @date 2026-11-22 22:26:22
 */
@Getter
@RequiredArgsConstructor
public enum FailInfoEnum {
    /**
     * badAlg：算法不受支持。
     */
    BAD_ALG("0", "算法不受支持"),
    /**
     * badMessageCheck：消息完整性校验失败。
     */
    BAD_MESSAGE_CHECK("1", "消息完整性校验失败"),
    /**
     * badRequest：交易不允许、未支持或 CSR/授权策略不满足。
     */
    BAD_REQUEST("2", "申请不符合服务端要求"),
    /**
     * badTime：签名时间不符合要求。
     */
    BAD_TIME("3", "签名时间不符合要求"),
    /**
     * badCertId：指定证书不存在。
     */
    BAD_CERT_ID("4", "未找到指定证书"),
    /**
     * 未识别的输入，仅用于解析结果。
     */
    UNKNOWN("", "未知失败原因");

    private final String code;

    private final String description;

    /**
     * 保留未知原因的拒绝语义；异常对象另行保存原始原因码，便于排查互通。
     */
    public static FailInfoEnum fromCode(String code) {
        for (FailInfoEnum value : values()) {
            if (value.code.equals(code)) {
                return value;
            }
        }
        return UNKNOWN;
    }
}

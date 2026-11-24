package com.example.scep.common.protocol;

import com.example.scep.common.protocol.enums.FailInfoEnum;

/**
 * 客户端已验证响应身份和事务后收到的 CertRep FAILURE。
 * <p>表示服务端明确拒绝申请，与网络不通、HTTP 错误或无法验证响应不同。
 * failInfo 是协议原因码，不是 HTTP 状态码；客户端应根据具体原因决定重试、调整算法或检查申请。</p>
 *
 * @author robin.li
 * @date 2026-11-20 21:52:59
 */
public final class ScepFailureException extends Exception {
    private static final long serialVersionUID = 1L;

    private final String failInfo;

    /**
     * 记录协议返回的失败原因。
     *
     * @param failInfo SignedData 属性中的 failInfo 字符串
     */
    public ScepFailureException(String failInfo) {
        super("SCEP 申请被拒绝：" + reason(failInfo) + "（failInfo=" + failInfo + "）");
        this.failInfo = failInfo;
    }

    /**
     * 仅翻译协议原因码，不根据解密错误推断更多内部信息。
     */
    private static String reason(String failInfo) {
        return FailInfoEnum.fromCode(failInfo).getDescription();
    }

    public String failInfo() {
        return failInfo;
    }
}

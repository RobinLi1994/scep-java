package com.example.scep.common.protocol;

import com.example.scep.common.protocol.enums.FailInfoEnum;

/**
 * 带 SCEP 协议失败原因的报文异常。
 *
 * <p>这是解析层对异常分类的保留。能取得合法的事务关联字段时，服务端可将
 * {@link FailInfoEnum} 编码成签名的 CertRep FAILURE。缺少必要字段时由上层按 HTTP 错误处理。</p>
 *
 * @author robin.li
 * @date 2026-11-23 09:00:00
 */
public final class ScepProtocolException extends IllegalArgumentException {
    private static final long serialVersionUID = 1L;

    private final FailInfoEnum failInfo;

    /**
     * 创建带协议原因的报文异常。
     *
     * @param failInfo RFC 8894 §3.2.1.4 定义的失败原因
     * @param message  面向日志和调试的中文说明，不应包含密钥或注册口令
     */
    public ScepProtocolException(FailInfoEnum failInfo, String message) {
        this(failInfo, message, null);
    }

    /**
     * 创建带 SCEP 失败原因和底层异常的报文异常。
     *
     * @param failInfo RFC 8894 定义的失败原因
     * @param message  中文诊断说明
     * @param cause    原始异常，供服务端诊断
     */
    public ScepProtocolException(FailInfoEnum failInfo, String message, Throwable cause) {
        super(message, cause);
        if (failInfo == null || failInfo == FailInfoEnum.UNKNOWN) {
            throw new IllegalArgumentException("协议异常必须使用已知的 SCEP 失败原因");
        }
        this.failInfo = failInfo;
    }

    /**
     * 返回可用于构造 CertRep FAILURE 的原因码。
     *
     * @return SCEP 失败原因
     */
    public FailInfoEnum failInfo() {
        return failInfo;
    }
}

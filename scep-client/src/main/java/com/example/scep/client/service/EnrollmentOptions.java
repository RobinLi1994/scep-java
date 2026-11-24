package com.example.scep.client.service;

import java.net.URI;
import java.nio.file.Path;

import lombok.Value;
import lombok.experimental.Accessors;

/**
 * 客户端申请参数；key 是新证书的密钥，signingKey 是续期时证明旧身份的私钥。
 * <p>Lombok 生成只读访问方法和按字段比较的 equals/hashCode；构造器中的业务校验仍显式保留。</p>
 *
 * @author robin.li
 * @date 2026-11-22 09:53:00
 */
@Value
@Accessors(fluent = true)
public class EnrollmentOptions {
    /**
     * 服务地址。
     */
    URI endpoint;

    /**
     * 预配可信 CA 文件。
     */
    Path ca;

    /**
     * 首次注册主题；续期默认沿用旧主题。
     */
    String subject;

    /**
     * 申请密钥文件，不存在时创建。
     */
    Path key;

    /**
     * 新证书输出，不覆盖既有文件。
     */
    Path output;

    /**
     * 续期旧证书，初始注册为 null。
     */
    Path renewFrom;

    /**
     * 旧身份私钥；续期必填，初始注册为 null。
     */
    Path signingKey;

    /**
     * 创建并校验参数；校验成功后一次性保存，运行过程中不提供 setter。
     */
    public EnrollmentOptions(URI endpoint, Path ca, String subject, Path key, Path output, Path renewFrom,
            Path signingKey) {
        if (endpoint == null || ca == null || key == null || output == null) {
            throw new IllegalArgumentException("必须通过 scep.client 配置或命令选项提供服务地址、CA、申请密钥及证书输出路径");
        }
        if (renewFrom == null) {
            if (subject == null || subject.isBlank()) {
                throw new IllegalArgumentException("首次注册必须配置 scep.client.subject 或提供 --subject");
            }
            if (signingKey != null) {
                throw new IllegalArgumentException("指定旧私钥时必须同时提供续期旧证书");
            }
        } else if (signingKey == null) {
            throw new IllegalArgumentException("续期必须提供旧证书对应的签名私钥");
        }
        this.endpoint = endpoint;
        this.ca = ca;
        this.subject = subject;
        this.key = key;
        this.output = output;
        this.renewFrom = renewFrom;
        this.signingKey = signingKey;
    }

}

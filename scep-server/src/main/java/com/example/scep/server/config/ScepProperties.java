package com.example.scep.server.config;

import java.nio.file.Path;

import lombok.ToString;
import lombok.Value;
import lombok.experimental.Accessors;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.ConstructorBinding;
import org.springframework.core.io.Resource;

/**
 * Spring Boot 将 application.yml 的 scep.* 配置绑定到此普通不可变配置类。
 * <p>这些是本项目的部署和签发策略，不是 SCEP 网络消息中的字段。</p>
 *
 * <p>Lombok 生成只读访问方法和按字段比较的 equals/hashCode；构造器中的业务校验仍显式保留。</p>
 *
 * @author robin.li
 * @date 2026-11-20 21:52:59
 */
@ConfigurationProperties(prefix = "scep")
@Value
@Accessors(fluent = true)
public class ScepProperties {
    /**
     * 过小的限制装不下常见 CMS，过大则增加内存占用；范围是本项目部署策略。
     */
    private static final int MIN_REQUEST_BYTES = 4 * 1024;

    private static final int MAX_REQUEST_BYTES = 16 * 1024 * 1024;

    /**
     * 可写数据目录，issued 子目录保存签发记录。
     */
    Path depot;

    /**
     * CA 证书资源，支持 classpath: 和 file:。
     */
    Resource caCertificate;

    /**
     * CA 私钥资源，支持 classpath: 和 file:。
     */
    Resource caPrivateKey;

    /**
     * 初始注册共享口令，由 ScepService 校验是否配置。
     */
    @ToString.Exclude
    String challenge;

    /**
     * 新证书期望有效天数。
     */
    int validityDays;

    /**
     * 允许提前续期的天数，0 表示不限制提前时间。
     */
    int renewalDays;

    /**
     * 是否允许 CSR 申请 SAN。
     */
    boolean allowSan;

    /**
     * HTTP 层允许的 CMS 最大字节数。
     */
    int maxRequestBytes;

    /**
     * 创建并校验参数；校验成功后一次性保存，运行过程中不提供 setter。
     */
    @ConstructorBinding
    public ScepProperties(Path depot, Resource caCertificate, Resource caPrivateKey, String challenge, int validityDays,
            int renewalDays, boolean allowSan, int maxRequestBytes) {
        if (caCertificate == null || caPrivateKey == null) {
            throw new IllegalArgumentException("必须配置 CA 证书和私钥的资源位置");
        }
        if (depot == null) {
            throw new IllegalArgumentException("必须配置 scep.depot 存储目录");
        }
        if (maxRequestBytes < MIN_REQUEST_BYTES || maxRequestBytes > MAX_REQUEST_BYTES) {
            throw new IllegalArgumentException("scep.max-request-bytes 必须在 4096～16777216 之间");
        }
        this.depot = depot;
        this.caCertificate = caCertificate;
        this.caPrivateKey = caPrivateKey;
        this.challenge = challenge;
        this.validityDays = validityDays;
        this.renewalDays = renewalDays;
        this.allowSan = allowSan;
        this.maxRequestBytes = maxRequestBytes;
    }

}

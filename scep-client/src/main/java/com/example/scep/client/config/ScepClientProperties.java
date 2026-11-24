package com.example.scep.client.config;

import java.net.URI;
import java.nio.file.Path;

import lombok.ToString;
import lombok.Value;
import lombok.experimental.Accessors;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 将 application.yml 的 scep.client 配置绑定为客户端默认值。
 * <p>命令行只覆盖本次操作；配置对象不随命令修改，交互会话中的下一条命令仍使用原默认值。</p>
 *
 * <p>Lombok 生成全参构造器与只读访问方法；Spring 按唯一构造器的参数名绑定配置。</p>
 *
 * @author robin.li
 * @date 2026-11-22 22:04:06
 */
@ConfigurationProperties(prefix = "scep.client")
@Value
@Accessors(fluent = true)
public class ScepClientProperties {
    /**
     * SCEP 服务地址。
     */
    URI url;

    /**
     * 预配可信 CA 的 PEM 文件路径。
     */
    Path ca;

    /**
     * 初始注册的证书主题。
     */
    String subject;

    /**
     * 初始注册的申请私钥文件，不存在时创建。
     */
    Path key;

    /**
     * 初始注册的证书输出文件。
     */
    Path out;

    /**
     * 续期使用的旧证书。
     */
    Path renewFrom;

    /**
     * 旧证书对应的签名私钥。
     */
    Path signingKey;

    /**
     * 续期申请的私钥文件，可与旧私钥不同。
     */
    Path renewKey;

    /**
     * 续期证书输出文件，不覆盖旧证书。
     */
    Path renewOut;

    /**
     * 初始注册口令，支持 YAML 中的环境变量占位符，不进入命令行帮助。
     */
    @ToString.Exclude
    String challenge;

}

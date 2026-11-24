package com.example.scep.server.config;

import java.io.InputStream;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.example.scep.common.crypto.PemFiles;
import com.example.scep.server.ca.CertificateAuthority;
import com.example.scep.server.service.ScepService;

/**
 * 服务端装配：读取 CA 资源并把 YAML 策略交给签发服务；入口类只负责启动模式。
 * @author robin.li
 * @date 2026-11-22 22:30:43
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(ScepProperties.class)
@Slf4j
public class ScepServerConfiguration {
    /**
     * 从配置的资源加载 CA，默认使用 JAR 内的 classpath:ca/ca.pem 与 ca.key。
     *
     * @param properties 存储路径等配置
     * @return 已校验的 CA
     * @throws Exception CA 文件或密钥检查失败时抛出
     */
    @Bean
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    public CertificateAuthority certificateAuthority(ScepProperties properties) throws Exception {
        log.info("装配 CA，证书资源={}，私钥资源={}，签发目录={}", properties.caCertificate().getDescription(),
                properties.caPrivateKey().getDescription(), properties.depot().toAbsolutePath());
        // ClassPathResource.getFile() 在打包成 JAR 后不可用，必须使用资源输入流。
        // depot 只负责可写的签发记录；不能把新证书写回只读的 JAR 资源目录。
        if (!properties.caCertificate().exists() || !properties.caPrivateKey().exists()) {
            throw new IllegalArgumentException("CA 证书或私钥资源不存在，请检查 scep.ca-certificate 和 scep.ca-private-key");
        }
        try (InputStream certificateInput = properties.caCertificate().getInputStream();
                InputStream privateKeyInput = properties.caPrivateKey().getInputStream()) {
            X509Certificate certificate = PemFiles.certificate(certificateInput);
            PrivateKey privateKey = PemFiles.privateKey(privateKeyInput);
            return CertificateAuthority.load(certificate, privateKey, properties.depot());
        }
    }

    /**
     * 将部署配置传给独立于 Spring 的签发服务。
     *
     * @param ca         签发及解密所用的 CA
     * @param properties 注册口令、证书模板和兼容策略
     * @return SCEP 服务对象
     * @throws IllegalArgumentException 必需口令或签发参数无效时抛出
     */
    @Bean
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    public ScepService scepService(CertificateAuthority ca, ScepProperties properties) {
        log.info("装配 SCEP 服务，证书有效期={} 天，续期窗口={} 天，允许 SAN={}", properties.validityDays(),
                properties.renewalDays(), properties.allowSan());
        return new ScepService(ca, properties.challenge(), properties.validityDays(), properties.renewalDays(),
                properties.allowSan());
    }
}

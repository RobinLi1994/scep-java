package com.example.scep.server.shell;

import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.HexFormat;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.shell.core.command.annotation.Command;
import org.springframework.shell.core.command.annotation.Option;
import org.springframework.stereotype.Component;

import com.example.scep.common.crypto.Crypto;
import com.example.scep.common.crypto.PemFiles;
import com.example.scep.common.shell.ShellConfiguration;
import com.example.scep.server.ca.CertificateAuthority;

/**
 * 服务端管理命令，仅在非 Web 管理模式注册；HTTP 服务不会暴露 CA 初始化操作。
 *
 * @author robin.li
 * @date 2026-11-22 09:53:00
 */
@Component
@ConditionalOnProperty(name = ShellConfiguration.ENABLED_PROPERTY, havingValue = "true")
@Slf4j
public class CaCommands {

    /**
     * 创建本地 CA，拒绝覆盖；输出指纹用于通过可信渠道核对身份。
     */
    @Command(name = "ca-init", description = "初始化本地 CA，已有 CA 不会被覆盖")
    public String initialize(@Option(longName = "depot", defaultValue = "depot", description = "CA 及签发记录目录") Path depot,
            @Option(longName = "subject", defaultValue = "CN=Java SCEP CA", description = "CA 主题名称") String subject,
            @Option(longName = "bits", defaultValue = "3072", description = "RSA 密钥位数，2048～8192") int bits,
            @Option(longName = "days", defaultValue = "3650", description = "CA 有效天数，1～36500") int days)
            throws Exception {
        log.info("收到 CA 初始化命令，目录={}，subject={}，RSA 位数={}，有效期={} 天", depot.toAbsolutePath(), subject,
                bits, days);
        CertificateAuthority.initialize(depot, subject, bits, days);
        X509Certificate certificate = PemFiles.certificate(depot.resolve(CertificateAuthority.CERTIFICATE_FILE));
        String fingerprint = HexFormat.of()
                .formatHex(MessageDigest.getInstance(Crypto.SHA256_ALGORITHM).digest(certificate.getEncoded()));
        return "CA 已创建：" + depot.toAbsolutePath() + "\nSHA-256 指纹：" + fingerprint;
    }
}

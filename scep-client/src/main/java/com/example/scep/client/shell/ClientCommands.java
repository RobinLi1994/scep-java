package com.example.scep.client.shell;

import java.net.URI;
import java.nio.file.Path;

import lombok.extern.slf4j.Slf4j;
import lombok.RequiredArgsConstructor;
import org.springframework.shell.core.command.annotation.Command;
import org.springframework.shell.core.command.annotation.Option;
import org.springframework.stereotype.Component;

import com.example.scep.client.config.ScepClientProperties;
import com.example.scep.client.service.EnrollmentOptions;
import com.example.scep.client.service.EnrollmentService;

/**
 * Spring Shell 命令适配：框架完成类型转换，业务流程交给 EnrollmentService。
 * <p>默认值由 YAML 注入，显式命令参数优先；口令仅从配置读取，不提供 --challenge 参数。</p>
 * <p>Lombok 为 final 配置字段生成构造器，Spring 使用该构造器完成注入。</p>
 *
 * @author robin.li
 * @date 2026-11-22 09:53:00
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class ClientCommands {
    private final ScepClientProperties properties;

    /**
     * 初始注册只接受新身份的申请材料；已有证书续期统一使用 renew。
     */
    @Command(name = "enroll", description = "注册证书；未传选项使用 scep.client 配置，口令来自 challenge 配置")
    public String enroll(@Option(longName = "url", description = "SCEP 服务地址，默认读取 scep.client.url") URI url,
            @Option(longName = "ca", description = "可信 CA 文件，默认读取 scep.client.ca") Path ca,
            @Option(longName = "subject", description = "首次注册主题，默认读取 scep.client.subject") String subject,
            @Option(longName = "key", description = "申请密钥，默认读取 scep.client.key") Path key,
            @Option(longName = "out", description = "证书输出，默认读取 scep.client.out") Path out) throws Exception {
        log.info("收到客户端注册命令");
        // 不在 @Option 中写 defaultValue，才能区分“用户没有传参数”与“用户明确覆盖配置”。
        EnrollmentOptions options = new EnrollmentOptions(url == null ? properties.url() : url,
                ca == null ? properties.ca() : ca, subject == null ? properties.subject() : subject,
                key == null ? properties.key() : key, out == null ? properties.out() : out, null, null);
        // 无旧身份代表初次注册；业务流程仍与 renew 共用，不复制 CSR 和证书保存逻辑。
        return EnrollmentService.enroll(options, properties.challenge());
    }

    /**
     * 显式续期入口，支持旧身份签名、新密钥申请的换钥续期。
     */
    @Command(name = "renew", description = "续期证书；未传选项使用 scep.client 的续期配置，新旧密钥可以不同")
    public String renew(@Option(longName = "url", description = "SCEP 服务地址，默认读取 scep.client.url") URI url,
            @Option(longName = "ca", description = "可信 CA 文件，默认读取 scep.client.ca") Path ca,
            @Option(longName = "renew-from", description = "旧证书，默认读取 scep.client.renew-from") Path renewFrom,
            @Option(longName = "signing-key", description = "旧私钥，默认读取 scep.client.signing-key") Path signingKey,
            @Option(longName = "key", description = "续期申请密钥，默认读取 scep.client.renew-key") Path key,
            @Option(longName = "out", description = "续期证书输出，默认读取 scep.client.renew-out") Path out) throws Exception {
        log.info("收到客户端续期命令");
        Path oldCertificate = renewFrom == null ? properties.renewFrom() : renewFrom;
        Path oldKey = signingKey == null ? properties.signingKey() : signingKey;
        // 必填检查在合并 YAML 和 CLI 后执行，避免拒绝仅通过 YAML 提供的合法续期材料。
        // 即便两者都缺失，也不能让 renew 因没有旧身份而被误当成初始注册。
        if (oldCertificate == null || oldKey == null) {
            throw new IllegalArgumentException("续期必须配置 scep.client.renew-from 和 signing-key，或提供对应命令选项");
        }
        EnrollmentOptions options = new EnrollmentOptions(url == null ? properties.url() : url,
                ca == null ? properties.ca() : ca, null, key == null ? properties.renewKey() : key,
                out == null ? properties.renewOut() : out, oldCertificate, oldKey);
        // 续期使用旧证书证明身份，不依赖初始注册口令。
        return EnrollmentService.enroll(options, null);
    }
}

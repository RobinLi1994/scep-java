package com.example.scep.server;

import java.util.Arrays;
import java.util.Map;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Import;

import com.example.scep.common.shell.CommandConsole;
import com.example.scep.common.shell.ShellConfiguration;
import com.example.scep.common.shell.UserMessages;

/**
 * 应用入口：无子命令时启动 HTTP 服务，有子命令时执行服务端管理工具；客户端由独立模块启动。
 * <p>Spring 只装配组件，协议和授权逻辑分别位于 ScepCodec、ScepService。
 * CA 默认从 resources/ca 读取；启动时不会重新生成密钥，重启保持同一信任根。</p>
 *
 * @author robin.li
 * @date 2026-11-20 21:52:59
 */
@Slf4j
@SpringBootApplication
@Import(ShellConfiguration.class)
public class ScepApplication {
    /**
     * 选择 CLI 或服务端模式。
     *
     * @param args ca-init/help/shell 管理命令，或以 -- 开头的 Spring 配置参数
     */
    public static void main(String[] args) {
        boolean cli = args.length > 0 && !args[0].startsWith("--");
        SpringApplication application = new SpringApplication(ScepApplication.class);
        if (!cli) {
            // 正常服务模式保留 Spring Boot 的配置参数处理，不进入 Shell 等待输入。
            try {
                application.run(args);
                log.info("SCEP 服务端启动完成");
            } catch (Exception e) {
                log.error("服务端启动失败：{}", UserMessages.describe(e), e);
                System.exit(CommandConsole.EXIT_FAILURE);
            }
            return;
        }
        // ca-init/help 等管理命令不启动 HTTP，也不加载尚未创建的 CA。
        application.setWebApplicationType(WebApplicationType.NONE);
        application.setAddCommandLineProperties(false);
        application.setDefaultProperties(
                Map.of(ShellConfiguration.ENABLED_PROPERTY, "true", "spring.main.log-startup-info", "false"));
        String[] commandArgs = "shell".equals(args[0]) ? Arrays.copyOfRange(args, 1, args.length) : args;
        int exitCode;
        try (ConfigurableApplicationContext context = application.run(commandArgs)) {
            exitCode = context.getBean(CommandConsole.class).exitCode();
        } catch (Exception e) {
            log.error("管理命令启动失败：{}", UserMessages.describe(e), e);
            exitCode = CommandConsole.EXIT_FAILURE;
        }
        System.exit(exitCode);
    }

}

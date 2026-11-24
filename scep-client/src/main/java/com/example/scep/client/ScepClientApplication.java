package com.example.scep.client;

import java.util.Map;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Import;

import com.example.scep.client.config.ScepClientProperties;
import com.example.scep.common.shell.CommandConsole;
import com.example.scep.common.shell.ShellConfiguration;
import com.example.scep.common.shell.UserMessages;

/**
 * 独立客户端入口：无参数进入 Spring Shell，有参数执行一次并返回真实退出码。
 *
 * @author robin.li
 * @date 2026-11-22 09:53:00
 */
@Slf4j
@SpringBootApplication
@EnableConfigurationProperties(ScepClientProperties.class)
@Import(ShellConfiguration.class)
public class ScepClientApplication {
    /**
     * CLI 参数只交给 Spring Shell，避免 --key 等选项被当作 Spring 部署配置。
     */
    public static void main(String[] args) {
        SpringApplication application = new SpringApplication(ScepClientApplication.class);
        application.setWebApplicationType(WebApplicationType.NONE);
        application.setAddCommandLineProperties(false);
        application.setDefaultProperties(Map.of(ShellConfiguration.ENABLED_PROPERTY, "true", "spring.main.banner-mode",
                "off", "spring.main.log-startup-info", "false"));
        int exitCode;
        try (ConfigurableApplicationContext context = application.run(args)) {
            log.info("SCEP 客户端启动完成");
            exitCode = context.getBean(CommandConsole.class).exitCode();
        } catch (Exception e) {
            log.error("客户端启动失败：{}", UserMessages.describe(e), e);
            exitCode = CommandConsole.EXIT_FAILURE;
        }
        System.exit(exitCode);
    }
}

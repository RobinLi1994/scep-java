package com.example.scep.client;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.MockedStatic;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.boot.test.context.SpringBootTest;

import com.example.scep.client.config.ScepClientProperties;
import com.example.scep.client.service.EnrollmentOptions;
import com.example.scep.client.service.EnrollmentService;
import com.example.scep.client.shell.ClientCommands;
import com.example.scep.common.shell.CommandConsole;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mockStatic;

/**
 * 使用实际 YAML 和 Shell runner 验证配置绑定、命令覆盖与注册/续期默认值隔离。
 * <p>只替换最终文件工作流，避免配置测试访问网络或写入真实证书；密码流程另有真实报文测试。</p>
 * @author robin.li
 * @date 2026-11-22 22:04:06
 */
@SpringBootTest(classes = ScepClientApplication.class, webEnvironment = SpringBootTest.WebEnvironment.NONE,
        properties = {"spring.config.import=classpath:client-config-test.yml", "scep.shell.enabled=true"},
        args = "help")
class ClientConfigurationTest {
    @Autowired
    ApplicationRunner runner;

    @Autowired
    CommandConsole console;

    @Autowired
    ScepClientProperties properties;

    @TempDir
    Path directory;

    /** 裸 enroll 命令应使用 YAML 中的所有注册配置，包括独立传入的口令。 */
    @Test
    void enrollUsesYamlDefaults() throws Exception {
        EnrollmentOptions expected = new EnrollmentOptions(URI.create("http://127.0.0.1:19090/configured-scep"),
                Path.of("yaml files/ca.pem"), "CN=YAML Device,O=Example", Path.of("yaml files/device.key"),
                Path.of("yaml files/device.pem"), null, null);
        try (MockedStatic<EnrollmentService> workflow = mockStatic(EnrollmentService.class)) {
            runner.run(new DefaultApplicationArguments("enroll"));
            workflow.verify(() -> EnrollmentService.enroll(expected, "yaml-test-secret"));
            assertEquals(0, console.exitCode());
        }
    }

    /** 显式选项覆盖 YAML，空格参数仍正确绑定，且不会改变下一条命令的默认配置。 */
    @Test
    void enrollOptionsOverrideYamlWithoutChangingDefaults() throws Exception {
        EnrollmentOptions expected =
                new EnrollmentOptions(URI.create("http://127.0.0.1:19091/override"), Path.of("cli files/ca.pem"),
                        "CN=CLI Device", Path.of("cli files/device.key"), Path.of("cli files/device.pem"), null, null);
        try (MockedStatic<EnrollmentService> workflow = mockStatic(EnrollmentService.class)) {
            runner.run(new DefaultApplicationArguments("enroll", "--url=" + expected.endpoint(),
                    "--ca=" + expected.ca(), "--subject=" + expected.subject(), "--key=" + expected.key(),
                    "--out=" + expected.output()));
            workflow.verify(() -> EnrollmentService.enroll(expected, "yaml-test-secret"));
            assertEquals(0, console.exitCode());
            assertEquals("CN=YAML Device,O=Example", properties.subject());
            assertEquals(Path.of("yaml files/device.key"), properties.key());
        }
    }

    /** 裸 renew 使用旧身份和独立的新文件配置；即使配置了注册口令也不将其传入续期。 */
    @Test
    void renewUsesYamlDefaultsWithoutRegistrationChallenge() throws Exception {
        EnrollmentOptions expected = new EnrollmentOptions(URI.create("http://127.0.0.1:19090/configured-scep"),
                Path.of("yaml files/ca.pem"), null, Path.of("yaml files/new.key"), Path.of("yaml files/renewed.pem"),
                Path.of("yaml files/old.pem"), Path.of("yaml files/old.key"));
        try (MockedStatic<EnrollmentService> workflow = mockStatic(EnrollmentService.class)) {
            runner.run(new DefaultApplicationArguments("renew"));
            workflow.verify(() -> EnrollmentService.enroll(expected, null));
            assertEquals(0, console.exitCode());
        }
    }

    /** 续期可只覆盖证书与密钥路径，服务地址和可信 CA 继续从 YAML 继承。 */
    @Test
    void renewOptionsOverrideYaml() throws Exception {
        EnrollmentOptions expected = new EnrollmentOptions(URI.create("http://127.0.0.1:19090/configured-scep"),
                Path.of("yaml files/ca.pem"), null, Path.of("cli files/new.key"), Path.of("cli files/renewed.pem"),
                Path.of("cli files/old.pem"), Path.of("cli files/old.key"));
        try (MockedStatic<EnrollmentService> workflow = mockStatic(EnrollmentService.class)) {
            runner.run(new DefaultApplicationArguments("renew", "--renew-from=" + expected.renewFrom(),
                    "--signing-key=" + expected.signingKey(), "--key=" + expected.key(), "--out=" + expected.output()));
            workflow.verify(() -> EnrollmentService.enroll(expected, null));
            assertEquals(0, console.exitCode());
        }
    }

    /** 配置遗漏旧身份时必须明确失败，不能把续期降为使用 challenge 的初始注册。 */
    @Test
    void renewRejectsMissingIdentityBeforeWorkflow() throws Exception {
        ScepClientProperties missingIdentity = new ScepClientProperties(properties.url(), properties.ca(),
                properties.subject(), properties.key(), properties.out(), null, null, properties.renewKey(),
                properties.renewOut(), properties.challenge());
        ClientCommands commands = new ClientCommands(missingIdentity);
        try (MockedStatic<EnrollmentService> workflow = mockStatic(EnrollmentService.class)) {
            IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                    () -> commands.renew(null, null, null, null, null, null));
            assertTrue(failure.getMessage().contains("续期必须配置"));
            workflow.verifyNoInteractions();
        }
    }

    /** 缺少注册口令时，在加载不存在的 CA 或生成新私钥之前报告中文配置错误。 */
    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = " ")
    void missingChallengeDoesNotCreatePrivateKey(String challenge) {
        Path key = directory.resolve("client.key");
        EnrollmentOptions options = new EnrollmentOptions(properties.url(), directory.resolve("missing-ca.pem"),
                "CN=device", key, directory.resolve("client.pem"), null, null);
        IllegalArgumentException failure =
                assertThrows(IllegalArgumentException.class, () -> EnrollmentService.enroll(options, challenge));
        assertTrue(failure.getMessage().contains("scep.client.challenge"));
        assertFalse(Files.exists(key));
    }
}

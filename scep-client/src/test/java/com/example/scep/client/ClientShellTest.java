package com.example.scep.client;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.shell.core.command.CommandRegistry;
import org.springframework.shell.core.command.DefaultCommandParser;
import org.springframework.shell.core.command.ParsedInput;

import com.example.scep.common.shell.CommandConsole;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 验证真实 Spring Shell 命令注册、参数边界和失败退出码，不访问网络或修改真实证书。
 * @author robin.li
 * @date 2026-11-22 09:51:00
 */
@SpringBootTest(classes = ScepClientApplication.class, webEnvironment = SpringBootTest.WebEnvironment.NONE,
        properties = "scep.shell.enabled=true", args = "help")
class ClientShellTest {
    @Autowired
    CommandRegistry registry;

    @Autowired
    ApplicationRunner runner;

    @Autowired
    CommandConsole console;

    /** 只提供注册与续期两个业务入口，旧 client 别名不再注册。 */
    @Test
    void registersCommandsAndHelpWithoutServerDependencies() {
        assertNotNull(registry.getCommandByName("enroll"));
        assertNull(registry.getCommandByName("client"));
        assertNotNull(registry.getCommandByName("renew"));
        assertNotNull(registry.getCommandByName("help"));
        assertNull(registry.getCommandByName("ca-init"));
    }

    /** 注册不能混入续期选项；续期选项可由 YAML 提供，所以不在语法层强制出现。 */
    @Test
    void separatesRegistrationAndRenewalOptions() {
        assertFalse(registry.getCommandByName("enroll").getOptions().stream()
                .anyMatch(option -> option.isOptionEqual("--renew-from") || option.isOptionEqual("--signing-key")));
        assertTrue(registry.getCommandByName("renew").getOptions().stream()
                .anyMatch(option -> option.isOptionEqual("--renew-from") && !Boolean.TRUE.equals(option.required())));
        assertTrue(registry.getCommandByName("renew").getOptions().stream()
                .anyMatch(option -> option.isOptionEqual("--signing-key") && !Boolean.TRUE.equals(option.required())));
    }

    /** 操作系统已分好的参数不可在交给 Shell 时丢失空格、引号或反斜杠。 */
    @Test
    void preservesQuotedArguments() {
        String path = "/tmp/测试 folder/with\"quote\\slash.key";
        String subject = "CN=Learning Device,O=Example";
        String line = CommandConsole.encodeArguments(new String[] {"enroll", "--key=" + path, "--subject", subject});
        ParsedInput parsed = new DefaultCommandParser(registry).parse(line);
        assertEquals(path, parsed.options().get(0).value());
        assertEquals(subject, parsed.options().get(1).value());
    }

    /** 解析错误、未知选项、缺少选项值及未知命令都必须使脚本失败。 */
    @ParameterizedTest
    @ValueSource(strings = {"not-a-command", "enroll --typo=x", "enroll --out", "enroll --out=a --out=b", "client",
            "enroll --renew-from=old.pem", "enroll --signing-key=old.key", "enroll extra"})
    void badCommandsReturnNonzero(String command) throws Exception {
        runner.run(new DefaultApplicationArguments(command.split(" ")));
        assertNotEquals(0, console.exitCode());
    }
}

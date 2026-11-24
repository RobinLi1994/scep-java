package com.example.scep.server;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.shell.core.InputReader;
import org.springframework.shell.core.command.CommandContext;
import org.springframework.shell.core.command.CommandExecutor;
import org.springframework.shell.core.command.CommandRegistry;
import org.springframework.shell.core.command.DefaultCommandParser;
import org.springframework.shell.core.command.ParsedInput;

import com.example.scep.common.crypto.PemFiles;
import com.example.scep.common.shell.CommandConsole;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 管理模式必须无需既有 CA 就能启动，并通过真实 Shell 参数转换创建新 CA。
 * @author robin.li
 * @date 2026-11-22 09:53:00
 */
@SpringBootTest(classes = ScepApplication.class, webEnvironment = SpringBootTest.WebEnvironment.NONE,
        properties = "scep.shell.enabled=true", args = "help")
class CaShellTest {
    @TempDir
    Path directory;

    @Autowired
    CommandRegistry registry;

    @Autowired
    ApplicationRunner runner;

    @Autowired
    CommandConsole console;

    /** 真实执行带空格路径及 subject 的管理命令，验证文件路径类型转换。 */
    @Test
    void initializesCaFromTypedShellOptions() throws Exception {
        Path depot = directory.resolve("CA with spaces");
        String line = CommandConsole.encodeArguments(new String[] {"ca-init", "--depot=" + depot,
                "--subject=CN=Shell CA,O=Example", "--bits=2048", "--days=30"});
        ParsedInput parsed = new DefaultCommandParser(registry).parse(line);
        StringWriter output = new StringWriter();
        CommandContext context = new CommandContext(parsed, registry, new PrintWriter(output), new InputReader() {});
        assertEquals(0, new CommandExecutor(registry).execute(context).code());
        assertTrue(output.toString().contains("CA 已创建"));
        assertTrue(
                PemFiles.certificate(depot.resolve("ca.pem")).getSubjectX500Principal().getName().contains("Shell CA"));
        assertNull(registry.getCommandByName("enroll"));
    }

    /** 服务端也必须经过共享 runner 校验，拒绝错误选项后不能产生 CA 文件。 */
    @ParameterizedTest
    @ValueSource(strings = {"--typo=x", "--bits=4096"})
    void rejectsInvalidOptionsBeforeCreatingCa(String option) throws Exception {
        Path depot = directory.resolve("rejected CA");
        runner.run(new DefaultApplicationArguments("ca-init", "--depot=" + depot, "--bits=2048", option));
        assertNotEquals(0, console.exitCode());
        assertFalse(Files.exists(depot));
    }
}

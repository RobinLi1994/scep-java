package com.example.scep.common.shell;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

import lombok.extern.slf4j.Slf4j;

/**
 * 与 Spring 无关的控制台 I/O：统一中文错误、退出码，以及操作系统 argv 的引号保护。
 * <p>命令注册、语法解析、选项绑定与帮助均交给两个应用注入的 Spring Shell 执行器。</p>
 *
 * @author robin.li
 * @date 2026-11-22 09:50:00
 */
@Slf4j
public final class CommandConsole {
    public static final int EXIT_SUCCESS = 0;

    public static final int EXIT_FAILURE = 1;

    private final BufferedReader reader = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));

    private final PrintWriter writer = new PrintWriter(System.out, true, StandardCharsets.UTF_8);

    private int exitCode;

    /**
     * 重新编码 argv 的值而保留选项名，使包含空格、引号和反斜杠的路径不被二次拆分。
     *
     * @param args 操作系统参数数组
     * @return 可交给 Spring Shell 解析器的一行文本
     */
    public static String encodeArguments(String[] args) {
        StringBuilder line = new StringBuilder();
        for (int index = 0; index < args.length; index++) {
            String argument = args[index];
            if (index > 0) {
                line.append(' ');
            }
            int equals = argument.indexOf('=');
            if (argument.startsWith("-") && equals > 0) {
                line.append(argument, 0, equals + 1).append(quote(argument.substring(equals + 1)));
            } else if (index == 0 || argument.startsWith("-")) {
                line.append(argument);
            } else {
                line.append(quote(argument));
            }
        }
        return line.toString();
    }

    /**
     * Spring Shell 4 的解析器支持双引号内的引号与反斜杠转义。
     *
     * @param value 原始选项值
     * @return 双引号包围的转义值
     */
    private static String quote(String value) {
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    /**
     * 有参数执行一次；无参数循环读取，exit/quit 或 EOF 结束交互。
     *
     * @param args     操作系统已分组的命令参数
     * @param executor 由应用提供的 Spring Shell 执行桥接
     * @throws Exception 标准输入读取失败时抛出；命令失败在内部转为退出码
     */
    public void run(String[] args, Executor executor) throws Exception {
        log.info("启动命令行，参数数量={}", args.length);
        if (args.length > 0) {
            exitCode = execute(encodeArguments(args), executor);
            return;
        }
        writer.println("SCEP 命令行已启动，输入 help 查看帮助，exit 退出。");
        while (true) {
            String line = readLine("scep> ");
            if (line == null || line.trim().equalsIgnoreCase("exit") || line.trim().equalsIgnoreCase("quit")) {
                writer.println("已退出 SCEP 命令行。");
                return;
            }
            if (!line.isBlank()) {
                exitCode = execute(line, executor);
            }
        }
    }

    /**
     * 统一捕获解析、参数绑定和业务异常；脚本调用失败必须返回非零退出码。
     *
     * @param line     完整命令行
     * @param executor 框架执行器
     * @return 0 表示成功，非零表示失败
     */
    private int execute(String line, Executor executor) {
        String command = line.trim().split("\\s+", 2)[0];
        log.info("执行命令，名称={}", command);
        try {
            int code = executor.execute(line);
            if (code != EXIT_SUCCESS) {
                writer.println("命令执行失败，退出码：" + code);
                log.warn("命令执行失败，名称={}，退出码={}", command, code);
            } else {
                log.info("命令执行成功，名称={}", command);
            }
            return code;
        } catch (Exception e) {
            writer.println("错误：" + UserMessages.describe(e));
            log.error("命令执行异常，名称={}", command, e);
            return EXIT_FAILURE;
        } finally {
            writer.flush();
        }
    }

    /**
     * 向控制台输出提示并读取一行，不关闭进程共用的标准输入输出。
     *
     * @param prompt 输入提示
     * @return 输入文本，EOF 时为 null
     * @throws Exception 标准输入读取失败时抛出
     */
    public String readLine(String prompt) throws Exception {
        writer.print(prompt);
        writer.flush();
        return reader.readLine();
    }

    public PrintWriter writer() {
        return writer;
    }

    public int exitCode() {
        return exitCode;
    }

    /**
     * 仅定义调用接口，避免 common 依赖 Spring 或具体 CLI 框架。
     */
    @FunctionalInterface
    public interface Executor {
        /**
         * 执行一行命令，返回框架提供的退出码。
         */
        int execute(String line) throws Exception;
    }
}

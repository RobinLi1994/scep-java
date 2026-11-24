package com.example.scep.common.shell;

import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.env.Environment;
import org.springframework.shell.core.InputReader;
import org.springframework.shell.core.command.Command;
import org.springframework.shell.core.command.CommandContext;
import org.springframework.shell.core.command.CommandExecutor;
import org.springframework.shell.core.command.CommandOption;
import org.springframework.shell.core.command.CommandRegistry;
import org.springframework.shell.core.command.DefaultCommandParser;
import org.springframework.shell.core.command.ParsedInput;

/**
 * 用 Spring Shell 注册表、解析器和执行器接管命令；控制台负责中文错误和进程退出码。
 * <p>替换默认 runner 是为了保留 argv 中的空格，并让解析错误也能使脚本失败。</p>
 * <p>两个应用显式导入同一份配置；只使用协议工具时无需加载此类或引入 Spring。</p>
 *
 * @author robin.li
 * @date 2026-11-22 09:50:00
 */
@Configuration(proxyBeanMethods = false)
@Slf4j
public class ShellConfiguration {

    /**
     * 两端管理命令共用的开关；HTTP 服务默认关闭。
     */
    public static final String ENABLED_PROPERTY = "scep.shell.enabled";

    /**
     * 根据框架的命令元数据拒绝拼写错误、重复选项和多余位置参数。
     * Spring Shell 4 的注解绑定器只读取已知选项，额外选项需要在执行边界明确拒绝。
     */
    private static void validateOptions(ParsedInput parsed, CommandRegistry registry) {
        String name = parsed.commandName();
        if (!parsed.subCommands().isEmpty()) {
            name += " " + String.join(" ", parsed.subCommands());
        }
        Command command = registry.getCommandByName(name);
        if (command == null) {
            throw new IllegalArgumentException("未知命令，请使用 help 查看帮助");
        }
        if (parsed.arguments().size() > command.getArguments().size()) {
            throw new IllegalArgumentException("存在多余位置参数，请用 --选项名 指定参数");
        }
        Set<String> supplied = new HashSet<>();
        for (CommandOption option : parsed.options()) {
            String key = option.longName().isEmpty() ? "-" + option.shortName() : "--" + option.longName();
            if (key.equals("--help") || key.equals("-h")) {
                continue;
            }
            CommandOption declared =
                    command.getOptions().stream().filter(item -> item.isOptionEqual(key)).findFirst().orElse(null);
            if (declared == null) {
                throw new IllegalArgumentException("存在未知选项，请使用命令的 --help 查看可用选项");
            }
            if (!supplied.add(declared.longName() + ":" + declared.shortName())) {
                throw new IllegalArgumentException("同一选项不能重复提供");
            }
        }
        boolean help = parsed.options().stream()
                .anyMatch(option -> "help".equals(option.longName()) || option.shortName() == 'h');
        if (!help) {
            for (CommandOption required : command.getOptions()) {
                if (Boolean.TRUE.equals(required.required())
                        && !supplied.contains(required.longName() + ":" + required.shortName())) {
                    throw new IllegalArgumentException("缺少必填选项：--" + required.longName());
                }
            }
        }
    }

    /**
     * Spring Shell 的默认转换器不含 String→Path；显式注册，仍由框架执行参数绑定。
     */
    @Bean
    public Converter<String, Path> shellPathConverter() {
        return Path::of;
    }

    /**
     * 每个应用上下文独立保存退出状态，控制台输入输出仍与框架适配分离。
     */
    @Bean
    public CommandConsole commandConsole() {
        return new CommandConsole();
    }

    /**
     * ApplicationRunner 在容器完成装配后执行，此时所有 @Command 已注册。
     */
    @Bean
    public ApplicationRunner springShellApplicationRunner(CommandRegistry registry, CommandConsole console,
            Environment environment) {
        return arguments -> {
            // 默认关闭，避免 HTTP 服务等待标准输入；客户端和管理模式由各自入口显式开启。
            if (!environment.getProperty(ENABLED_PROPERTY, Boolean.class, false)) {
                log.debug("Shell runner 未启用");
                return;
            }
            log.info("Shell runner 已启用，参数数量={}", arguments.getSourceArgs().length);
            DefaultCommandParser parser = new DefaultCommandParser(registry);
            CommandExecutor executor = new CommandExecutor(registry);
            InputReader input = new InputReader() {
                @Override
                public String readInput(String prompt) throws Exception {
                    return console.readLine(prompt);
                }
            };
            console.run(arguments.getSourceArgs(), line -> {
                ParsedInput parsed = parser.parse(line);
                validateOptions(parsed, registry);
                return executor.execute(new CommandContext(parsed, registry, console.writer(), input)).code();
            });
        };
    }
}

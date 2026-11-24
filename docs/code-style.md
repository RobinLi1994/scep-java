# 代码规范与包职责

本次参照 [Alibaba Java 编程规范](https://github.com/alibaba/p3c) 中的命名、常量、枚举、格式、注释等规则整理现有工程；不表示已经完成手册全部条款或全部 PMD 规则的认证。

## 枚举和常量的选择

- 有有限个协议选项并参与分支判断时使用枚举：`MessageTypeEnum`、`PkiStatusEnum`、`FailInfoEnum`、`OperationEnum`、`CapabilityEnum`，位于 `common.protocol.enums`。
- `code` 明确写出标准的线上字符串；枚举顺序不构成协议约定。消息类型 3（CertRep）和状态 3（PENDING）属于不同枚举。
- OID、nonce 长度、事务标识限制、SCEP 媒体类型与查询参数放在 `common.protocol.ScepConstants`。BC 已有算法 OID 继续复用，不另建重复枚举。
- Spring 路由注解只能引用编译期常量，因此 HTTP 操作字符串也定义在 `ScepConstants`，由 `OperationEnum` 复用；客户端仍通过枚举表达操作，不维护两份字符串。
- JCA 算法名、RSA 范围、证书时钟宽限、私钥证明长度放在已有的 `Crypto` 中；本地 HTTP 超时、响应限制、CA 文件名和签发范围放在使用它们的类中。避免创建统一的杂项常量包。
- Spring HTTP 端复用 `HttpStatus`、`HttpMethod`、`MediaType`，JDK HTTP 客户端复用 `HttpURLConnection.HTTP_OK`，不把传输层状态与 SCEP 状态混在一起。
- 空集合的 0、单个值的 1、数组起始下标，以及已经写明名称的注解默认值不机械地包装成常量。独立协议测试保留固定 OID、消息码和畸形报文值，以免生产代码和测试共用错误的映射。

未知消息类型映射到 `UNKNOWN` 后，由服务层返回签名的 badRequest；不支持的 CMS 算法返回 badAlg；找不到续期证书返回 badCertId；CMS 外层签名完整性失败标记为 badMessageCheck，但在没有可信事务上下文时由 HTTP 层拒绝。未知 HTTP 操作返回 400。能力解析保留未知名称并按大小写不敏感匹配已知能力；未知失败原因保留原始码，不能按成功继续处理。`UNKNOWN` 不能作为请求或失败响应的发送参数。

## 包和依赖

| 模块 | 包 | 职责 |
|---|---|---|
| common | protocol、protocol.enums | CMS 编解码、线上值、协议失败 |
| common | crypto | 密钥、签名、PEM 文件读写 |
| common | shell | 双端共用的输入输出、中文错误、框架执行桥接 |
| client | config、shell | YAML 绑定、命令参数合并 |
| client | service | 准备 CSR/身份/密钥并保存结果 |
| client | transport | HTTP 能力发现、发送请求、验证返回证书 |
| server | config、shell | CA 资源和服务装配、可选管理命令 |
| server | ca、service | 证书生成和存储、注册/续期授权 |
| server | web | HTTP 参数、媒体类型、大小限制与中文错误 |

模块包根分别为 `com.example.scep.common/client/server`。两端都依赖 common；服务端只在测试范围依赖客户端。common 的密码和协议代码不依赖 Spring，Shell 的框架依赖保持 optional。没有增加通用父类、枚举转换框架或额外模块。

## 格式规则

类型写法、Lombok、导包、控制体、中文注释和错误提示的通用约定统一见 [AGENTS.md](../AGENTS.md#源码约定)，适用于生产代码与测试。这里维护具体的格式参数与工具用法。

- Java 使用 UTF-8、LF、4 空格，不用制表符。目标行宽 120，续行增加 8 空格。
- 字段/方法注解单独一行；导包按 JDK、第三方、项目、静态导入分组。
- 保留教学段落与行注释的人工换行，避免格式器把说明压成一行。
- 所有 POM 展开到独立元素并使用 4 空格，YAML 使用 2 空格；编辑器基础规则见根目录 `.editorconfig`。

`config/formatter/alibaba-eclipse.xml` 基于 Alibaba 仓库的官方 Eclipse 配置，保留其来源注释。本项目覆盖续行缩进（8 空格）、字段间隔、注解换行，关闭 Javadoc/行注释的重新排版，表达式换行仍交由格式器统一决定。规则由 `net.revelc.code.formatter:formatter-maven-plugin:2.29.0` 执行，支持当前 Java 17。

在项目根目录执行：

```bash
mvn formatter:format
mvn formatter:validate
mvn verify
```

本项目关闭格式缓存，确保规则变更和重复格式化都实际检查源文件。`verify` 在 validate 阶段执行格式检查，发现格式不一致直接失败，不静默修改源码。`.mvn` 目录用于定位多模块根目录，从子模块运行时也能找到同一份格式配置。IDEA 的明确导包阈值及空的强制通配符包列表参考 [JetBrains 自身工程配置](https://github.com/JetBrains/intellij-community/blob/master/.editorconfig)，已写入 `.editorconfig`。IDE 保存时遵循 `.editorconfig`；若 IDE 格式器与 Maven 不一致，以此处的 Maven 命令为准。

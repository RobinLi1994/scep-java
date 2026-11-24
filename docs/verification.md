# 验证记录：SCEP HTTP 入口与失败原因映射

日期：2026-11-23（Asia/Shanghai）。当前实现已删除单 DES 开关；[历史验证记录](history/verification-20261120-21.md) 只描述旧版行为，不作为当前运行说明。

## 当前构建

实际执行：

```bash
mvn -s /private/tmp/scep-maven-settings.xml -B -ntp formatter:format verify
```

2026-11-23 17:53:08 完成本次最终构建，退出码 0，所有模块 BUILD SUCCESS。本次保留同一 Controller 的四种 HTTP 请求拆分，并修正 SCEP `failInfo` 映射，同时严格校验响应 nonce 和 FAILURE/PENDING 内容结构：不支持算法为 `badAlg=0`，CMS 完整性异常保留 `badMessageCheck=1`，找不到续期证书为 `badCertId=4`，CSR/授权策略继续为 `badRequest=2`。临时 Maven 设置仅将缓存放到 `/private/tmp/scep-m2` 并使用 Maven Central，没有修改用户 Maven 设置；正常环境直接执行 `mvn formatter:format verify`。此前分包阶段已执行 clean verify 清除旧路径产物。

Java 17、Spring Boot 4.0.10、Spring Shell 4.0.4、Bouncy Castle 1.87、Lombok 1.18.48。

| 测试类 | 数量 | 覆盖 |
|---|---:|---|
| ClientShellTest | 11 | 注册/续期选项分离、旧别名移除、引号与空格、未知/重复/缺失参数及多余位置参数、失败退出码 |
| ClientConfigurationTest | 8 | 实际 YAML 绑定、CLI 覆盖、续期配置隔离、缺失旧身份拒绝、缺失口令时不写私钥 |
| ScepServiceTest | 21 | 真实注册、续期、CSR/CMS 校验、授权、SAN、文件持久化及永久拒绝单 DES |
| ScepHttpTest | 31 | 真实 HTTP、四种路由、缺失/重复/未知参数、Base64 前后大小边界、签名失败仍为 200、固定/chunked 长度、旧 MIME 和中文错误 |
| ProtocolRegressionTest | 18 | 响应省略 CA、双向 nonce、新鲜 senderNonce、请求身份必需、信封/证书包结构；线上枚举编码、未知消息、未知失败原因、FAILURE/PENDING 内容结构与未知状态拒绝 |
| CaShellTest | 3 | 无已有 CA 的管理启动、Path 转换、带空格参数初始化、共享 runner 拒绝错误选项且不创建文件 |
| ClientCapabilitiesTest | 9 | GetCACaps 顺序、CRLF/LF、大小写、未知能力、旧 MIME、SCEPStandard、POST/GET、算法及 Renewal 门槛 |
| ClasspathCaTest | 1 | 无文件系统 CA 时启动，读取默认 classpath CA 并完成真实 HTTP 注册 |
| CaResourceValidationTest | 4 | 无文件路径的资源流、缺失资源、损坏 PEM 和证书私钥不匹配 |
| ClientValueObjectsTest | 3 | 能力集合快照、申请参数值比较、配置诊断输出排除口令 |
| ProtocolValueObjectsTest | 2 | 请求数组输入/输出隔离、消息数组引用比较 |
| **合计** | **111** | **0 failures、0 errors、0 skipped** |

客户端 22 项，服务端 89 项。密码测试使用真实 RSA、CMS、CSR，HTTP 测试启动真实本地服务器，不以 mock 替代密码过程。

## 本次响应结构回归

`readResponse` 现在强制读取响应自身的 `senderNonce`，检查它是 16 字节且不复用请求 nonce；`recipientNonce` 仍必须与请求 `senderNonce` 完全匹配。验签结果保留 `contentPresent`，因此 FAILURE/PENDING 只能在缺少外层 `eContent` 时成立，SUCCESS 必须包含非空 `pkcsPKIEnvelope`。`ProtocolRegressionTest` 新增 3 项参数化/边界回归，覆盖缺失、截断、复用 nonce 以及带空正文的 FAILURE/PENDING。

## 本次 HTTP 入口回归

先在旧 Controller 上运行新增的 25 个用例，连同原有 6 项共 31 项通过，再执行入口拆分。拆分后全量 108 项通过。基线日志为 `target/verification/controller-baseline.log`，当前构建日志为 `controller-verify.log`。

四个具体映射保留同一个 `/scep` 路径，GET/POST 的消息读取分别处理，再进入 `processPkiMessage`。兜底映射保留缺失/未知操作的中文错误；所有入口都拒绝重复 operation，避免 Spring 参数匹配后遗漏唯一性检查。测试覆盖重复值的不同顺序、错误 POST 操作、空消息、无效 Base64、解码前后大小限制及可验签的 CertRep FAILURE。

本次实际 JAR 运行 `SCEP_INTEROP_PORT=18186 bash scripts/interop-go.sh /private/tmp/scep-go-aes-client`：Java 注册/换钥续期、AES 适配版 Go 注册/续期及错误口令拒绝全部通过；OpenSSL 对四张证书验签均为 OK。脚本创建的服务已停止，详情保存为 `target/verification/nonce-interop.log` 和 `nonce-interop-details/`。Shell 与 YAML 的专项进程脚本本次未重复执行；下面对应记录属于此前验证。

42 个 Java 文件的类型语法、显式导包形式与控制体检查通过，日志为 `failinfo-style.log`。中文学习文档同步补充四种请求的方法对应关系、重复参数检查原因及 HTTP 错误与签名协议失败的区别。

## 本次失败原因映射回归

`ScepProtocolException` 在 common 模块保留解析阶段的 RFC 原因，服务端只有在外层 CMS 已验签、拥有可信事务上下文时才将其编码成签名的 CertRep FAILURE。单 DES 及不支持的摘要/公钥算法使用 `badAlg=0`；外层 CMS 签名验证失败标记 `badMessageCheck=1`，但不继续伪造回复；CSR 格式、CSR PoP、challenge、SAN 和续期授权等交易策略拒绝使用 `badRequest=2`；本 CA 找不到续期证书使用 `badCertId=4`。这样既符合 RFC 8894 §3.2.1.4，也避免把不可信的请求属性用于构造响应。

`ScepServiceTest` 覆盖单 DES、篡改 CMS 签名和缺失续期记录三个关键码；原有错误口令、损坏 CSR、SAN 和未知消息类型用例继续断言 `badRequest=2`。相关 RFC 原文见 [RFC 8894 §3.2.1.4](https://www.rfc-editor.org/rfc/rfc8894.html#section-3.2.1.4)。

## 此前问题的复现与修复

ProtocolRegressionTest 在旧代码上首次运行：9 项中 5 个断言失败、1 个错误，分别复现错误信封/证书包被接受与省略 CA 的合法响应被拒绝。ClientCapabilitiesTest 在旧代码上首次运行：9 项均失败，证实客户端没有先查询能力。修复后通过，并增加无 CA 的签名失败响应回归。

HTTP 中文测试先观察到默认 404 JSON 的英文 `Not Found`，再加入全局处理器修复。实际 Shell CA 初始化也先复现 Spring Shell 缺少 String→Path 转换器，补上框架转换器后通过测试与真实 JAR 验证。

本次精简先更新 ClientShellTest 的命令契约，观察到旧 `client` 别名仍存在、`enroll` 仍接受续期选项的 2 项失败；收敛入口后全部通过。服务端增加未知/重复选项的 runner 回归，确认拒绝发生在 CA 文件写入之前。原有响应省略 CA、错误签名者、篡改响应及事务绑定测试继续通过，移除重复证书编码比较没有删去实际验签或信任检查。

## 此前 Shell、资源及 JAR 验证

此前模块、YAML 和格式调整阶段验证过双端 Shell、客户端 YAML 注入、JAR 默认 CA 资源加载与外部 CA 的 Go 互通（本次 HTTP 拆分的实际 JAR 验证见上节）：

```bash
bash scripts/smoke-shell.sh
SCEP_RESOURCE_TEST_PORT=18183 bash scripts/smoke-classpath-ca.sh
SCEP_INTEROP_PORT=18182 bash scripts/interop-go.sh /private/tmp/scep-go-aes-client
```

Shell 验证覆盖：双端帮助；未知命令、未知选项、缺少值/必填项、重复项、非法数字、参数范围、缺失文件的中文错误与非零退出码；带空格路径和主题；CA 防覆盖；客户端与服务端交互会话；交互失败后继续执行 help。

新增实际进程检查：旧 `client`、`enroll --renew-from`、`enroll --signing-key` 被拒绝；服务端也拒绝未知/重复选项。Java 换钥续期已通过 `renew` 入口完成。

互通验证覆盖：Java 初始注册、旧身份换新密钥续期；Go 初始注册、续期及序列号变化；错误 challenge 被拒绝；OpenSSL 对四张 Java/Go 证书验签均为 OK。临时服务只监听本机，脚本结束后已停止。

Go 来源固定提交 `9902c1a3549891d080e9b4d476e37fb2f8ae22ff`。使用 `build-go-aes-client.sh` 在临时导出目录增加初始化代码，设置 `pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES128CBC`；构建使用的 go.mod 变更也仅在临时目录。本结果对应 **AES 适配版 Go 客户端**，不能称为未修改的原始客户端。Java 没有开启单 DES。

## 此前源码检查与当前交付产物

- 42 个 Java 源文件（含测试）中 `var` 和 `record` 为 0；双端共用 common 中一份 ShellConfiguration。
- JDK 编译器 AST 检查：无省略大括号的控制体，无含语句的紧凑代码块。
- 使用 Lombok 自带 delombok 展开到 `target/delombok-style-final`，再以 `-Xdoclint:all,-missing` 生成 `target/apidocs-style`，无错误。
- 逐个检查可执行 JAR 的依赖：服务端不含客户端运行包；客户端不含服务端运行包或 Tomcat；两者都包含 common。
- 两个应用 JAR 中均不存在旧 ShellConfiguration；配置仅存在于 common JAR，Spring 依赖标记为 optional。
- 使用仅包含 common 和 Bouncy Castle 的 classpath 独立生成、解析及验签请求，确认协议工具运行无需 Spring。
- 文档本地链接有效，四个脚本通过 bash 语法检查。
- `target/scep-java-source.zip` 按当前模块结构重新生成，逐字节核对所有打包文件与工作目录一致，包含明确标识的教学 CA 证书与私钥，不包含用户 CA、运行期证书、用户配置或构建缓存。
- `target/verification/SHA256SUMS` 保存当前 JAR 与源码包的校验值；`source-manifest.json` 保存源码摘要。

格式与分包阶段日志保存为 `target/verification/style-*.log`，包括当时的构建、无缓存格式验证、子模块格式验证、Javadoc、源码风格、独立协议调用及实际 Shell/资源/互通验证。本次 HTTP 拆分日志使用 `controller-*.log`，源码包、源码清单与 SHA-256 按本次工作目录重新生成；此前各阶段证据继续保留。

## 验证边界

当前是单 CA、同步注册/续期学习实现。未验证所有设备客户端，不支持独立 RA、多 CA 链、PENDING 轮询、吊销、HSM 或集群状态。客户端主动要求 AES/SHA-256，不自动降级到只支持旧算法的服务。

应用错误已提供中文；第三方 cause 与框架诊断日志保留原始内容供调试。HTTP 层错误与签名 CertRep FAILURE 的语义保持区分。

## CA 资源加载验证

先在旧加载逻辑上运行 ClasspathCaTest，复现空 depot 缺少 ca.pem 导致启动失败；改为读取 Spring Resource 输入流后通过。本次不改协议处理，仅把静态 CA 材料来源与可写的 issued 记录目录分离。

内置 CA 位于 `scep-server/src/main/resources/ca/`，证书主题包含 DEMO ONLY，专为学习工程生成；这份私钥随源码公开。默认配置无需执行 ca-init。已有外部 CA 可通过 SCEP_CA_CERTIFICATE、SCEP_CA_PRIVATE_KEY 的 file: 位置加载，互通脚本已验证这一分支。

`smoke-classpath-ca.sh` 从空工作目录运行实际可执行 JAR，不调用 ca-init。它核对 GetCACert 与资源证书一致、完成注册及 OpenSSL 验签、确认只在外部目录写入 issued 记录。对应日志保存在 `target/verification/resource-jar.log`。

## 全局导包整理复核

2026-11-22 16:47:21 执行 `mvn -s /private/tmp/scep-maven-settings.xml -B -ntp verify` 完成，客户端 12 项、服务端 54 项测试全部通过，两个可执行 JAR 已重新生成。

检查全部 30 个 Java 源文件，整理其中 25 个：23 处正文全限定类名改为 import 加简单类名，通配符导包展开为明确的类或静态方法导包，Javadoc 类链接同步使用导入。通过 JDK 编译器符号分析确认正文无遗留全限定类名，导包无重复或未使用项；无 var，控制体大括号和 Javadoc 校验通过。包名配置字符串保持原义。

本次仅调整导包和类名引用，没有新增测试或修改协议行为；未重复运行 Go 互通及实际 JAR 冒烟脚本，相关结果仍为上一节 Shell 精简后的验证记录。本次日志见 `target/verification/imports-verify.log` 与 `imports-javadoc.log`，源码包及 SHA-256 已更新。

## 客户端 YAML 注入验证

新增 ScepClientProperties，绑定 scep.client 下的服务地址、可信 CA、主题、注册/续期文件路径和注册口令。命令行显式参数优先于 YAML；续期使用独立的 renew-key/renew-out 默认值，且不依赖注册口令。业务工作流通过方法参数接收 challenge，不再调用 System.getenv。

ClientConfigurationTest 直接加载测试 YAML，经过真实 Spring Shell runner 验证注册/续期默认值、完整或部分 CLI 覆盖，以及配置对象不被覆盖操作修改。仅替换最终文件工作流以隔离 I/O；密码与协议测试仍使用真实 RSA、CMS 和 HTTP。另验证缺失旧身份不能回退到初始注册，缺失或空白口令在生成私钥前被拒绝。

实际执行 smoke-classpath-ca.sh：从空目录启动服务端，用外部 client.yml 配置客户端全部材料并取消其 SCEP_CHALLENGE 环境变量，直接运行裸 enroll 和 renew。注册证书主题匹配 YAML，换钥续期生成独立私钥与新序列号，两张证书均通过 OpenSSL 验签。smoke-shell.sh 和 AES 适配版 Go 互通也重新通过，环境变量口令占位符及显式命令选项继续兼容。

当前日志为 target/verification/client-yaml-verify.log、client-yaml-shell.log、client-yaml-resource.log、client-yaml-interop.log、client-yaml-javadoc.log。新源码包与摘要同步更新，未打包测试运行时产生的口令配置、私钥或证书。历史小节中的构建时间和数量保留为对应阶段记录。

## 普通类与 Lombok 验证

7 处数据类型已改为普通类，包括两端配置、EnrollmentOptions、CaCapabilities 和 ScepCodec 内部的 Request/Message/Verified。采用 Lombok @Value 简化只读访问和构造；@Accessors 保留公开访问方法名。包含校验的构造器及 Request 数组复制方法仍显式实现；公开协议对象的数组仍按引用比较，未改成 Lombok 默认的内容深比较。ClientCommands 使用 @RequiredArgsConstructor 注入配置。

根 POM 声明 provided、optional 的 Lombok 依赖及 annotationProcessorPaths，版本继承 Spring Boot。实际检查两个可执行 JAR 均不含 Lombok，客户端仍不含服务端或 Tomcat，服务端不含客户端运行依赖。两个配置对象的自动 toString 排除 challenge，客户端测试确认口令没有进入诊断输出。

78 项测试全部通过；实际执行双端 Shell、外部 YAML 注册/换钥续期及 AES 适配版 Go 注册/续期/错误口令拒绝，均通过。JDK AST 检查源码中的控制语句格式；源文件中 record、var、通配符导包均为 0。delombok 后的 Javadoc 校验通过，展开源码仅作为 target 下的学习/验证产物，不替代维护中的源码。

本次日志位于 target/verification/lombok-verify.log、lombok-shell.log、lombok-resource.log、lombok-interop.log、lombok-javadoc.log。源码压缩包与 SHA-256 已更新。未测试 Java/Go 以外的设备客户端。

## 协议枚举、分包与格式验证

生产源码按 common/client/server 独立包根组织：公共协议与密码工具、客户端配置/命令/申请流程/HTTP、服务端配置/命令/CA/授权/HTTP 分包。两个应用的组件扫描、Maven mainClass、测试引用和文档链接已同步更新；入口类不再承担 CA Bean 的装配。

消息类型、响应状态、失败原因、HTTP 操作、能力名称使用独立枚举；OID、nonce/事务限制、媒体类型、算法、密钥范围、证书时钟宽限、HTTP 超时/大小限制等按所属职责命名。HTTP 状态复用现有框架/JDK 常量。独立报文测试保留标准的字面值，避免生产映射和测试同时出错。

新增 5 个回归用例，证明：PKCSReq/CertRep/SUCCESS 的线上值不变；签名有效的未知消息类型仍返回已签名 badRequest；未知 failInfo 原值保留；PENDING 与未知状态均被拒绝。原有注册、换钥续期、输入校验和信任边界测试全部通过。

格式基于 Alibaba 的 Eclipse 配置，补充项目的续行和中文注释保留规则。初次验证发现保留已有表达式换行会造成二次排版变化，已恢复表达式的统一换行策略，并在不读取缓存的条件下验证。Maven 关闭格式缓存，validate 阶段强制检查 Java 生产与测试源码；从客户端子目录执行格式检查也通过。POM 与 `.editorconfig` 同步规范，IDEA 设置禁止自动合并通配符导包。

保留已有 Lombok 日志注解和教学注释，最终明确导包、控制块 AST、Javadoc、脚本语法及本地文档链接检查通过。源码包同步包含格式规则、来源许可证、编辑器配置和分包说明；具体准则见 [代码规范](code-style.md)。未执行阿里巴巴手册的全部静态规则，也未扩展协议功能。

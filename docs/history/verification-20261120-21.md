> 历史验证快照，包含已经移除的单 DES 兼容模式；不能用于当前版本启动。最新记录见 [verification.md](../verification.md)。

# 验证记录

日期：2026-11-20（Asia/Shanghai）。

## 环境

- Java：Temurin OpenJDK 17.0.13
- Maven：3.9.0
- Go：1.25.1
- OpenSSL：3.6.2
- Spring Boot：4.0.10；Bouncy Castle：1.87
- 参考项目提交：`9902c1a3549891d080e9b4d476e37fb2f8ae22ff`

构建时使用 `/private/tmp/scep-maven-settings.xml`，将依赖缓存隔离到 `/private/tmp/scep-m2`，从 Maven Central 下载，未修改用户 Maven 设置。普通环境可直接执行 `mvn clean verify`。

## 自动测试

26 项测试通过，0 failures、0 errors、0 skipped。`mvn verify` 成功生成可执行 JAR。

`ScepServiceTest` 21 项，验证真实加密、验签和证书签发：

- 注册后的公钥、subject、终端权限、clientAuth、文件持久化和重新加载。
- challenge 错误、外层签名篡改、CSR 私钥证明损坏、签名证书与 CSR 公钥不匹配。
- 旧证书换钥续期、到期窗口、subject 修改与 RDN 重排拒绝、自签证书不能续期。
- 响应固定 CA、transactionID、nonce 校验，标准无 eContent 的签名失败响应。
- SAN 默认拒绝、显式开启后保留 SAN，续期不能新增/删除/修改 SAN。
- CSR 请求 CA 权限仍只能获得终端权限，DES 默认拒绝且显式开启后可用。
- CA 不覆盖已有材料、初始化目标符号链接保护、存储记录缺失与损坏的区别。
- 解密错误与明文/授权错误对外返回相同 failInfo。
- 兼容原 Go 客户端的初始签名 subject，同时保留公钥和 challenge 约束。

`ScepHttpTest` 5 项，通过随机端口启动真实 Spring Boot 服务：

- GetCACaps、GetCACert 内容与 MIME。
- URL 编码 Base64 GET 与二进制 POST 注册。
- 缺少/重复参数、不支持的操作、错误 Base64/CMS、错误 MIME、超大固定长度与 chunked 请求。
- Java 客户端真实 HTTP 注册，以及错误的固定 CA 拒绝。
- 兼容 application/octet-stream 及省略 Content-Type 的旧客户端 POST。

## 独立审查与回归

独立只读审查发现 5 个问题。先加入测试，观察 5 项失败，再修复并确认全套通过：

1. 外部 failInfo 不再区分解密和明文错误。
2. 使用保留 RDN 顺序的 X500Principal 比较身份。
3. FAILURE 省略 eContent，客户端仍验证空内容的签名和 messageDigest。
4. 私钥使用单一 CREATE_NEW 文件通道以 0600 创建，CA 材料先暂存，普通失败回滚。
5. 已签发证书存储损坏向上传播为服务错误，缺失记录仍拒绝续期。

首次真实 Go 互通进一步发现原客户端使用 `application/octet-stream` 以及固定的初始 `SCEP SIGNER` subject。分别增加失败回归用例后修复，最终全套 26 项通过。续期的严格身份约束保持不变。

## 实际 JAR 与原 Go 客户端互通

执行：

```bash
mvn -s /private/tmp/scep-maven-settings.xml -B -ntp verify
bash scripts/interop-go.sh /private/tmp/scep-go-client
```

2026-11-20 21:42（Asia/Shanghai）完成，构建和互通脚本退出码均为 0。

| 验证 | 实际结果 |
|---|---|
| JAR `ca-init` | 创建临时 RSA CA |
| JAR Java 客户端初始注册 | 成功 |
| JAR Java 客户端使用旧身份、换新密钥续期 | 成功 |
| 未修改的 Go 互通验证客户端初始注册 | `pkiStatus=SUCCESS` |
| 同一 Go 客户端续期 | `pkiStatus=SUCCESS`，序列号变化 |
| Go 客户端错误 challenge | HTTP 成功传输签名失败响应，客户端报告 `failInfo: badRequest (2)` |
| OpenSSL 验证 Java/Go 初始及续期证书 | 4 张均为 `OK` |
| 服务清理 | Spring Boot graceful shutdown 完成 |

测试配置仅监听本机，启用 `SCEP_ALLOW_LEGACY_DES=true` 和 `SCEP_RENEWAL_DAYS=0`。未修改原 Go 源码来适配 Java。未验证 Java 客户端对所有外部 CA 的兼容性。

交付目录 `target/verification/` 保存构建、互通和 Go 客户端的文本日志；源码包不包含测试私钥、CA 材料或任何用户凭据。

## 验证边界

本记录仅对应列出的实现与测试环境，不表示通过所有 SCEP 设备的兼容性认证。独立 RA、多 CA 链、HSM、吊销、集群、设备身份平台不在本次工程范围内。只有开启兼容配置的 Go 互通测试接受单 DES；默认配置关闭该算法。

## 学习注释补充验证

2026-11-20 22:00（Asia/Shanghai）再次运行 `mvn verify`，26 项测试全部通过。中文 Javadoc 已通过 JDK doclint 检查并生成 `target/apidocs/`。本次注释补充及保留的并行编辑详情见 [注释补充记录](../annotation-summary.md)。本轮未重跑 Go 互通，上述互通结果仍对应首次实现验证。

## 显式类型调整验证

2026-11-20 22:08（Asia/Shanghai）将 10 个 Java 文件中的 159 处局部类型推断替换为编译器确认的显式类型，保留现有注释。主代码和测试源码已无 `var`。再次运行 `mvn verify`，26 项测试全部通过；Javadoc doclint 检查通过，重新生成可执行 JAR、API 文档与源码包。本轮未重跑 Go 互通。

## 当前工作目录显式类型复查

2026-11-21 13:07（Asia/Shanghai）复查发现当前 `ScepCodec.java` 有 23 处 `var`，而此前源码包内没有这些声明；导致二者差异的操作未确认。本轮直接修改当前工作目录，仅将这 23 处声明改为显式类型，保留注释和逻辑。全工程 15 个 Java 文件扫描结果为 0 处 `var`；重新运行 `mvn verify`，26 项测试全部通过；Javadoc doclint 检查通过。同步更新 JAR、API 文档和源码包，并逐字节核对源码包中的 Java 文件与工作目录一致。本轮未重跑 Go 互通。

## 控制语句排版与行内注释验证

2026-11-21 16:00（Asia/Shanghai）完成 13 个 Java 文件的可读性整理：57 处条件/循环补齐大括号，展开紧凑代码块，净增 125 行 `//` 注释。JDK AST 检查全部 15 个 Java 文件，未发现省略大括号的控制体或紧凑非空代码块，`var` 数量为 0。词法对比确认除注释、空白和大括号外的代码 token 未改变，已有作者和日期全部保留。重新运行 `mvn verify`，26 项测试全部通过；Javadoc doclint 无错误。更新源码包并逐字节核对其中的 Java 文件与工作目录一致；构建和检查日志位于 `target/verification/readable-*`。本轮未重跑 Go 互通。

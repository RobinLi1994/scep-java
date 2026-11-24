> 以下为历史注释统计；源码链接已更新到三模块结构。最新实现与验证见 [验证记录](verification.md)。

# 注释补充记录

本次按 Java 开发者学习 SCEP 的目标补充中文注释。新增日期使用 Asia/Shanghai 的 `2026-11-20 21:52:59`，保留已有作者和日期信息；没有修改版权年份。

| 文件 | 新增类型注释 | 扩充已有类注释 | 新增方法/构造器注释 | 补充类日期 | 版权更新 |
|---|---:|---:|---:|---:|---:|
| [ScepApplication.java](../scep-server/src/main/java/com/example/scep/server/ScepApplication.java) | 1 | 0 | 3 | 1 | 0 |
| [ScepProperties.java](../scep-server/src/main/java/com/example/scep/server/config/ScepProperties.java) | 1 | 0 | 1 | 1 | 0 |
| [client/EnrollmentService.java（原 CommandLine）](../scep-client/src/main/java/com/example/scep/client/service/EnrollmentService.java) | 0 | 1 | 4 | 1 | 0 |
| [client/ScepClient.java](../scep-client/src/main/java/com/example/scep/client/transport/ScepClient.java) | 0 | 1 | 4 | 1 | 0 |
| [crypto/CertificateAuthority.java](../scep-server/src/main/java/com/example/scep/server/ca/CertificateAuthority.java) | 0 | 1 | 4 | 1 | 0 |
| [crypto/Crypto.java](../scep-common/src/main/java/com/example/scep/common/crypto/Crypto.java) | 0 | 1 | 6 | 1 | 0 |
| [crypto/PemFiles.java](../scep-common/src/main/java/com/example/scep/common/crypto/PemFiles.java) | 0 | 1 | 5 | 1 | 0 |
| [protocol/ScepCodec.java](../scep-common/src/main/java/com/example/scep/common/protocol/ScepCodec.java) | 3 | 1 | 19 | 4 | 0 |
| [protocol/ScepFailureException.java](../scep-common/src/main/java/com/example/scep/common/protocol/ScepFailureException.java) | 0 | 1 | 1 | 1 | 0 |
| [service/ScepService.java](../scep-server/src/main/java/com/example/scep/server/service/ScepService.java) | 0 | 1 | 9 | 1 | 0 |
| [web/ScepController.java](../scep-server/src/main/java/com/example/scep/server/web/ScepController.java) | 0 | 1 | 4 | 1 | 0 |
| [test/ProtocolFixtures.java](../scep-server/src/test/java/com/example/scep/server/ProtocolFixtures.java) | 0 | 1 | 4 | 1 | 0 |
| [test/ScepHttpTest.java](../scep-server/src/test/java/com/example/scep/server/ScepHttpTest.java) | 1 | 0 | 8 | 1 | 0 |
| [test/ScepServiceTest.java](../scep-server/src/test/java/com/example/scep/server/ScepServiceTest.java) | 1 | 0 | 26 | 1 | 0 |

另外新增根包 `package-info.java` 阅读导航，并扩充已有的 `CertificateAuthority.issue` 方法注释。纯 getter、Override 和空工具类私有构造器未添加重复说明。

## 学习内容

- SCEP 请求/成功响应/失败响应的 CMS 层次。
- OID、ASN.1 类型、operation/messageType/pkiStatus 的区别。
- 外层签名、CSR 私钥证明和业务授权分别验证什么。
- 初始自签身份、challenge，以及续期时新旧密钥的不同角色。
- DN/RDN、SAN、KeyUsage/EKU、CA/终端权限和有效期策略。
- HTTP 编码、MIME、大小限制与 Go 客户端兼容点。
- 每个测试验证的具体场景和可单步调试的路径。

## 验证

- `mvn verify`：26 项测试通过，0 失败、0 错误、0 跳过，可执行 JAR 已更新。
- JDK Javadoc：包含私有成员及测试类，启用 doclint（关闭缺失注释提示），注册自定义 `@date` 标签；退出码 0，无警告/错误输出。HTML 位于 `target/apidocs/index.html`。
- 使用 JDK 编译器 AST 比较 14 个已有 Java 文件的类型声明与方法体，排除注释和格式影响；仅保留了同时发生的两个 Bean 方法 `public` 修饰符调整，其余一致。导入整理也按当前文件保留。
- 本轮未重新执行 Go 互通；上轮互通结果见 verification.md，本次通过 AST 对比及原有测试验证注释编辑。

## 2026-11-21：分行控制语句和行内注释

本轮修改 13 个 Java 文件，将 57 处没有大括号的条件或循环体展开为分行代码块，并展开紧凑的 try/catch、辅助方法和 switch 分支。主代码与测试均使用显式类型。

在原有 Javadoc 基础上，净增 125 行方法内及相关字段旁的 `//` 注释，重点解释数据层次、密钥归属、校验原因与失败处理。本轮新增类 Javadoc、方法 Javadoc、日期标签和版权更新均为 0；已有作者和日期全部保留。

| 文件 | 净增 `//` 注释行 | 本轮重点 |
|---|---:|---|
| ScepApplication.java | 2 | CLI 与服务端的启动边界 |
| ScepProperties.java | 0 | 条件语句展开 |
| client/EnrollmentService.java（原 CommandLine） | 8 | 新旧密钥、CSR 口令、续期身份、本地密钥匹配检查 |
| client/ScepClient.java | 10 | 固定 CA 信任、POST 二进制、响应校验和读取上限 |
| crypto/CertificateAuthority.java | 12 | 根 CA、用途位、证书扩展、有效期、记录匹配与签发 |
| crypto/Crypto.java | 7 | Provider、随机性、RSA、序列号与临时自签身份 |
| crypto/PemFiles.java | 4 | PEM 私钥格式、创建权限和拒绝覆盖 |
| protocol/ScepCodec.java | 47 | CMS 封装、签名属性、信封接收者、nonce、CertRep 和客户端验收 |
| service/ScepService.java | 20 | 两层验签、challenge、SAN、续期授权与错误分层 |
| web/ScepController.java | 10 | HTTP 操作、GET/POST 编码、大小限制与状态含义 |
| test/ProtocolFixtures.java | 0 | 空构造器分行 |
| test/ScepHttpTest.java | 0 | 条件、异常分支和辅助方法分行 |
| test/ScepServiceTest.java | 5 | 终端权限、失败不落盘、换钥续期的断点观察位置 |

验证：JDK 编译器 AST 检查全部 15 个 Java 文件，未发现省略大括号的条件/循环或含语句的紧凑代码块；词法对比确认除大括号、空白和注释外的代码 token 未变；`var` 扫描为 0。`mvn verify` 的 26 项测试及 Javadoc doclint 均通过。未重跑 Go 互通。

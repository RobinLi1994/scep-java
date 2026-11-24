> 历史设计/计划：当前模块、命令和算法策略以 [README](../../../README.md) 与 [模块设计](../../modules-and-shell.md) 为准。

# Java SCEP 实现设计

本设计使用 Java 与 Spring Boot 实现 SCEP 服务端和客户端。

## 方案与范围

采用 Java 17、Spring Boot、Maven、Bouncy Castle；协议核心独立于 HTTP，便于嵌入其他 Java 服务。相较纯 JDK HTTP 服务，Spring Boot 方案便于接入现有业务；相较依赖第三方完整 SCEP 框架，直接使用 BC 可明确控制协议属性、验签和签发策略。

协议依据 RFC 8894，使用 Bouncy Castle 实现密码消息处理。互通验证客户端的固定提交为 `9902c1a3549891d080e9b4d476e37fb2f8ae22ff`。

提供 `/scep` 的 GetCACaps、GetCACert、GET/POST PKIOperation；支持 PKCSReq(19)、RenewalReq(17)、成功与失败 CertRep(3)。支持 RSA、SHA-256、AES-128-CBC，并接收 DES3、SHA-1。参考客户端实际默认使用单 DES，通过显式兼容开关支持，默认关闭。只公布实际支持的能力。

提供显式 CA 初始化、加载 PEM CA、签发 clientAuth 证书、证书文件保存、CLI 注册与续期。Java 客户端使用本地可信 CA 验证服务端，不直接信任 HTTP 下载的 CA。

## 模块

- `crypto`：PEM、RSA、CA 初始化、证书签名。
- `protocol`：SCEP OID、CMS 验签、解密、请求与响应封装。
- `service`：challenge、续期身份约束、证书签发、持久化。
- `web`：Spring MVC 协议端点及输入限制。
- `client`：请求生成、响应验证、命令行调用。

## 签发约束

注册须使用配置的 challenge；CSR 必须持有私钥且 RSA 不少于 2048 位。初始请求签名证书与 CSR 使用同一 key；RFC 8894 对初始 subject 相同仅作 SHOULD 要求，因此允许初始自签身份名称不同。续期由当前 CA 签发且有效、已保存的旧证书授权，subject 和 SAN 不得扩权，允许换钥。缺省只允许到期前 14 天续期。

证书固定为终端证书，只允许 clientAuth；CSR 的 CA/KeyUsage 等扩展不得直接继承。SAN 默认不签发，可显式开启；开启时续期必须保持 SAN。CA 私钥权限在 POSIX 下为 0600，CA 初始化不得覆盖现有材料。CA 缺失或 challenge 未配置则启动失败。

## 边界

这是可运行、可扩展的单节点基础工程；不提供 HSM、集群事务、吊销/CRL/OCSP、人工审批/PENDING、GetCert、GetNextCACert、RA/多 CA 链和设备清单授权。静态 challenge 与内置文件 CA 用于集成验证，生产授权需替换接口。CA 与 SCEP 使用同一密钥，部署边界在 README 说明。

## 验收

JUnit 验证真实 CMS/CSR、成功注册、错误 challenge、被篡改签名、nonce/transaction 绑定、续期限制、CA 持久化和 HTTP 协议。打包可执行 JAR，完成 Java CLI 注册/续期及原 Go 客户端互通，记录实际执行结果。

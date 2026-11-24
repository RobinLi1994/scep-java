# 教学 CA 文件

- `ca.pem`：CA 证书，客户端可用它建立预配信任。
- `ca.key`：与证书匹配的未加密 PKCS#8 RSA 私钥，仅供服务端签发及解密。

这是一组专门为本学习工程生成的演示材料，证书主题含 `DEMO ONLY`。私钥随源码和 JAR 公开，因此只能用于本地学习，不能作为真实设备环境的信任根。

默认从 `classpath:ca/ca.pem` 与 `classpath:ca/ca.key` 加载，无需执行 `ca-init`。如使用自己的 CA，替换这两个匹配的 PEM 文件后重新构建；也可通过 `SCEP_CA_CERTIFICATE=file:/.../ca.pem` 和 `SCEP_CA_PRIVATE_KEY=file:/.../ca.key` 指定外部文件。替换 CA 后，客户端也必须更新可信 CA 证书。

签发记录在 `SCEP_DEPOT/issued` 中，运行时不会写入此目录。已有 CA 文件会检查有效期、RSA 长度、CA 用途及证书和私钥的匹配关系。

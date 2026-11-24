# SCEP Java

基于 Java 17、Spring Boot 和 Spring Shell 的 SCEP（Simple Certificate Enrollment Protocol）学习与集成工程。
项目提供可独立运行的 SCEP 服务端、命令行客户端和协议公共库，覆盖证书注册、续期、CMS 报文处理以及基于文件的 CA 签发流程。

## 功能

- 支持 `GetCACaps`、`GetCACert` 和 `PKIOperation`
- 支持 `PKCSReq` 初始注册和 `RenewalReq` 证书续期
- 使用 RSA、CMS、CSR 和真实证书完成签名、验签、加密和解密
- 支持 HTTP GET/POST、Base64 编码和标准 SCEP `CertRep` 响应
- 提供 `enroll`、`renew` 和 `ca-init` 命令
- 支持从 classpath 或外部文件加载 CA 证书和私钥
- 协议代码位于独立公共模块，可以脱离 Spring 使用

项目适合学习 SCEP 协议、调试客户端与服务端交互，以及作为 Java 集成的起点。内置 CA 和私钥仅用于本地演示，生产环境必须替换为自行管理的 CA 材料，并配置访问控制与 TLS。

## 项目结构

| 模块 | 说明 |
| --- | --- |
| `scep-common` | SCEP/CMS 编解码、密码工具、协议枚举和共享 Shell 适配 |
| `scep-client` | 能力发现、注册、续期和命令行客户端 |
| `scep-server` | HTTP 服务、证书签发、CA 管理和服务端命令 |

模块依赖关系为 `scep-client → scep-common` 和 `scep-server → scep-common`。每个应用都会生成普通 JAR 和可执行的 `-exec.jar`。

Docker 文件按用途分开：

| 目录 | 用途 |
| --- | --- |
| [docker/scep](docker/scep/docker-compose.yml) | 统一部署本项目 Java 服务端与客户端；客户端支持注册、RenewalReq 续期和交互 Shell |
| [docker/sscep](docker/sscep/docker-compose.yml) | 第三方 sscep v0.10.0 测试客户端，用来请求、测试 SCEP 服务端，不提供 HTTP 服务 |

## 快速开始

### 环境要求

- JDK 17 或更高版本
- Maven 3.6.3 或更高版本

### 构建

在项目根目录执行：

```bash
mvn clean verify
```

### 启动服务端

项目自带一组教学 CA，默认从 `scep-server/src/main/resources/ca/` 加载。启动前设置客户端和服务端共用的注册口令：

```bash
export SCEP_CHALLENGE='请替换为本地测试口令'
java -jar scep-server/target/scep-server-1.0.0-exec.jar
```

服务端默认监听 `127.0.0.1:8080`，SCEP 地址为 `http://127.0.0.1:8080/scep`。

### 注册证书

另开一个终端，在项目根目录执行：

```bash
export SCEP_CHALLENGE='请替换为本地测试口令'
java -jar scep-client/target/scep-client-1.0.0-exec.jar enroll
```

客户端默认读取 [application.yml](scep-client/src/main/resources/application.yml)，生成以下文件：

```text
client-output/client.key       客户端私钥
client-output/client.pem       注册得到的证书
```

续期会使用旧证书和旧私钥签名，并生成新的密钥和证书：

```bash
java -jar scep-client/target/scep-client-1.0.0-exec.jar renew
```

命令行参数优先于 YAML 配置。例如，为另一台设备注册证书：

```bash
java -jar scep-client/target/scep-client-1.0.0-exec.jar enroll \
  --subject=CN=device-02 \
  --key=client-output/device-02.key \
  --out=client-output/device-02.pem
```

## Docker Compose 部署 Java 服务端与客户端

当前 Compose 按 Apple Silicon 环境使用 ARM64 镜像，要求安装 Docker Compose，以及用于打包的 JDK 17 和 Maven。
在项目根目录执行：

```bash
# 先从当前源码打包，再构建双端镜像。
mvn clean package -DskipTests
export SCEP_CHALLENGE='请替换为本地测试口令'
docker compose -f docker/scep/docker-compose.yml build scep-server scep-client
docker compose -f docker/scep/docker-compose.yml up -d
docker compose -f docker/scep/docker-compose.yml logs -f scep-server
```

上面的打包命令跳过测试；完整验证仍使用 `mvn clean verify`。
默认访问地址为 `http://127.0.0.1:8080/scep`。若本机已有 IDEA/JAR 服务占用 8080，先停止该服务，
或使用其他宿主机端口：

```bash
SCEP_PORT=18080 docker compose -f docker/scep/docker-compose.yml up -d --build
```

容器内固定监听 `0.0.0.0:8080`，发布端口默认仅绑定宿主机 `127.0.0.1`。
签发记录保存在命名卷 `scep-server_scep-depot`，重建容器后继续保留。
默认使用 JAR 中的教学 CA；CA 证书和私钥并不保存在签发记录卷中。
需要自行管理的 CA 时，可在 Compose 中将材料目录只读挂载到 `/app/ca`，
并设置 `SCEP_CA_CERTIFICATE=file:/app/ca/ca.pem` 和 `SCEP_CA_PRIVATE_KEY=file:/app/ca/ca.key`。

本地立即练习续期时，可在启动命令前设置 `SCEP_RENEWAL_DAYS=0`，并使用支持 RenewalReq 的客户端。
停止服务端：

```bash
docker compose -f docker/scep/docker-compose.yml down
```

`down` 保留签发记录卷，`down -v` 会删除该卷；正常停止无需添加 `-v`。

双端共用 `docker/scep` 目录中的 Compose、Dockerfile 和构建上下文过滤文件，
通过 Dockerfile 的 `server`、`client` 构建目标分别生成镜像。
客户端使用 `client` profile，普通 `up -d` 只启动服务端，需要时通过 `run --rm` 执行客户端。
客户端默认通过内部网络访问 `http://scep-server:8080/scep`，不受宿主机映射端口变化影响。
服务端需先启动并就绪，运行客户端时保持相同的注册口令：

```bash
export SCEP_CHALLENGE='请替换为服务端使用的注册口令'

# 查看帮助，不发送 SCEP 请求。
docker compose -f docker/scep/docker-compose.yml run --rm scep-client help

# 注册证书。
docker compose -f docker/scep/docker-compose.yml run --rm scep-client enroll

# 发送 RenewalReq（17），使用旧身份签名并生成新密钥。
docker compose -f docker/scep/docker-compose.yml run --rm scep-client renew

# 无参数进入交互 Shell，输入 help、enroll、renew 或 exit。
docker compose -f docker/scep/docker-compose.yml run --rm scep-client
```

客户端使用只读挂载的 [client.yml](docker/scep/client.yml)，并将宿主机教学 CA 证书只读挂载到 `/ca/ca.pem`；
CA 私钥不会挂载到客户端。使用自行管理的 CA 时，将 Compose 中 CA 证书的 `source` 改为相应可信证书文件。
输出目录 `client-output` 挂载到 `/work/client-output`，临时容器退出后保留密钥和证书，已有证书输出不会被覆盖。
注册默认生成 `client.key` 和 `client.pem`，续期默认生成 `new.key` 和 `renewed.pem`。
续期窗口仍由服务端的 `SCEP_RENEWAL_DAYS` 控制。

需要请求宿主机已有的 IDEA/JAR 服务时，可覆盖地址；也可传入已有 Shell 命令选项：

```bash
SCEP_URL=http://host.docker.internal:18080/scep \
  docker compose -f docker/scep/docker-compose.yml run --rm scep-client enroll \
  --subject=CN=device-02 --key=client-output/device-02.key --out=client-output/device-02.pem
```

`run --rm` 每次运行后自动删除客户端容器；不需要为客户端发布端口。

## sscep：服务端测试客户端

`docker/sscep` 只部署第三方 sscep 客户端，用于手动测试本项目服务端，不会启动 Java 服务端，也不占用 8080 端口。
它从官方 v0.10.0 源码构建 ARM64 镜像，适用于当前 Apple Silicon 环境。

在项目根目录执行：

```bash
docker compose -f docker/sscep/docker-compose.yml up -d --build
docker compose -f docker/sscep/docker-compose.yml exec sscep-client bash
```

`docker/sscep/sscep-test` 挂载为容器内的 `/work`，用于保存测试私钥、CSR 和返回的证书。
`SCEP_URL` 默认是 `http://host.docker.internal:8080/scep`，可访问宿主机的 IDEA/JAR 服务，
也可访问上面映射到本机 8080 的 Java 服务端容器。IDEA/JAR 服务需监听容器可访问的地址，
例如设置 `SCEP_BIND=0.0.0.0`。自定义宿主机端口时，在启动测试客户端前设置对应地址：

```bash
SCEP_URL=http://host.docker.internal:18080/scep \
  docker compose -f docker/sscep/docker-compose.yml up -d
```

进入客户端容器后手动执行：

```bash
sscep getcaps -u "$SCEP_URL" -v
sscep getca -u "$SCEP_URL" -c /work/ca.pem -v

# 先准备 client.key 和 client.csr；CSR 的 challengePassword 须与服务端一致。
sscep enroll -u "$SCEP_URL" -c /work/ca.pem \
  -k /work/client.key -r /work/client.csr \
  -l /work/client.pem -L /work/client-selfsigned.pem \
  -E aes -S sha256 -v
```

下载的 CA 应与预配可信材料核对。sscep v0.10.0 会先查询 GetCACaps，服务端声明 `POSTPKIOperation` 时自动使用 POST。
该版本的 `-K/-O` 仍发送 PKCSReq（19），不能测试本项目的 RenewalReq（17）续期分支。
停止测试客户端使用 `docker compose -f docker/sscep/docker-compose.yml down`，共享目录中的测试材料会保留。

## 配置

服务端配置通过环境变量覆盖默认值：

| 环境变量 | 默认值 | 说明 |
| --- | --- | --- |
| `SCEP_BIND` | `127.0.0.1` | 监听地址 |
| `SCEP_PORT` | `8080` | 监听端口 |
| `SCEP_CHALLENGE` | `12345678` | 初始注册口令 |
| `SCEP_CA_CERTIFICATE` | `classpath:ca/ca.pem` | CA 证书位置 |
| `SCEP_CA_PRIVATE_KEY` | `classpath:ca/ca.key` | CA 私钥位置 |
| `SCEP_DEPOT` | `./depot` | 签发记录目录 |
| `SCEP_VALIDITY_DAYS` | `1` | 新证书有效期，单位为天 |
| `SCEP_RENEWAL_DAYS` | `14` | 提前续期天数，`0` 表示不限制 |
| `SCEP_ALLOW_SAN` | `false` | 是否允许 CSR 提交 SAN |

使用外部 CA 时，将证书和私钥配置为文件 URI：

```bash
export SCEP_CA_CERTIFICATE='file:/absolute/path/ca.pem'
export SCEP_CA_PRIVATE_KEY='file:/absolute/path/ca.key'
```

客户端的完整配置位于 [scep-client/src/main/resources/application.yml](scep-client/src/main/resources/application.yml)。已打包应用可以通过 `SPRING_CONFIG_ADDITIONAL_LOCATION` 加载外部 YAML：

```bash
SPRING_CONFIG_ADDITIONAL_LOCATION=file:/absolute/path/client.yml \
  java -jar scep-client/target/scep-client-1.0.0-exec.jar enroll
```

## Shell 命令

查看帮助或进入交互模式：

```bash
java -jar scep-client/target/scep-client-1.0.0-exec.jar help
java -jar scep-client/target/scep-client-1.0.0-exec.jar renew --help
java -jar scep-server/target/scep-server-1.0.0-exec.jar ca-init --help
java -jar scep-client/target/scep-client-1.0.0-exec.jar
java -jar scep-server/target/scep-server-1.0.0-exec.jar shell
```

`ca-init` 是可选的 CA 文件生成工具，日常启动服务端不需要执行。

## 支持范围

当前实现支持：

- AES-128-CBC、AES-192-CBC、AES-256-CBC 和 3DES 的请求解密
- SHA-1 和 SHA-256 的报文校验，输出使用 AES-128-CBC 和 SHA-256
- 注册与续期时的 challenge、CSR 私钥证明、交易 ID、双向 nonce 和证书公钥校验
- 签名的 `CertRep SUCCESS` 与 `CertRep FAILURE` 响应

当前未实现人工审批、轮询取证书、证书撤销、CRL/OCSP、HSM、集群事务和 CA 轮换。文件目录按单实例使用。

## 开发与验证

格式化并运行全部测试：

```bash
mvn formatter:format
mvn verify
```

可执行 JAR 的命令行和 classpath CA 验证：

```bash
bash scripts/smoke-shell.sh
bash scripts/smoke-classpath-ca.sh
```

更多内容：

- [SCEP 学习指南](docs/learning-scep.md)
- [模块与命令行设计](docs/modules-and-shell.md)
- [代码规范](docs/code-style.md)
- [验证记录](docs/verification.md)

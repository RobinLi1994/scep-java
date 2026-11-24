package com.example.scep.client.transport;

import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import javax.security.auth.x500.X500Principal;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;

import com.example.scep.common.crypto.Crypto;
import com.example.scep.common.protocol.ScepCodec;
import com.example.scep.common.protocol.ScepConstants;
import com.example.scep.common.protocol.enums.CapabilityEnum;
import com.example.scep.common.protocol.enums.MessageTypeEnum;
import com.example.scep.common.protocol.enums.OperationEnum;

/**
 * 最小同步 SCEP 客户端：把已准备的 CSR 提交给固定可信 CA，并验证结果。
 * <p>HTTP 下载到 CA 证书不等于建立信任。trustedCa 必须先通过可信渠道配置，
 * GetCACert 只确认服务提供了预期证书。HTTP/TLS 与 CMS 验证是不同层的保护。</p>
 * <p>本客户端处理单 CA、同步签发及能力发现；优先 POST，兼容 GET，不处理 RA 链或 PENDING 轮询。</p>
 *
 * @author robin.li
 * @date 2026-11-20 21:52:59
 */
@Slf4j
public final class ScepClient {
    private static final String CONTENT_TYPE_HEADER = "Content-Type";

    /**
     * HTTP 连接建立上限，与一次请求等待响应的上限分开设置。
     */
    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);

    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);

    /**
     * 响应最多读取 1 MiB；再多读一个字节用来检测超限。
     */
    private static final int MAX_RESPONSE_BYTES = 1024 * 1024;

    private final URI endpoint;

    private final X509Certificate trustedCa;

    private final HttpClient http = HttpClient.newBuilder().connectTimeout(CONNECT_TIMEOUT).build();

    /**
     * 创建固定信任一张 CA 证书的客户端。
     *
     * @param endpoint  完整 SCEP 地址，不带查询参数
     * @param trustedCa 事先信任的 CA 证书，不从当前 HTTP 连接中自动接受新信任
     * @throws IllegalArgumentException 地址协议或结构不受支持时抛出
     */
    public ScepClient(URI endpoint, X509Certificate trustedCa) {
        if (!("http".equals(endpoint.getScheme()) || "https".equals(endpoint.getScheme())) || endpoint.getHost() == null
                || endpoint.getRawQuery() != null || endpoint.getFragment() != null || endpoint.getUserInfo() != null) {
            throw new IllegalArgumentException("SCEP 地址必须使用 HTTP(S)，且不能包含查询参数、片段或用户信息");
        }
        this.endpoint = endpoint;
        this.trustedCa = trustedCa;
    }

    /**
     * 注册或续期，并检查返回证书对应申请的公钥和 subject。
     *
     * @param csr                已签名的 PKCS#10 申请，其中的公钥将写入新证书
     * @param signingKey         CMS 身份私钥；换钥续期时与 CSR 的签名私钥不同
     * @param signingCertificate CMS 身份证书；初始为自签证书，续期为旧证书
     * @param type               PKCS_REQ 初始注册或 RENEWAL_REQ 续期
     * @return 通过协议与证书校验的新证书
     * @throws Exception HTTP 调用、固定 CA 校验、SCEP 拒绝或证书校验失败时抛出
     */
    public X509Certificate enroll(PKCS10CertificationRequest csr, PrivateKey signingKey,
            X509Certificate signingCertificate, MessageTypeEnum type) throws Exception {
        log.info("开始发送 SCEP 申请，端点={}，messageType={}，subject={}", endpoint, type.getCode(),
                csr.getSubject());
        // GetCACaps 未签名，只用于选择双方支持的操作；算法下限仍由本地策略决定。
        CaCapabilities capabilities = getCapabilities();
        capabilities.requireEnrollment(type);
        // 1. 信任根来自调用方事先配置；下载 CA 证书只用于确认端点与这份配置一致。
        trustedCa.checkValidity();
        byte[] serverCa = send(HttpRequest.newBuilder(operation(OperationEnum.GET_CA_CERT)).GET().build(),
                ScepConstants.CA_CERT_MEDIA_TYPE);
        if (!Arrays.equals(serverCa, trustedCa.getEncoded())) {
            throw new IllegalArgumentException("GetCACert 返回的证书与预配可信 CA 不一致");
        }
        // 2. request 保存本次的事务 ID 和 nonce；解读响应时还要用到，不能只保留发送字节。
        ScepCodec.Request request = ScepCodec.request(csr, signingKey, signingCertificate, trustedCa, type);
        HttpRequest transport;
        if (capabilities.supports(CapabilityEnum.POST_PKI_OPERATION)) {
            // 服务端声明支持 POST 时必须优先使用 POST，直接传输 CMS 二进制。
            transport = HttpRequest.newBuilder(operation(OperationEnum.PKI_OPERATION))
                    .header(CONTENT_TYPE_HEADER, ScepConstants.PKI_MESSAGE_MEDIA_TYPE)
                    .POST(HttpRequest.BodyPublishers.ofByteArray(request.encoded())).build();
            log.debug("SCEP 申请使用 POST，transactionId={}，请求大小={} 字节", request.transactionId(),
                    request.encoded().length);
        } else {
            // 旧服务端可能只有 GET；先标准 Base64，再 URL 编码，防止 '+' 被解释为空格。
            String message =
                    URLEncoder.encode(Base64.getEncoder().encodeToString(request.encoded()), StandardCharsets.UTF_8);
            transport = HttpRequest.newBuilder(URI.create(
                    operation(OperationEnum.PKI_OPERATION) + "&" + ScepConstants.MESSAGE_PARAMETER + "=" + message))
                    .GET().build();
            log.debug("SCEP 申请使用 GET，transactionId={}，请求大小={} 字节", request.transactionId(),
                    request.encoded().length);
        }
        byte[] response = send(transport, ScepConstants.PKI_MESSAGE_MEDIA_TYPE);
        // 4. expectedKey 应来自 CSR；换钥续期时，它与用来签名/解密的旧身份公钥不同。
        PublicKey key = new JcaPKCS10CertificationRequest(csr).setProvider(Crypto.PROVIDER).getPublicKey();
        X509Certificate issued = ScepCodec.readResponse(response, request, trustedCa, signingKey, key);
        // 5. 协议层已检查 CA 签名、有效期和公钥，这里再检查完整 subject 与申请一致。
        X500Principal expectedSubject = new X500Principal(csr.getSubject().getEncoded());
        if (!expectedSubject.equals(issued.getSubjectX500Principal())) {
            throw new IllegalArgumentException("签发证书的主题与申请不一致");
        }
        log.info("SCEP 申请成功，transactionId={}，证书序列号={}", request.transactionId(),
                issued.getSerialNumber().toString(16));
        return issued;
    }

    /**
     * 查询服务能力。RFC 8894 §3.5.2 要求兼容旧端点的媒体类型，因此此操作不检查 MIME。
     * HTTP 错误等价于没有已声明能力；后续 requireEnrollment 会明确拒绝不安全降级。
     *
     * @return 已解析的能力集合
     * @throws Exception 连接失败、读取超时或响应过大时抛出
     */
    public CaCapabilities getCapabilities() throws Exception {
        log.debug("查询 CA 能力，端点={}", endpoint);
        return CaCapabilities.parse(
                new String(send(HttpRequest.newBuilder(operation(OperationEnum.GET_CA_CAPS)).GET().build(), null),
                        StandardCharsets.US_ASCII));
    }

    /**
     * 构造 HTTP 操作地址；注册和续期都使用 PKIOperation。
     *
     * @param operation SCEP HTTP 操作名称
     * @return 带 operation 参数的 URI
     */
    private URI operation(OperationEnum operation) {
        return URI.create(endpoint + "?" + ScepConstants.OPERATION_PARAMETER + "=" + operation.getCode());
    }

    /**
     * 校验传输层结果；HTTP 200 后仍需由协议层检查 pkiStatus。
     *
     * @param original     已设置地址、方法和请求体的请求
     * @param expectedType 本次操作预期返回的 MIME 类型
     * @return 至多 1 MiB 的响应体
     * @throws Exception 超时、网络错误、HTTP/MIME 不符或响应过大时抛出
     */
    private byte[] send(HttpRequest original, String expectedType) throws Exception {
        // 连接超时在 HttpClient 上配置；这里再给每个请求设置超时，并保留原请求的头与正文。
        HttpRequest request = HttpRequest.newBuilder(original, (name, value) -> true).timeout(REQUEST_TIMEOUT).build();
        // 选择流式响应体后才能自行限制读取量，避免一开始就将任意大的响应装进 byte[]。
        HttpResponse<InputStream> response = http.send(request, HttpResponse.BodyHandlers.ofInputStream());
        // GET 查询参数可能携带完整 CMS 报文，日志只记录不含查询参数的端点。
        log.debug("收到 SCEP HTTP 响应，方法={}，端点={}，状态码={}", request.method(), endpoint,
                response.statusCode());
        try (InputStream input = response.body()) {
            if (response.statusCode() != HttpURLConnection.HTTP_OK) {
                if (expectedType == null) {
                    return new byte[0];
                }
                throw new IllegalStateException("SCEP HTTP 请求失败，状态码：" + response.statusCode());
            }
            // 按操作检查 MIME，防止把代理/登录页返回的 HTML 误交给 CMS 解析器；分号后是媒体类型参数。
            String contentType = response.headers().firstValue(CONTENT_TYPE_HEADER).orElse("").split(";", 2)[0].trim();
            if (expectedType != null && !expectedType.equalsIgnoreCase(contentType)) {
                throw new IllegalArgumentException("SCEP 响应的 Content-Type 不符合预期");
            }
            // 上限是 1 MiB，多读一个字节用于区分“恰好达到上限”和“实际已经超限”。
            byte[] bytes = input.readNBytes(MAX_RESPONSE_BYTES + 1);
            if (bytes.length > MAX_RESPONSE_BYTES) {
                throw new IllegalArgumentException("SCEP 响应超过大小限制");
            }
            log.debug("读取 SCEP HTTP 响应，大小={} 字节", bytes.length);
            return bytes;
        }
    }
}

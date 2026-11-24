package com.example.scep.server;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Base64;

import org.bouncycastle.asn1.x500.X500Name;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import com.example.scep.client.transport.ScepClient;
import com.example.scep.common.crypto.Crypto;
import com.example.scep.common.protocol.ScepCodec;
import com.example.scep.common.protocol.ScepFailureException;
import com.example.scep.common.protocol.enums.MessageTypeEnum;
import com.example.scep.server.ca.CertificateAuthority;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * HTTP 集成示例集：随机端口启动真实 Spring Boot，验证传输层与协议层的连接。
 *
 * @author robin.li
 * @date 2026-11-20 21:52:59
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ScepHttpTest {
    static final Path DEPOT;
    static {
        try {
            DEPOT = Files.createTempDirectory("scep-http-test-");
            CertificateAuthority.initialize(DEPOT, "CN=HTTP Test CA", 2048, 3650);
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    /**
     * 把临时 CA 和较小的请求上限注入测试服务，不使用开发者真实 depot。
     * @param registry Spring 测试的动态配置注册器
     */
    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("scep.depot", () -> DEPOT.toString());
        registry.add("scep.ca-certificate", () -> DEPOT.resolve("ca.pem").toUri().toString());
        registry.add("scep.ca-private-key", () -> DEPOT.resolve("ca.key").toUri().toString());
        registry.add("scep.challenge", () -> "http-secret");
        registry.add("scep.max-request-bytes", () -> 16384);
        // 允许边界用例到达 Controller，避免 Tomcat 先按默认请求头上限拒绝较长的 GET URL。
        registry.add("server.max-http-request-header-size", () -> "32KB");
    }

    @LocalServerPort
    int port;

    final HttpClient http = HttpClient.newHttpClient();

    /**
     * 根据本次随机端口生成测试地址。
     * @param query 已处理 URL 编码的查询字符串
     * @return 测试服务 URI
     */
    URI uri(String query) {
        return URI.create("http://127.0.0.1:" + port + "/scep?" + query);
    }

    /**
     * 直接获取原始响应字节，防止测试替服务进行多余的 JSON/Base64 转换。
     * @param query 已处理 URL 编码的查询字符串
     * @return 状态码、响应头和原始响应体
     * @throws Exception HTTP 调用失败时抛出
     */
    HttpResponse<byte[]> get(String query) throws Exception {
        return http.send(HttpRequest.newBuilder(uri(query)).GET().build(), HttpResponse.BodyHandlers.ofByteArray());
    }

    /** 统一发送真实 HTTP 请求；测试输入保留协议字面值，避免与生产路由共用错误映射。 */
    private HttpResponse<byte[]> send(String method, String query, byte[] body) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri(query));
        if ("POST".equals(method)) {
            builder.header("Content-Type", "application/x-pki-message")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(body));
        } else {
            builder.GET();
        }
        return http.send(builder.build(), HttpResponse.BodyHandlers.ofByteArray());
    }

    /** 缺失、重复和未知操作都要经过明确校验，不能由参数路由选中某一项后直接处理。 */
    @ParameterizedTest
    @CsvSource({"GET, '', 400, 必须且只能提供一个 operation 参数", "POST, '', 400, 必须且只能提供一个 operation 参数",
            "GET, operation=, 400, 不支持该 SCEP 操作", "POST, operation=, 405, POST 仅支持 PKIOperation 操作",
            "GET, operation=Unknown, 400, 不支持该 SCEP 操作", "POST, operation=Unknown, 405, POST 仅支持 PKIOperation 操作",
            "POST, operation=GetCACaps, 405, POST 仅支持 PKIOperation 操作",
            "POST, operation=GetCACert, 405, POST 仅支持 PKIOperation 操作", "GET, operation=getcacaps, 400, 不支持该 SCEP 操作",
            "GET, operation=GetCACaps&operation=GetCACaps, 400, 必须且只能提供一个 operation 参数",
            "GET, operation=GetCACert&operation=GetCACaps, 400, 必须且只能提供一个 operation 参数",
            "GET, operation=PKIOperation&operation=GetCACaps&message=AQID, 400, 必须且只能提供一个 operation 参数",
            "POST, operation=PKIOperation&operation=PKIOperation, 400, 必须且只能提供一个 operation 参数",
            "POST, operation=GetCACert&operation=PKIOperation, 400, 必须且只能提供一个 operation 参数",
            "GET, operation=Unknown&operation=GetCACert, 400, 必须且只能提供一个 operation 参数",
            "POST, operation=Unknown&operation=PKIOperation, 400, 必须且只能提供一个 operation 参数"})
    void preservesOperationErrors(String method, String query, int status, String message) throws Exception {
        assertHttpError(send(method, query, new byte[0]), status, message);
    }

    /** GET 参数读取和 POST 请求体读取分开后，空值、重复值及报文错误仍应保持原有响应。 */
    @ParameterizedTest
    @CsvSource({"GET, operation=PKIOperation, 必须且只能提供一个 message 参数",
            "GET, operation=PKIOperation&message=, SCEP 报文不能为空",
            "GET, operation=PKIOperation&message=AQID&message=AQID, 必须且只能提供一个 message 参数",
            "GET, operation=PKIOperation&message=!!!, message 参数不是有效的 Base64 编码",
            "GET, operation=PKIOperation&message=AQID, SCEP 报文格式或签名无效", "POST, operation=PKIOperation, SCEP 报文不能为空"})
    void preservesMessageErrors(String method, String query, String message) throws Exception {
        assertHttpError(send(method, query, new byte[0]), 400, message);
    }

    /** Base64 长度只能提前筛选，解码后必须复核；相邻字节长度可能得到同样长的 Base64。 */
    @Test
    void checksGetSizeBeforeAndAfterBase64Decoding() throws Exception {
        String atLimit = Base64.getEncoder().encodeToString(new byte[16384]);
        String overLimit = Base64.getEncoder().encodeToString(new byte[16385]);
        assertEquals(atLimit.length(), overLimit.length());
        assertHttpError(get("operation=PKIOperation&message=" + atLimit), 400, "SCEP 报文格式或签名无效");
        assertHttpError(get("operation=PKIOperation&message=" + overLimit), 413, "SCEP 报文超过大小限制");
        assertHttpError(get("operation=PKIOperation&message=" + overLimit + "AAAA"), 413, "SCEP 报文超过大小限制");
    }

    /** 授权拒绝仍是 HTTP 200 加可验签的 CertRep FAILURE；GET/POST 共用同一协议结果。 */
    @ParameterizedTest
    @ValueSource(strings = {"GET", "POST"})
    void keepsSignedFailureAsSuccessfulHttpResponse(String method) throws Exception {
        CertificateAuthority ca = CertificateAuthority.load(DEPOT);
        KeyPair key = Crypto.rsa(2048);
        X509Certificate identity = Crypto.selfSigned(key, new X500Name("CN=rejected-device"));
        ScepCodec.Request request = ScepCodec.request(ScepServiceTest.csr(key, "CN=rejected-device", "wrong-secret"),
                key.getPrivate(), identity, ca.certificate(), MessageTypeEnum.PKCS_REQ);
        String query = "operation=PKIOperation";
        if ("GET".equals(method)) {
            query += "&message="
                    + URLEncoder.encode(Base64.getEncoder().encodeToString(request.encoded()), StandardCharsets.UTF_8);
        }
        HttpResponse<byte[]> response = send(method, query, request.encoded());
        assertEquals(200, response.statusCode());
        assertEquals("application/x-pki-message", response.headers().firstValue("Content-Type").orElseThrow());
        assertEquals("no-store", response.headers().firstValue("Cache-Control").orElseThrow());
        ScepFailureException failure = assertThrows(ScepFailureException.class, () -> ScepCodec
                .readResponse(response.body(), request, ca.certificate(), key.getPrivate(), key.getPublic()));
        assertEquals("2", failure.failInfo());
    }

    /** HTTP 层错误使用明确状态及中文 UTF-8 文本，并保持禁止缓存。 */
    private static void assertHttpError(HttpResponse<byte[]> response, int status, String message) {
        assertEquals(status, response.statusCode());
        assertEquals(message, new String(response.body(), StandardCharsets.UTF_8));
        assertTrue(response.headers().firstValue("Content-Type").orElseThrow().toLowerCase().contains("charset=utf-8"));
        assertEquals("no-store", response.headers().firstValue("Cache-Control").orElseThrow());
    }

    /**
     * 从发现接口区分纯文本能力列表与 DER CA 证书，检查服务不宣告未实现能力。
     * @throws Exception 测试所需密码或 I/O 操作异常时由 JUnit 报告
     */
    @Test
    void discoveryHasCorrectMimeAndCertificate() throws Exception {
        HttpResponse<byte[]> caps = get("operation=GetCACaps");
        assertEquals(200, caps.statusCode());
        assertTrue(new String(caps.body(), StandardCharsets.US_ASCII).contains("POSTPKIOperation"));
        assertFalse(new String(caps.body(), StandardCharsets.US_ASCII).contains("GetNextCACert"));
        HttpResponse<byte[]> cert = get("operation=GetCACert");
        assertEquals("application/x-x509-ca-cert", cert.headers().firstValue("Content-Type").orElseThrow());
        assertArrayEquals(CertificateAuthority.load(DEPOT).certificate().getEncoded(), cert.body());
    }

    /**
     * 同一协议流程既能通过 URL 编码 Base64 GET，也能通过原始二进制 POST 完成。
     * @throws Exception 测试所需密码或 I/O 操作异常时由 JUnit 报告
     */
    @Test
    void registersOverGetAndPost() throws Exception {
        CertificateAuthority ca = CertificateAuthority.load(DEPOT);
        KeyPair key = Crypto.rsa(2048);
        X509Certificate self = Crypto.selfSigned(key, new X500Name("CN=http-device"));
        for (boolean post : new boolean[] {false, true}) {
            ScepCodec.Request request = ScepCodec.request(ScepServiceTest.csr(key, "CN=http-device", "http-secret"),
                    key.getPrivate(), self, ca.certificate(), MessageTypeEnum.PKCS_REQ);
            HttpResponse<byte[]> response;
            if (post) {
                response = http.send(
                        HttpRequest.newBuilder(uri("operation=PKIOperation"))
                                .header("Content-Type", "application/x-pki-message")
                                .POST(HttpRequest.BodyPublishers.ofByteArray(request.encoded())).build(),
                        HttpResponse.BodyHandlers.ofByteArray());
            } else {
                response = get("operation=PKIOperation&message=" + URLEncoder
                        .encode(Base64.getEncoder().encodeToString(request.encoded()), StandardCharsets.UTF_8));
            }
            assertEquals(200, response.statusCode());
            assertEquals("application/x-pki-message", response.headers().firstValue("Content-Type").orElseThrow());
            assertTrue(ca.isIssued(ScepCodec.readResponse(response.body(), request, ca.certificate(), key.getPrivate(),
                    key.getPublic())));
        }
    }

    /**
     * HTTP 参数、MIME、固定长度及 chunked 大小限制先于协议签发执行。
     * @throws Exception 测试所需密码或 I/O 操作异常时由 JUnit 报告
     */
    @Test
    void rejectsMalformedMissingUnsupportedAndOversizedRequests() throws Exception {
        assertEquals(400, get("").statusCode());
        assertEquals(400, get("operation=GetNextCACert").statusCode());
        assertEquals(400, get("operation=PKIOperation&message=!!!").statusCode());
        HttpResponse<byte[]> response = http.send(
                HttpRequest.newBuilder(uri("operation=PKIOperation"))
                        .header("Content-Type", "application/x-pki-message")
                        .POST(HttpRequest.BodyPublishers.ofByteArray(new byte[16385])).build(),
                HttpResponse.BodyHandlers.ofByteArray());
        assertEquals(413, response.statusCode());
        HttpResponse<byte[]> malformed = http.send(
                HttpRequest.newBuilder(uri("operation=PKIOperation"))
                        .header("Content-Type", "application/x-pki-message")
                        .POST(HttpRequest.BodyPublishers.ofByteArray(new byte[] {1, 2, 3})).build(),
                HttpResponse.BodyHandlers.ofByteArray());
        assertEquals(400, malformed.statusCode());
        HttpResponse<byte[]> chunked =
                http.send(
                        HttpRequest.newBuilder(uri("operation=PKIOperation"))
                                .header("Content-Type", "application/x-pki-message")
                                .POST(HttpRequest.BodyPublishers
                                        .ofInputStream(() -> new ByteArrayInputStream(new byte[16385])))
                                .build(),
                        HttpResponse.BodyHandlers.ofByteArray());
        assertEquals(413, chunked.statusCode());
        assertEquals(400, get("operation=GetCACert&operation=GetCACaps").statusCode());
        HttpResponse<byte[]> wrongType = http.send(
                HttpRequest.newBuilder(uri("operation=PKIOperation")).header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString("{}")).build(),
                HttpResponse.BodyHandlers.ofByteArray());
        assertEquals(415, wrongType.statusCode());
    }

    /**
     * 用真实 HTTP 客户端完成注册，并证明错误的预置信任 CA 会被拒绝。
     * @throws Exception 测试所需密码或 I/O 操作异常时由 JUnit 报告
     */
    @Test
    void javaClientEnrollsUsingPinnedCa() throws Exception {
        CertificateAuthority ca = CertificateAuthority.load(DEPOT);
        KeyPair key = Crypto.rsa(2048);
        X509Certificate self = Crypto.selfSigned(key, new X500Name("CN=java-client"));
        ScepClient client = new ScepClient(URI.create("http://127.0.0.1:" + port + "/scep"), ca.certificate());
        X509Certificate cert = client.enroll(ScepServiceTest.csr(key, "CN=java-client", "http-secret"),
                key.getPrivate(), self, MessageTypeEnum.PKCS_REQ);
        assertTrue(ca.isIssued(cert));
        ScepClient wrongCa = new ScepClient(URI.create("http://127.0.0.1:" + port + "/scep"), self);
        assertThrows(IllegalArgumentException.class,
                () -> wrongCa.enroll(ScepServiceTest.csr(key, "CN=java-client", "http-secret"), key.getPrivate(), self,
                        MessageTypeEnum.PKCS_REQ));
    }

    /**
     * 覆盖使用 application/octet-stream 或缺省 Content-Type 的客户端，响应仍须是可验证 CertRep。
     * @throws Exception 测试所需密码或 I/O 操作异常时由 JUnit 报告
     */
    @Test
    void acceptsBinaryPostsFromOlderClients() throws Exception {
        CertificateAuthority ca = CertificateAuthority.load(DEPOT);
        KeyPair key = Crypto.rsa(2048);
        ScepCodec.Request request = ScepCodec.request(ScepServiceTest.csr(key, "CN=http-device", "http-secret"),
                key.getPrivate(), Crypto.selfSigned(key, new X500Name("CN=http-device")), ca.certificate(),
                MessageTypeEnum.PKCS_REQ);
        for (String type : new String[] {"application/octet-stream", null}) {
            HttpRequest.Builder builder = HttpRequest.newBuilder(uri("operation=PKIOperation"))
                    .POST(HttpRequest.BodyPublishers.ofByteArray(request.encoded()));
            if (type != null) {
                builder.header("Content-Type", type);
            }
            HttpResponse<byte[]> response = http.send(builder.build(), HttpResponse.BodyHandlers.ofByteArray());
            assertEquals(200, response.statusCode());
            assertTrue(ca.isIssued(ScepCodec.readResponse(response.body(), request, ca.certificate(), key.getPrivate(),
                    key.getPublic())));
        }
    }

    /** HTTP 全局边界统一返回 UTF-8 中文，保留 404/405 等原始状态。 */
    @Test
    void httpErrorsUseChineseMessages() throws Exception {
        HttpResponse<byte[]> badRequest = get("");
        assertTrue(new String(badRequest.body(), StandardCharsets.UTF_8).contains("必须且只能"));
        assertTrue(badRequest.headers().firstValue("Content-Type").orElseThrow().toLowerCase().contains("utf-8"));
        HttpResponse<String> missing =
                http.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/missing")).GET().build(),
                        HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        assertEquals(404, missing.statusCode());
        assertEquals("请求的接口不存在", missing.body());
        HttpResponse<String> method = http.send(HttpRequest.newBuilder(uri("operation=GetCACert")).DELETE().build(),
                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        assertEquals(405, method.statusCode());
        assertEquals("该接口不支持此 HTTP 方法", method.body());
    }

}

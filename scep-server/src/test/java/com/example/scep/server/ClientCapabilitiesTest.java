package com.example.scep.server;

import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import com.sun.net.httpserver.HttpServer;
import org.bouncycastle.asn1.x500.X500Name;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import com.example.scep.client.transport.ScepClient;
import com.example.scep.common.crypto.Crypto;
import com.example.scep.common.protocol.enums.MessageTypeEnum;
import com.example.scep.server.ca.CertificateAuthority;
import com.example.scep.server.service.ScepService;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 用真实本地 HTTP 端点观察客户端的能力查询和传输选择。
 * @author robin.li
 * @date 2026-11-22 09:45:39
 */
class ClientCapabilitiesTest {
    @TempDir
    Path depot;

    /** SCEPStandard 隐含现代算法及 POST，普通能力列表则逐项决定传输方式。 */
    @ParameterizedTest
    @CsvSource({"SCEPStandard,POST", "aes|sha-256|POSTPKIOperation|FutureFeature,POST", "AES|SHA-256,GET"})
    void queriesCapabilitiesBeforeEnrollment(String capabilities, String method) throws Exception {
        runScenario(capabilities.replace("|", "\r\n") + "\n", "19", method, true, 200);
    }

    /** 不向缺少现代算法或未声明续期能力的端点发送申请。 */
    @ParameterizedTest
    @CsvSource({"DES3|SHA-1,19", "AES,19", "SHA-256,19", "SCEPStandard,17", "FutureFeature,19"})
    void rejectsUnsupportedAlgorithmsOrRenewal(String capabilities, String type) throws Exception {
        runScenario(capabilities.replace("|", "\n"), type, "POST", false, 200);
    }

    /** 旧端点不能查询能力时视为能力缺失；本客户端禁止降级到旧算法。 */
    @Test
    void rejectsCapabilitiesHttpErrorBeforeSendingRequest() throws Exception {
        runScenario("", "19", "POST", false, 404);
    }

    /**
     * 启动独立 HTTP 夹具；成功用例实际签发证书，拒绝用例断言没有 PKIOperation。
     * MIME 刻意使用旧设备常见的 application/octet-stream，GetCACaps 应忽略它。
     */
    private void runScenario(String caps, String type, String method, boolean success, int capsStatus)
            throws Exception {
        CertificateAuthority.initialize(depot, "CN=Capabilities CA", 2048, 365);
        CertificateAuthority ca = CertificateAuthority.load(depot);
        ScepService service = new ScepService(ca, "test-secret", 30, 0, false);
        KeyPair key = Crypto.rsa(2048);
        X509Certificate identity = Crypto.selfSigned(key, new X500Name("CN=device-01"));
        List<String> trace = new CopyOnWriteArrayList<>();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/scep", exchange -> {
            String query = exchange.getRequestURI().getRawQuery();
            String operation = query.split("&", 2)[0].substring("operation=".length());
            trace.add(exchange.getRequestMethod() + " " + operation);
            try {
                byte[] bytes;
                int status = 200;
                String contentType;
                if (operation.equals("GetCACaps")) {
                    bytes = caps.getBytes(StandardCharsets.US_ASCII);
                    status = capsStatus;
                    contentType = "application/octet-stream";
                } else if (operation.equals("GetCACert")) {
                    bytes = ca.certificate().getEncoded();
                    contentType = "application/x-x509-ca-cert";
                } else {
                    // GET 必须正确转义 Base64 中的 +、/、=，解码后的 CMS 应和 POST 一样可验签。
                    byte[] request = exchange.getRequestMethod().equals("POST")
                            ? exchange.getRequestBody().readAllBytes() : Base64.getDecoder()
                                    .decode(URLDecoder.decode(query.split("&message=", 2)[1], StandardCharsets.UTF_8));
                    bytes = service.handle(request);
                    contentType = "application/x-pki-message";
                }
                exchange.getResponseHeaders().set("Content-Type", contentType);
                exchange.sendResponseHeaders(status, bytes.length);
                exchange.getResponseBody().write(bytes);
            } catch (Exception e) {
                exchange.sendResponseHeaders(500, -1);
            } finally {
                exchange.close();
            }
        });
        server.start();
        try {
            ScepClient client = new ScepClient(
                    URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/scep"), ca.certificate());
            if (success) {
                X509Certificate certificate = client.enroll(ScepServiceTest.csr(key, "CN=device-01", "test-secret"),
                        key.getPrivate(), identity, MessageTypeEnum.fromCode(type));
                assertTrue(ca.isIssued(certificate));
                assertEquals(List.of("GET GetCACaps", "GET GetCACert", method + " PKIOperation"), trace);
            } else {
                Exception failure = assertThrows(Exception.class,
                        () -> client.enroll(ScepServiceTest.csr(key, "CN=device-01", "test-secret"), key.getPrivate(),
                                identity, MessageTypeEnum.fromCode(type)));
                assertTrue(failure.getMessage().matches("(?s).*[\\p{IsHan}].*"), failure.getMessage());
                assertEquals(List.of("GET GetCACaps"), trace);
            }
        } finally {
            server.stop(0);
        }
    }
}

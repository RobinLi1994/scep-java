package com.example.scep.server;

import java.io.InputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x500.X500Name;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import com.example.scep.client.transport.ScepClient;
import com.example.scep.common.crypto.Crypto;
import com.example.scep.common.protocol.enums.MessageTypeEnum;
import com.example.scep.server.ca.CertificateAuthority;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 默认从 classpath 加载 CA：空的运行目录不需要先执行 ca-init，签发记录仍落到外部目录。
 * @author robin.li
 * @date 2026-11-22 12:47:14
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ClasspathCaTest {
    static final Path DEPOT;
    static {
        try {
            DEPOT = Files.createTempDirectory("scep-classpath-ca-");
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    @Autowired
    CertificateAuthority ca;

    @LocalServerPort
    int port;

    /** 仅指定可写的证书记录目录，刻意不在其中放置 CA 证书或私钥。 */
    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("scep.depot", () -> DEPOT.toString());
        registry.add("scep.challenge", () -> "resource-test-secret");
    }

    /** 独立读取资源中的证书，验证服务使用它完成真实 HTTP 注册和持久化。 */
    @Test
    void enrollsWithoutInitializingFilesystemCa() throws Exception {
        X509Certificate expected;
        try (InputStream input = getClass().getResourceAsStream("/ca/ca.pem")) {
            assertNotNull(input);
            expected = (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(input);
        }
        assertEquals(expected, ca.certificate());
        assertFalse(Files.exists(DEPOT.resolve("ca.pem")));
        assertFalse(Files.exists(DEPOT.resolve("ca.key")));
        KeyPair key = Crypto.rsa(2048);
        X509Certificate identity = Crypto.selfSigned(key, new X500Name("CN=resource-client"));
        ScepClient client = new ScepClient(URI.create("http://127.0.0.1:" + port + "/scep"), expected);
        X509Certificate issued = client.enroll(ScepServiceTest.csr(key, "CN=resource-client", "resource-test-secret"),
                key.getPrivate(), identity, MessageTypeEnum.PKCS_REQ);
        issued.verify(expected.getPublicKey());
        assertTrue(ca.isIssued(issued));
        assertTrue(Files.exists(DEPOT.resolve("issued").resolve(issued.getSerialNumber().toString(16) + ".pem")));
    }
}

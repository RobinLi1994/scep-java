package com.example.scep.server;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

import com.example.scep.common.crypto.Crypto;
import com.example.scep.common.crypto.PemFiles;
import com.example.scep.server.ca.CertificateAuthority;
import com.example.scep.server.config.ScepProperties;
import com.example.scep.server.config.ScepServerConfiguration;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 资源加载不能绕过原有 CA 校验，且不应依赖 Resource.getFile()。
 * @author robin.li
 * @date 2026-11-22 12:47:14
 */
class CaResourceValidationTest {
    @TempDir
    Path directory;

    /** 只提供字节流、没有文件路径的资源也可以加载，并且只创建签发记录目录。 */
    @Test
    void loadsResourcesWithoutFilesystemPaths() throws Exception {
        byte[] certificate;
        byte[] key;
        try (InputStream input = new ClassPathResource("ca/ca.pem").getInputStream()) {
            certificate = input.readAllBytes();
        }
        try (InputStream input = new ClassPathResource("ca/ca.key").getInputStream()) {
            key = input.readAllBytes();
        }
        CertificateAuthority ca = load(new ByteArrayResource(certificate), new ByteArrayResource(key));
        assertNotNull(ca.certificate());
        assertTrue(Files.isDirectory(directory.resolve("issued")));
        assertFalse(Files.exists(directory.resolve("ca.key")));
    }

    /** 资源缺失时给出中文配置提示，不自动生成或替换 CA。 */
    @Test
    void rejectsMissingResource() {
        IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                () -> load(new ClassPathResource("ca/not-present.pem"), new ClassPathResource("ca/ca.key")));
        assertTrue(failure.getMessage().contains("CA 证书或私钥资源不存在"));
        assertFalse(Files.exists(directory.resolve("issued")));
    }

    /** 不匹配的私钥不能通过加载检查，也不能形成可工作的 CA 实例。 */
    @Test
    void rejectsMismatchedKey() throws Exception {
        byte[] wrongKey = PemFiles.encode(Crypto.rsa(3072).getPrivate());
        assertThrows(Exception.class, () -> load(new ClassPathResource("ca/ca.pem"), new ByteArrayResource(wrongKey)));
        assertFalse(Files.exists(directory.resolve("issued")));
    }

    /** 证书内容损坏应明确拒绝，不能用空对象继续启动服务。 */
    @Test
    void rejectsInvalidPemCertificate() {
        IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                () -> load(new ByteArrayResource(new byte[] {1, 2, 3}), new ClassPathResource("ca/ca.key")));
        assertTrue(failure.getMessage().contains("PEM 格式证书"));
    }

    /** 构造最小部署配置，复用与真实 Spring Boot Bean 相同的加载入口。 */
    private CertificateAuthority load(Resource certificate, Resource privateKey) throws Exception {
        ScepProperties properties =
                new ScepProperties(directory, certificate, privateKey, "test-secret", 365, 14, false, 1048576);
        return new ScepServerConfiguration().certificateAuthority(properties);
    }
}

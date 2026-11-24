package com.example.scep.client;

import java.net.URI;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.example.scep.client.config.ScepClientProperties;
import com.example.scep.client.service.EnrollmentOptions;
import com.example.scep.client.transport.CaCapabilities;
import com.example.scep.common.protocol.enums.CapabilityEnum;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 验证普通 Lombok 类仍保持值对象的比较方式和只读集合边界。
 * @author robin.li
 * @date 2026-11-22 22:11:07
 */
class ClientValueObjectsTest {
    /** 外部集合或 getter 的使用者都不能改变已完成的算法能力判断。 */
    @Test
    void capabilitiesKeepAnImmutableSnapshot() {
        Set<String> source = new HashSet<>(Set.of("AES", "SHA-256"));
        CaCapabilities capabilities = new CaCapabilities(source);
        source.clear();
        assertTrue(capabilities.supports(CapabilityEnum.AES));
        assertThrows(UnsupportedOperationException.class, () -> capabilities.names().clear());
    }

    /** 内容相同的申请参数在 Set 中仍视为同一个值，不退化为对象引用比较。 */
    @Test
    void enrollmentOptionsRemainValues() {
        URI endpoint = URI.create("http://127.0.0.1:8080/scep");
        EnrollmentOptions first = new EnrollmentOptions(endpoint, Path.of("ca.pem"), "CN=device", Path.of("client.key"),
                Path.of("client.pem"), null, null);
        EnrollmentOptions same = new EnrollmentOptions(endpoint, Path.of("ca.pem"), "CN=device", Path.of("client.key"),
                Path.of("client.pem"), null, null);
        Set<EnrollmentOptions> options = new HashSet<>();
        options.add(first);
        options.add(same);
        assertEquals(1, options.size());
    }

    /** Lombok 的自动诊断输出不应带出配置中的注册口令。 */
    @Test
    void clientConfigurationDoesNotPrintChallenge() {
        ScepClientProperties properties = new ScepClientProperties(URI.create("http://127.0.0.1:8080/scep"),
                Path.of("ca.pem"), "CN=device", Path.of("client.key"), Path.of("client.pem"), Path.of("old.pem"),
                Path.of("old.key"), Path.of("new.key"), Path.of("new.pem"), "test-secret-not-for-logs");
        assertEquals("test-secret-not-for-logs", properties.challenge());
        assertFalse(properties.toString().contains("test-secret-not-for-logs"));
    }
}

package com.example.scep.client.transport;

import java.util.Arrays;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

import lombok.extern.slf4j.Slf4j;
import lombok.Value;
import lombok.experimental.Accessors;

import com.example.scep.common.protocol.enums.CapabilityEnum;
import com.example.scep.common.protocol.enums.MessageTypeEnum;

/**
 * GetCACaps 的能力集合：它是 HTTP 文本，不是受 CMS 签名保护的承诺。
 * <p>能力减少只会导致拒绝申请或改变传输方式，不会触发 DES/MD5 降级。</p>
 * <p>Lombok 生成只读访问方法和按字段比较的 equals/hashCode；构造器中的业务校验仍显式保留。</p>
 *
 * @author robin.li
 * @date 2026-11-22 09:48:00
 */
@Value
@Accessors(fluent = true)
@Slf4j
public class CaCapabilities {
    /**
     * 按 Locale.ROOT 规范化为大写的能力名称。
     */
    Set<String> names;

    /**
     * 保存不可变集合快照，避免外部修改导致能力检查结果在请求中途发生变化。
     */
    public CaCapabilities(Set<String> names) {
        this.names = Set.copyOf(names);
    }

    /**
     * 兼容 CRLF/LF、大小写和未知能力；按整行匹配，避免子串误判。
     *
     * @param text HTTP 能力响应文本
     * @return 不可变能力集合
     */
    public static CaCapabilities parse(String text) {
        Set<String> names = Arrays.stream(text.split("\\r?\\n")).map(String::trim).filter(line -> !line.isEmpty())
                .map(line -> line.toUpperCase(Locale.ROOT)).collect(Collectors.toSet());
        log.debug("解析 CA 能力，能力数量={}", names.size());
        return new CaCapabilities(names);
    }

    /**
     * SCEPStandard 只隐含 AES、SHA-256、POST 等最低能力，不隐含 Renewal。
     *
     * @param capability 要查询的协议能力
     * @return 是否显式声明或由 SCEPStandard 隐含
     */
    public boolean supports(CapabilityEnum capability) {
        String normalized = capability.getCode().toUpperCase(Locale.ROOT);
        return names.contains(normalized)
                || (names.contains(CapabilityEnum.SCEP_STANDARD.getCode().toUpperCase(Locale.ROOT))
                        && Set.of(CapabilityEnum.AES, CapabilityEnum.SHA256, CapabilityEnum.POST_PKI_OPERATION)
                                .contains(capability));
    }

    /**
     * 在生成并发送申请前确认现代算法和操作能力，错误信息不泄露注册口令。
     *
     * @param messageType 注册为 19，续期为 17
     * @throws IllegalArgumentException 消息类型不支持或缺少必要能力时抛出
     */
    public void requireEnrollment(MessageTypeEnum messageType) {
        log.debug("校验 CA 能力，messageType={}，能力={}", messageType.getCode(), names);
        if (messageType != MessageTypeEnum.PKCS_REQ && messageType != MessageTypeEnum.RENEWAL_REQ) {
            throw new IllegalArgumentException("客户端仅支持初始注册（19）和续期（17）");
        }
        if (!supports(CapabilityEnum.AES) || !supports(CapabilityEnum.SHA256)) {
            throw new IllegalArgumentException("服务端未声明 AES 和 SHA-256 能力，已停止申请，不降级到旧算法");
        }
        if (messageType == MessageTypeEnum.RENEWAL_REQ && !supports(CapabilityEnum.RENEWAL)) {
            throw new IllegalArgumentException("服务端未声明 Renewal 能力，不能执行续期");
        }
    }
}

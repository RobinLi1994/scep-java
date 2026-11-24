package com.example.scep.server;

import org.junit.jupiter.api.Test;

import com.example.scep.common.protocol.ScepCodec;
import com.example.scep.common.protocol.enums.MessageTypeEnum;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * 验证协议上下文改为普通类后仍保留数组所有权和原有比较方式。
 * @author robin.li
 * @date 2026-11-22 22:11:07
 */
class ProtocolValueObjectsTest {
    /** 不能通过构造参数或 getter 的返回数组修改请求与 nonce 的保存快照。 */
    @Test
    void requestProtectsInputAndOutputArrays() {
        byte[] encoded = {1, 2, 3};
        byte[] nonce = {4, 5, 6};
        ScepCodec.Request request = new ScepCodec.Request(encoded, "transaction", nonce);
        encoded[0] = 9;
        nonce[0] = 9;
        request.encoded()[1] = 9;
        request.nonce()[1] = 9;
        assertArrayEquals(new byte[] {1, 2, 3}, request.encoded());
        assertArrayEquals(new byte[] {4, 5, 6}, request.nonce());
        assertEquals("transaction", request.transactionId());
    }

    /** 相等性不应因为 Lombok 默认使用数组深比较而改变。 */
    @Test
    void messageKeepsArrayIdentityComparison() {
        byte[] nonce = {1};
        byte[] content = {2};
        ScepCodec.Message first = new ScepCodec.Message("transaction", MessageTypeEnum.PKCS_REQ, nonce, null, content);
        ScepCodec.Message same = new ScepCodec.Message("transaction", MessageTypeEnum.PKCS_REQ, nonce, null, content);
        ScepCodec.Message copied =
                new ScepCodec.Message("transaction", MessageTypeEnum.PKCS_REQ, nonce.clone(), null, content.clone());
        assertEquals(first, same);
        assertEquals(first.hashCode(), same.hashCode());
        assertNotEquals(first, copied);
    }
}

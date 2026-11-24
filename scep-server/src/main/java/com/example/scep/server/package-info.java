/**
 * 面向 Java 开发者的 SCEP 学习实现。
 *
 * <p>推荐先读 {@link ScepService#handle(byte[])} 了解服务端处理顺序，
 * 再读 {@link ScepCodec} 理解 CMS 结构，最后读
 * {@link CertificateAuthority} 理解证书签发。</p>
 * <p>从客户端开始则读 客户端模块中的 EnrollmentService，跟踪新旧密钥的选择，
 * 然后进入 ScepClient。HTTP 参数和 MIME 由
 * {@link ScepController} 负责。</p>
 *
 * <p>最重要的阅读区分：密码验签、身份授权、证书签发是三个不同步骤；
 * HTTP operation、CMS messageType、响应 pkiStatus 也是三个不同层次的字段。</p>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc8894.html">RFC 8894</a>
 * @author robin.li
 * @date 2026-11-20 21:52:59
 */
package com.example.scep.server;

import com.example.scep.common.protocol.ScepCodec;
import com.example.scep.server.ca.CertificateAuthority;
import com.example.scep.server.service.ScepService;
import com.example.scep.server.web.ScepController;

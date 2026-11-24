package com.example.scep.server.web;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.util.Base64;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.example.scep.common.protocol.ScepConstants;
import com.example.scep.common.protocol.enums.CapabilityEnum;
import com.example.scep.server.ca.CertificateAuthority;
import com.example.scep.server.config.ScepProperties;
import com.example.scep.server.service.ScepService;

/**
 * SCEP 的 HTTP 适配层，将查询参数/请求体转换成协议层需要的字节数组。
 *
 * <p>operation 决定 HTTP 操作（例如 PKIOperation）；注册还是续期由 CMS 中签名保护的
 * messageType 决定。HTTP 200 只表示收到正常协议响应，证书是否签发必须看 CertRep 的 pkiStatus。</p>
 * <p>此层负责 MIME、Base64 和大小限制，不应在这里直接解析 CSR 或作签发授权。</p>
 * <p>四个处理方法共享 /scep 地址，Spring 根据 HTTP 方法和 operation 参数选择入口；
 * GET/POST 的消息读取各自处理，解码后的字节交给同一协议处理方法。</p>
 *
 * @author robin.li
 * @date 2026-11-20 21:52:59
 */
@Slf4j
@ConditionalOnWebApplication
@RestController
@RequestMapping("/scep")
public class ScepController {

    /**
     * 能力发现是换行分隔的文本；只声明实际实现的能力，不等于客户端一定会按它协商算法。
     */
    private static final String CAPS = Stream
            .of(CapabilityEnum.RENEWAL, CapabilityEnum.SHA1, CapabilityEnum.SHA256, CapabilityEnum.AES,
                    CapabilityEnum.DES3, CapabilityEnum.POST_PKI_OPERATION)
            .map(CapabilityEnum::getCode).collect(Collectors.joining("\n", "", "\n"));

    /**
     * Base64 每组 3 个输入字节编码为 4 个字符；不足一组时向上取整。
     */
    private static final int BASE64_INPUT_BYTES = 3;

    private static final int BASE64_OUTPUT_CHARS = 4;

    private static final String INVALID_OPERATION_MESSAGE = "必须且只能提供一个 operation 参数";

    private static final String MESSAGE_TOO_LARGE = "SCEP 报文超过大小限制";

    private final ScepService service;

    private final CertificateAuthority ca;

    private final int maxBytes;

    /**
     * 由 Spring 注入协议服务、CA 和传输限制。
     *
     * @param service    负责消息处理与签发策略的服务
     * @param ca         用于 GetCACert 的单张 CA 证书来源
     * @param properties 请求体大小等配置
     */
    public ScepController(ScepService service, CertificateAuthority ca, ScepProperties properties) {
        this.service = service;
        this.ca = ca;
        this.maxBytes = properties.maxRequestBytes();
    }

    /**
     * 生成 HTTP 层文本错误；这些字节不是 SCEP CertRep。
     *
     * @param status  HTTP 状态码
     * @param message 不包含私钥、口令或内部堆栈的错误说明
     * @return 文本错误响应
     */
    private static ResponseEntity<byte[]> error(HttpStatus status, String message) {
        return response(status, "text/plain;charset=UTF-8", message.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * 统一设置 MIME 和禁止缓存，直接返回协议二进制，避免被 JSON 序列化器再次编码。
     *
     * @param status HTTP 状态码
     * @param type   媒体类型
     * @param bytes  响应体原始字节
     * @return Spring MVC 响应对象
     */
    private static ResponseEntity<byte[]> response(HttpStatus status, String type, byte[] bytes) {
        return ResponseEntity.status(status).contentType(MediaType.parseMediaType(type))
                .cacheControl(CacheControl.noStore()).body(bytes);
    }

    /**
     * 检查操作参数唯一性，防止不同 HTTP 组件对重复值作出不同选择。
     *
     * @param request 当前 HTTP 请求
     * @return operation 恰好出现一次时返回 true
     */
    private static boolean hasSingleOperation(HttpServletRequest request) {
        // Spring 的 params 路由只匹配值，不保证参数唯一；每个入口仍需此检查。
        String[] operations = request.getParameterValues(ScepConstants.OPERATION_PARAMETER);
        return operations == null || operations.length != 1;
    }

    /**
     * 返回当前服务支持的算法及操作能力。
     *
     * @param request 用于检查 operation 是否恰好出现一次
     * @return 换行分隔的能力文本，或参数错误
     */
    @GetMapping(params = ScepConstants.OPERATION_PARAMETER + "=" + ScepConstants.GET_CA_CAPS_OPERATION)
    public ResponseEntity<byte[]> getCaCapabilities(HttpServletRequest request) {
        log.info("收到 GetCACaps 请求，来源={}", request.getRemoteAddr());
        if (hasSingleOperation(request)) {
            return error(HttpStatus.BAD_REQUEST, INVALID_OPERATION_MESSAGE);
        }
        // 能力列表是纯文本，不是 JSON，也不是经过签名的 CMS。
        return response(HttpStatus.OK, MediaType.TEXT_PLAIN_VALUE, CAPS.getBytes(StandardCharsets.US_ASCII));
    }

    /**
     * 提供客户端后续加密所需的 CA 证书；下载证书本身并不建立信任。
     *
     * @param request 用于检查 operation 是否恰好出现一次
     * @return DER 编码的单张 CA 证书，或参数错误
     * @throws CertificateEncodingException CA 证书编码失败时抛出，由全局处理器返回内部错误
     */
    @GetMapping(params = ScepConstants.OPERATION_PARAMETER + "=" + ScepConstants.GET_CA_CERT_OPERATION)
    public ResponseEntity<byte[]> getCaCertificate(HttpServletRequest request) throws CertificateEncodingException {
        log.info("收到 GetCACert 请求，来源={}", request.getRemoteAddr());
        if (hasSingleOperation(request)) {
            return error(HttpStatus.BAD_REQUEST, INVALID_OPERATION_MESSAGE);
        }
        // 单张 CA 直接返回 DER X.509；多张 CA/RA 的 PKCS#7 响应不在当前实现范围内。
        return response(HttpStatus.OK, ScepConstants.CA_CERT_MEDIA_TYPE, ca.certificate().getEncoded());
    }

    /**
     * 接收通过 URL 编码的 Base64 报文，解码后进入共用的协议处理流程。
     *
     * @param request message 参数携带 CMS 报文
     * @return 签名 CertRep 或 HTTP 层错误
     */
    @GetMapping(params = ScepConstants.OPERATION_PARAMETER + "=" + ScepConstants.PKI_OPERATION)
    public ResponseEntity<byte[]> pkiOperationGet(HttpServletRequest request) {
        log.info("收到 PKIOperation GET 请求，来源={}", request.getRemoteAddr());
        if (hasSingleOperation(request)) {
            return error(HttpStatus.BAD_REQUEST, INVALID_OPERATION_MESSAGE);
        }
        // GET 把 CMS 先 Base64 再 URL 编码放入 message；Servlet 已完成 URL 解码，此处只解 Base64。
        String[] messages = request.getParameterValues(ScepConstants.MESSAGE_PARAMETER);
        if (messages == null || messages.length != 1) {
            return error(HttpStatus.BAD_REQUEST, "必须且只能提供一个 message 参数");
        }
        // Base64 每 3 字节最多变成 4 个字符；先限制文本长度，再在解码后复核真实字节数。
        if (messages[0].length() > ((maxBytes + BASE64_INPUT_BYTES - 1) / BASE64_INPUT_BYTES) * BASE64_OUTPUT_CHARS) {
            return error(HttpStatus.CONTENT_TOO_LARGE, MESSAGE_TOO_LARGE);
        }
        byte[] body;
        try {
            // 部分旧设备未转义 '+'；Servlet 已将其解析为空格。
            //body = Base64.getDecoder().decode(messages[0].replace(' ', '+'));
            // 旧版 sscep 的 Base64 带 CR/LF；只去除换行，其他非法字符仍由严格解码器拒绝。
            String encodedMessage = messages[0]
                    .replace("\r", "")
                    .replace("\n", "")
                    .replace(' ', '+');
            body = Base64.getDecoder().decode(encodedMessage);
        } catch (IllegalArgumentException e) {
            log.warn("PKIOperation GET 的 message 参数不是有效的 Base64，来源={}", request.getRemoteAddr(), e);
            return error(HttpStatus.BAD_REQUEST, "message 参数不是有效的 Base64 编码");
        }
        return processPkiMessage(body);
    }

    /**
     * 接收原始 CMS 字节；有界读取避免未知长度请求占用无限内存。
     *
     * @param request POST 的 body 为原始 CMS 字节，不再做 Base64 解码
     * @return 签名 CertRep 或 HTTP 层错误
     * @throws IOException 请求流读取失败时抛出，由全局处理器转换 HTTP 错误
     */
    @PostMapping(params = ScepConstants.OPERATION_PARAMETER + "=" + ScepConstants.PKI_OPERATION)
    public ResponseEntity<byte[]> pkiOperationPost(HttpServletRequest request) throws IOException {
        log.info("收到 PKIOperation POST 请求，来源={}，Content-Length={}", request.getRemoteAddr(),
                request.getContentLengthLong());
        if (hasSingleOperation(request)) {
            return error(HttpStatus.BAD_REQUEST, INVALID_OPERATION_MESSAGE);
        }
        // 已知长度超限时尽早拒绝；未知长度一般为 -1，后面仍须通过实际读取量检查。
        if (request.getContentLengthLong() > maxBytes) {
            return error(HttpStatus.CONTENT_TOO_LARGE, MESSAGE_TOO_LARGE);
        }
        String contentType = request.getContentType();
        String type = contentType == null ? "" : contentType.split(";", 2)[0].trim();
        // 不在注解中限定 consumes：兼容使用 octet-stream 或省略 Content-Type 的客户端。
        if (!type.isEmpty() && !type.equalsIgnoreCase(ScepConstants.PKI_MESSAGE_MEDIA_TYPE)
                && !type.equalsIgnoreCase(MediaType.APPLICATION_OCTET_STREAM_VALUE)) {
            return error(HttpStatus.UNSUPPORTED_MEDIA_TYPE,
                    "请求媒体类型必须为 application/x-pki-message 或 application/octet-stream");
        }
        // 多读 1 字节用来判断越界；不能只信 Content-Length，因为 chunked 请求没有这个头。
        byte[] body = request.getInputStream().readNBytes(maxBytes + 1);
        return processPkiMessage(body);
    }

    /**
     * 承接未匹配到具体操作的 GET/POST，保留中文错误及原有状态码。
     *
     * @param request 缺失、未知操作或操作与 HTTP 方法不匹配的请求
     * @return HTTP 层文本错误
     */
    @RequestMapping(method = {RequestMethod.GET, RequestMethod.POST})
    public ResponseEntity<byte[]> unsupportedOperation(HttpServletRequest request) {
        log.warn("收到不支持的 SCEP HTTP 请求，方法={}，来源={}", request.getMethod(), request.getRemoteAddr());
        // 带 params 的方法更具体，会被优先选择；此兜底方法不是第二次业务分发。
        if (hasSingleOperation(request)) {
            return error(HttpStatus.BAD_REQUEST, INVALID_OPERATION_MESSAGE);
        }
        if (HttpMethod.POST.matches(request.getMethod())) {
            return error(HttpStatus.METHOD_NOT_ALLOWED, "POST 仅支持 PKIOperation 操作");
        }
        return error(HttpStatus.BAD_REQUEST, "不支持该 SCEP 操作");
    }

    /**
     * 在 GET/POST 共用的边界复核报文，再将协议结果转换为 HTTP 响应。
     *
     * @param body 已从传输层还原的 CMS 字节
     * @return 签名 CertRep，或无法形成可信协议响应时的 HTTP 错误
     */
    private ResponseEntity<byte[]> processPkiMessage(byte[] body) {
        log.debug("进入 SCEP 协议处理，报文大小={} 字节", body.length);
        if (body.length > maxBytes) {
            return error(HttpStatus.CONTENT_TOO_LARGE, MESSAGE_TOO_LARGE);
        }
        if (body.length == 0) {
            return error(HttpStatus.BAD_REQUEST, "SCEP 报文不能为空");
        }
        try {
            // 正常传回一个 CertRep 就返回 HTTP 200，包括 pkiStatus=FAILURE 的业务拒绝结果。
            byte[] result = service.handle(body);
            log.info("SCEP 协议处理完成，响应大小={} 字节", result.length);
            return response(HttpStatus.OK, ScepConstants.PKI_MESSAGE_MEDIA_TYPE, result);
        } catch (IllegalArgumentException e) {
            // 外层格式或签名不可信时，无法构造可信的协议回复上下文，用 HTTP 400 表达请求错误。
            log.warn("SCEP 报文格式或签名无效，报文大小={} 字节", body.length, e);
            return error(HttpStatus.BAD_REQUEST, "SCEP 报文格式或签名无效");
        } catch (Exception e) {
            // CA/存储等内部故障使用 HTTP 500，客户端不能把它误认为签发成功或正常的授权拒绝。
            log.error("SCEP 签发失败，报文大小={} 字节", body.length, e);
            return error(HttpStatus.INTERNAL_SERVER_ERROR, "SCEP 服务处理失败");
        }
    }
}

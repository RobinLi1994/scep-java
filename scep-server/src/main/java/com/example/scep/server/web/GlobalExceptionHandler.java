package com.example.scep.server.web;

import java.nio.charset.StandardCharsets;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.ErrorResponse;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * HTTP 全局异常出口：中文 UTF-8 文本并保留框架状态码，不把内部异常暴露给申请者。
 * <p>正常的 SCEP 授权拒绝仍是 HTTP 200 加签名 CertRep FAILURE，不在此转换成 HTTP 错误。</p>
 *
 * @author robin.li
 * @date 2026-11-22 09:50:00
 */
@Slf4j
@RestControllerAdvice
@ConditionalOnWebApplication
public class GlobalExceptionHandler {

    /**
     * 捕获控制器及路由异常，不覆盖框架对 404、405 等错误的分类。
     *
     * @param failure 控制器或路由层异常
     * @return 保留状态和必要响应头的中文文本错误
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<byte[]> handle(Exception failure) {
        HttpStatusCode status =
                failure instanceof ErrorResponse error ? error.getStatusCode() : HttpStatus.INTERNAL_SERVER_ERROR;
        // resolve 可能返回 null（扩展 HTTP 状态）；保留原始状态码，文字使用通用说明。
        HttpStatus knownStatus = HttpStatus.resolve(status.value());
        String message = status.is5xxServerError() ? "服务处理失败，请稍后重试" : "请求无法处理，请检查接口及参数";
        if (knownStatus != null) {
            message = switch (knownStatus) {
                case BAD_REQUEST -> "请求参数或报文格式不正确";
                case NOT_FOUND -> "请求的接口不存在";
                case METHOD_NOT_ALLOWED -> "该接口不支持此 HTTP 方法";
                case NOT_ACCEPTABLE -> "接口无法提供请求指定的响应格式";
                case CONTENT_TOO_LARGE -> "请求内容超过大小限制";
                case UNSUPPORTED_MEDIA_TYPE -> "不支持该请求媒体类型";
                default -> message;
            };
        }
        if (status.is5xxServerError()) {
            // 服务故障在最终边界记录堆栈；HTTP 响应仍只包含上面的通用中文提示。
            log.error("HTTP 请求处理失败，状态码={}", status.value(), failure);
        }
        return ResponseEntity.status(status)
                .headers(failure instanceof ErrorResponse error ? error.getHeaders() : HttpHeaders.EMPTY)
                .contentType(new MediaType("text", "plain", StandardCharsets.UTF_8))
                .cacheControl(CacheControl.noStore()).body(message.getBytes(StandardCharsets.UTF_8));
    }
}

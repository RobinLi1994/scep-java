package com.example.scep.common.shell;

import java.io.IOException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.NoSuchFileException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;

/**
 * 将底层异常转换为用户可读的中文；保留原异常供调用方排查，不直接展示第三方英文堆栈。
 * @author robin.li
 * @date 2026-11-22 09:50:00
 */
public final class UserMessages {
    private UserMessages() {
    }

    /**
     * 穿过 Spring 反射包装查找应用错误，避免把敏感参数或服务端正文作为错误提示输出。
     * @param failure 原异常，可包含多层 cause
     * @return 面向用户的中文说明，不附带堆栈
     */
    public static String describe(Throwable failure) {
        Throwable current = failure;
        String fallback = "操作失败，请检查参数、证书、密钥及运行配置";
        while (current != null) {
            StackTraceElement[] trace = current.getStackTrace();
            String message = current.getMessage();
            if (trace.length > 0 && trace[0].getClassName().startsWith("com.example.scep.") && message != null
                    && message.matches("(?s).*[\\p{IsHan}].*")) {
                return message;
            }
            if (current instanceof NoSuchFileException) {
                fallback = "文件不存在，请检查证书、私钥或 CA 存储目录";
            } else if (current instanceof FileAlreadyExistsException) {
                fallback = "目标文件已存在，不能覆盖，请使用新的输出路径";
            } else if (current instanceof CertificateExpiredException) {
                fallback = "证书已过期，请检查可信 CA 或身份凭证";
            } else if (current instanceof CertificateNotYetValidException) {
                fallback = "证书尚未生效，请检查证书有效期和系统时间";
            } else if (current instanceof NumberFormatException) {
                fallback = "数字参数格式不正确，请使用整数";
            } else if (current instanceof IOException) {
                fallback = "文件或网络读写失败，请检查路径、权限及服务连接";
            } else if (current instanceof IllegalArgumentException) {
                fallback = "参数或报文格式不正确，请使用 help 查看命令参数";
            }
            current = current.getCause();
        }
        return fallback;
    }
}

package com.example.scep.common.crypto;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Set;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import com.example.scep.common.crypto.Crypto;

/**
 * PEM 文件读写，与 SCEP 网络消息的 DER 编码分开处理。
 * <p>DER 是 ASN.1 二进制；PEM 通常是 DER 的 Base64 文本加 BEGIN/END 标记。
 * Base64 不是加密，本类写出的私钥 PEM 未加密，因此在 POSIX 上以 0600 权限创建。</p>
 *
 * @author robin.li
 * @date 2026-11-20 21:52:59
 */
@Slf4j
public final class PemFiles {
    private PemFiles() {
    }

    /**
     * 将文件中的第一张 PEM 证书转换成 JCA X509Certificate；此处不验证它是否可信。
     *
     * @param path PEM 文件路径
     * @return 解析后的证书
     * @throws Exception 文件不可读、首个 PEM 对象不是证书或转换失败时抛出
     */
    public static X509Certificate certificate(Path path) throws Exception {
        try (InputStream input = Files.newInputStream(path)) {
            X509Certificate certificate = certificate(input);
            log.debug("加载 PEM 证书，路径={}，subject={}，序列号={}", path.toAbsolutePath(),
                    certificate.getSubjectX500Principal().getName(), certificate.getSerialNumber().toString(16));
            return certificate;
        }
    }

    /**
     * 从流读取 PEM 证书，支持 JAR 内的 classpath 资源，不要求存在文件系统路径。
     * @param input PEM 输入流，本方法读取完毕后关闭它
     * @return 解析后的证书，信任与用途由调用方校验
     * @throws Exception 格式不正确、读取或转换失败时抛出
     */
    public static X509Certificate certificate(InputStream input) throws Exception {
        Object object = read(input);
        if (!(object instanceof X509CertificateHolder holder)) {
            throw new IllegalArgumentException("输入内容必须包含 PEM 格式证书");
        }
        return new JcaX509CertificateConverter().setProvider(Crypto.PROVIDER).getCertificate(holder);
    }

    /**
     * 读取未加密的私钥，兼容传统 RSA PEM 和通用 PKCS#8 PrivateKeyInfo。
     *
     * @param path 私钥 PEM 路径
     * @return JCA 私钥对象，不能输出到日志或网络
     * @throws Exception 文件不可读、格式不支持或转换失败时抛出
     */
    public static PrivateKey privateKey(Path path) throws Exception {
        try (InputStream input = Files.newInputStream(path)) {
            PrivateKey key = privateKey(input);
            log.debug("加载 PEM 私钥，路径={}，算法={}", path.toAbsolutePath(), key.getAlgorithm());
            return key;
        }
    }

    /**
     * 从流读取未加密 PEM 私钥；资源流不会转换为临时私钥文件。
     * @param input 私钥输入流，本方法读取完毕后关闭它
     * @return 私钥对象，仅供签名及解密使用
     * @throws Exception 格式不支持、读取或转换失败时抛出
     */
    public static PrivateKey privateKey(InputStream input) throws Exception {
        Object object = read(input);
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(Crypto.PROVIDER);
        // 传统 BEGIN RSA PRIVATE KEY 可解析成 PEMKeyPair；这里只取私钥，公钥可由 RSA 参数恢复。
        if (object instanceof PEMKeyPair pair) {
            return converter.getKeyPair(pair).getPrivate();
        }
        // BEGIN PRIVATE KEY 对应通用 PKCS#8；此分支不处理 BEGIN ENCRYPTED PRIVATE KEY。
        if (object instanceof PrivateKeyInfo info) {
            return converter.getPrivateKey(info);
        }
        throw new IllegalArgumentException("输入内容必须包含未加密的 PKCS#8 或 RSA PEM 私钥");
    }

    /**
     * 根据 PEM 标记判断对象类型，只读取第一个对象，不代表支持证书链导入。
     *
     * @param input PEM 输入流，读取后关闭
     * @return BC 解析对象；空文件可能返回 null，由上层作类型检查
     * @throws Exception 文件读取或 PEM 解析失败时抛出
     */
    private static Object read(InputStream input) throws Exception {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.US_ASCII));
                PEMParser parser = new PEMParser(reader)) {
            return parser.readObject();
        }
    }

    /**
     * 把 BC/JCA 支持的证书或私钥编码为 PEM 文本字节。
     *
     * @param value 待编码对象
     * @return ASCII PEM 字节，不包含额外加密保护
     * @throws Exception 对象不支持或编码失败时抛出
     */
    public static byte[] encode(Object value) throws Exception {
        StringWriter text = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(text)) {
            writer.writeObject(value);
        }
        return text.toString().getBytes(StandardCharsets.US_ASCII);
    }

    /**
     * 以 CREATE_NEW 创建 PEM 文件，拒绝覆盖，并在同一文件通道中完成写入。
     *
     * @param path   目标文件路径；缺失的父目录会自动创建
     * @param value  要保存的证书或私钥
     * @param secret 是否为私密材料；支持 POSIX 时在创建瞬间设置 0600
     * @throws Exception 编码失败、文件已存在、权限不足或写入失败时抛出
     */
    public static void create(Path path, Object value, boolean secret) throws Exception {
        byte[] bytes = encode(value);
        Path parent = path.toAbsolutePath().getParent();
        Files.createDirectories(parent);
        // POSIX 上在创建文件的瞬间就设为仅所有者可读写，避免“先写私钥、再收紧权限”的时间窗口。
        FileAttribute<?>[] attributes = secret && Files.getFileStore(parent).supportsFileAttributeView("posix")
                ? new FileAttribute<?>[] {
                        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))}
                : new FileAttribute<?>[0];
        // CREATE_NEW 将“必须不存在”的检查与创建合并，避免 exists 检查后目标被其他进程创建的竞态。
        try (FileChannel channel =
                FileChannel.open(path, Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE), attributes)) {
            // write 不保证一次写完；force 请求刷新数据和元信息，但不能把多个文件变成原子事务。
            ByteBuffer buffer = ByteBuffer.wrap(bytes);
            while (buffer.hasRemaining()) {
                channel.write(buffer);
            }
            channel.force(true);
        }
        log.debug("写入 PEM 文件，路径={}，类型={}，敏感材料={}", path.toAbsolutePath(), value.getClass().getSimpleName(),
                secret);
    }
}

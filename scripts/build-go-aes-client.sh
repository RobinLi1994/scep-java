#!/usr/bin/env bash
set -euo pipefail

# 在隔离目录构建参考 Go 客户端，唯一协议调整是将单 DES 改为 AES-128-CBC。
# 不修改传入的源码目录；输出明确标记为 AES 适配版，不能称为未修改的原客户端。
SOURCE=${1:?请提供固定提交版本的参考 Go 客户端源码目录}
OUTPUT=${2:?请提供输出可执行文件的绝对路径}
COMMIT=9902c1a3549891d080e9b4d476e37fb2f8ae22ff
[[ "$OUTPUT" = /* ]] || { echo '输出路径必须是绝对路径' >&2; exit 1; }
[[ $(git -C "$SOURCE" rev-parse HEAD) == "$COMMIT" ]] || { echo '参考源码提交不匹配' >&2; exit 1; }
WORK=$(mktemp -d "${TMPDIR:-/tmp}/scep-go-aes.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
# git archive 只导出固定提交，忽略源目录中可能存在的工作区修改。
git -C "$SOURCE" archive "$COMMIT" | tar -x -C "$WORK"
cat > "$WORK/cmd/scepclient/aes_interop.go" <<'GO'
package main

import "github.com/smallstep/pkcs7"

// 仅用于 RFC 8894 互通验证：不放宽 Java 服务端的算法限制。
func init() {
    pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES128CBC
}
GO
(cd "$WORK" && go build -mod=mod -o "$OUTPUT" ./cmd/scepclient)
echo "已构建 AES 适配版 Go 客户端：$OUTPUT"

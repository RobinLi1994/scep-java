#!/usr/bin/env bash
set -euo pipefail

# 直接运行交付 JAR，验证 Spring Shell 绑定与操作系统进程退出码。
ROOT=$(cd "$(dirname "$0")/.." && pwd)
SERVER="$ROOT/scep-server/target/scep-server-1.0.0-exec.jar"
CLIENT="$ROOT/scep-client/target/scep-client-1.0.0-exec.jar"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/scep-shell.XXXXXX")

# 用户提示与诊断日志分别验证：异常堆栈写入文件，不参与中文控制台提示的检查。
export LOGGING_FILE_NAME="$WORK/diagnostics.log"
export LOGGING_PATTERN_CONSOLE="%nopex"

expect_failure() {
  local name=$1
  shift
  if "$@" > "$WORK/$name.log" 2>&1; then
    echo "应失败的命令返回了成功：$name" >&2
    exit 1
  fi
  rg -q '错误：' "$WORK/$name.log"
  if rg -q 'Exception|Unable to|Failed to|Unknown command' "$WORK/$name.log"; then
    echo "错误输出泄露了英文异常：$name" >&2
    exit 1
  fi
}

java -jar "$CLIENT" help > "$WORK/client-help.log"
java -jar "$SERVER" ca-init --help > "$WORK/server-help.log"
expect_failure unknown java -jar "$CLIENT" missing-command
expect_failure removed-alias java -jar "$CLIENT" client
expect_failure enroll-renewal java -jar "$CLIENT" enroll --renew-from=old.pem
expect_failure enroll-signing-key java -jar "$CLIENT" enroll --signing-key=old.key
expect_failure missing java -jar "$CLIENT" renew "--renew-from=$WORK/missing.pem"
expect_failure typo java -jar "$CLIENT" enroll --typo=value
expect_failure duplicate java -jar "$CLIENT" enroll --out=a --out=b
expect_failure parse java -jar "$CLIENT" enroll --out
expect_failure numeric java -jar "$SERVER" ca-init --bits=abc
expect_failure server-typo java -jar "$SERVER" ca-init --typo=value
expect_failure server-duplicate java -jar "$SERVER" ca-init --bits=2048 --bits=4096
expect_failure range java -jar "$SERVER" ca-init --bits=1024
expect_failure no-file java -jar "$CLIENT" enroll "--ca=$WORK/missing.pem"

# 带空格的路径与主题可验证 argv 在进入 Shell 解析器前没有丢失分组。
java -jar "$SERVER" ca-init "--depot=$WORK/CA with spaces" '--subject=CN=Shell Test,O=Example' \
  --bits 2048 --days 30 > "$WORK/ca-init.log"
openssl x509 -in "$WORK/CA with spaces/ca.pem" -noout -subject > "$WORK/subject.log"
rg -q 'Shell Test' "$WORK/subject.log"
expect_failure overwrite java -jar "$SERVER" ca-init "--depot=$WORK/CA with spaces"

# 交互会话中错误命令不终止进程，后续 help 仍可执行；不依赖真实 TTY。
printf 'missing-command\nhelp\nexit\n' | java -jar "$CLIENT" > "$WORK/client-interactive.log"
rg -q '错误：未知命令' "$WORK/client-interactive.log"
rg -q 'enroll' "$WORK/client-interactive.log"
rg -q '已退出' "$WORK/client-interactive.log"
printf 'help\nexit\n' | java -jar "$SERVER" shell > "$WORK/server-interactive.log"
rg -q 'ca-init' "$WORK/server-interactive.log"
rg -q '已退出' "$WORK/server-interactive.log"
rg -q '命令执行异常' "$WORK/diagnostics.log"
rg -q 'at com.example.scep.common.shell.CommandConsole.execute' "$WORK/diagnostics.log"
echo '验证通过：命令帮助、中文错误、异常堆栈、非零退出码、空格参数、CA 防覆盖及双端交互会话。'
echo "证据目录：$WORK"

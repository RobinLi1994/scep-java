#!/usr/bin/env bash
set -euo pipefail

# 从空的工作目录启动打包后的 JAR；整个流程不调用 ca-init。
ROOT=$(cd "$(dirname "$0")/.." && pwd)
SERVER="$ROOT/scep-server/target/scep-server-1.0.0-exec.jar"
CLIENT="$ROOT/scep-client/target/scep-client-1.0.0-exec.jar"
CERT="$ROOT/scep-server/src/main/resources/ca/ca.pem"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/scep-resource.XXXXXX")
PORT=${SCEP_RESOURCE_TEST_PORT:-18081}
export SCEP_CHALLENGE
SCEP_CHALLENGE=$(openssl rand -hex 24)
SERVER_PID=
cleanup() {
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT
(
  cd "$WORK"
  # 显式验证 classpath 默认位置，不依赖测试者原有环境中的 CA 覆盖变量。
  export SCEP_CA_CERTIFICATE=classpath:ca/ca.pem SCEP_CA_PRIVATE_KEY=classpath:ca/ca.key
  export SCEP_DEPOT="$WORK/records" SCEP_PORT="$PORT" SCEP_RENEWAL_DAYS=0
  exec java -jar "$SERVER"
) > "$WORK/server.log" 2>&1 &
SERVER_PID=$!
URL="http://127.0.0.1:$PORT/scep"
READY=false
for ((i=0; i<40; i++)); do
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then cat "$WORK/server.log"; exit 1; fi
  if curl -fsS "$URL?operation=GetCACert" -o "$WORK/ca.der" 2>/dev/null; then
    openssl x509 -in "$CERT" -outform DER -out "$WORK/expected.der"
    if cmp -s "$WORK/ca.der" "$WORK/expected.der"; then READY=true; break; fi
  fi
  sleep 1
done
[[ "$READY" == true ]] || { cat "$WORK/server.log"; exit 1; }
# 使用真实外部 YAML 提供客户端全部配置，验证裸 enroll / renew 命令。
cat > "$WORK/client.yml" <<YAML
scep:
  client:
    url: "$URL"
    ca: "$CERT"
    subject: "CN=resource-device"
    key: "$WORK/client.key"
    out: "$WORK/client.pem"
    challenge: "$SCEP_CHALLENGE"
    renew-from: "$WORK/client.pem"
    signing-key: "$WORK/client.key"
    renew-key: "$WORK/new.key"
    renew-out: "$WORK/renewed.pem"
YAML
(
  # 取消环境口令，证明工作流确实使用 YAML 注入值，而非直接读取 System.getenv。
  unset SCEP_CHALLENGE
  export SPRING_CONFIG_ADDITIONAL_LOCATION="file:$WORK/client.yml"
  java -jar "$CLIENT" enroll > "$WORK/enroll.log"
  java -jar "$CLIENT" renew > "$WORK/renew.log"
)
openssl verify -CAfile "$CERT" "$WORK/client.pem"
openssl verify -CAfile "$CERT" "$WORK/renewed.pem"
openssl x509 -in "$WORK/client.pem" -noout -subject | rg -q 'resource-device'
[[ -f "$WORK/new.key" ]]
[[ $(openssl x509 -in "$WORK/client.pem" -noout -serial) != $(openssl x509 -in "$WORK/renewed.pem" -noout -serial) ]]
[[ ! -e "$WORK/records/ca.pem" && ! -e "$WORK/records/ca.key" ]]
[[ -d "$WORK/records/issued" ]]
echo '验证通过：服务端直接读取内置 CA；客户端仅用 YAML 完成注册与换钥续期，签发记录写入外部目录。'
echo "证据目录：$WORK"

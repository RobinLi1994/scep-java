#!/usr/bin/env bash
set -euo pipefail

# 使用 AES 适配版 Go 客户端验证 Java 服务；Java 永久拒绝单 DES。
ROOT=$(cd "$(dirname "$0")/.." && pwd)
GO_CLIENT=${1:?用法：bash scripts/interop-go.sh /绝对路径/scepclient-aes}
SERVER_JAR="$ROOT/scep-server/target/scep-server-1.0.0-exec.jar"
CLIENT_JAR="$ROOT/scep-client/target/scep-client-1.0.0-exec.jar"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/scep-interop.XXXXXX")
PORT=${SCEP_INTEROP_PORT:-18080}
export SCEP_CHALLENGE
SCEP_CHALLENGE=$(openssl rand -hex 24)
SERVER_PID=
cleanup() {
  if [[ -n "$SERVER_PID" ]]; then kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; fi
}
trap cleanup EXIT

[[ -f "$SERVER_JAR" && -f "$CLIENT_JAR" ]] || { echo '请先运行 mvn package 构建两个可执行 JAR' >&2; exit 1; }
[[ -x "$GO_CLIENT" ]] || { echo 'Go 客户端路径必须指向可执行文件' >&2; exit 1; }
java -jar "$SERVER_JAR" ca-init "--depot=$WORK/depot" --subject=CN=Interop-CA --bits=2048 > "$WORK/ca.log"
SCEP_CA_CERTIFICATE="file:$WORK/depot/ca.pem" SCEP_CA_PRIVATE_KEY="file:$WORK/depot/ca.key" \
SCEP_DEPOT="$WORK/depot" SCEP_PORT="$PORT" SCEP_RENEWAL_DAYS=0 \
  java -jar "$SERVER_JAR" > "$WORK/server.log" 2>&1 &
SERVER_PID=$!
URL="http://127.0.0.1:$PORT/scep"
READY=false
for ((i=0; i<40; i++)); do
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then cat "$WORK/server.log"; exit 1; fi
  if curl -fsS "$URL?operation=GetCACert" -o "$WORK/served-ca.der" 2>/dev/null; then
    openssl x509 -in "$WORK/depot/ca.pem" -outform DER -out "$WORK/expected-ca.der"
    if cmp -s "$WORK/served-ca.der" "$WORK/expected-ca.der"; then READY=true; break; fi
  fi
  sleep 1
done
[[ "$READY" == true ]] || { cat "$WORK/server.log"; exit 1; }

java -jar "$CLIENT_JAR" enroll "--url=$URL" "--ca=$WORK/depot/ca.pem" --subject=CN=java-device \
  "--key=$WORK/java.key" "--out=$WORK/java.pem"
java -jar "$CLIENT_JAR" renew "--url=$URL" "--ca=$WORK/depot/ca.pem" \
  "--renew-from=$WORK/java.pem" "--signing-key=$WORK/java.key" "--key=$WORK/java-new.key" "--out=$WORK/java-renewed.pem"

mkdir "$WORK/go" "$WORK/bad"
"$GO_CLIENT" -server-url="$URL" -challenge="$SCEP_CHALLENGE" -cn=go-device \
  -private-key="$WORK/go/client.key" -certificate="$WORK/go/client.pem" > "$WORK/go-enroll.log" 2>&1
cp "$WORK/go/client.pem" "$WORK/go/initial.pem"
"$GO_CLIENT" -server-url="$URL" -challenge="$SCEP_CHALLENGE" -cn=go-device \
  -private-key="$WORK/go/client.key" -certificate="$WORK/go/client.pem" > "$WORK/go-renew.log" 2>&1
if "$GO_CLIENT" -server-url="$URL" -challenge=wrong-challenge -cn=bad-device \
  -private-key="$WORK/bad/client.key" -certificate="$WORK/bad/client.pem" > "$WORK/go-rejected.log" 2>&1; then
  echo '错误口令被意外接受' >&2; exit 1
fi
for CERT in java.pem java-renewed.pem go/initial.pem go/client.pem; do
  openssl verify -CAfile "$WORK/depot/ca.pem" "$WORK/$CERT"
done
[[ $(openssl x509 -in "$WORK/go/initial.pem" -noout -serial) != $(openssl x509 -in "$WORK/go/client.pem" -noout -serial) ]]
echo "验证通过：Java 注册/换钥续期、AES 适配版 Go 注册/续期、错误口令拒绝。"
echo "证据目录：$WORK"

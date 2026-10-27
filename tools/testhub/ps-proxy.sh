#!/usr/bin/env bash
#
# Copyright 2026 gematik GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# *******
#
# For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
#

# PS intercept (LIANA-183, a single proxy since LIANA-189.03): a Primärsystem talks to LIANA via a Tiger proxy, all
# traffic shows up in its WebUI.
#   PS ──HTTP and HTTPS :80, :443, :8080, :8443──▶ liana-ps-tiger ──HTTPS with the PS client certificate──▶ LIANA :8443
# Tiger accepts HTTP and HTTPS on the same port and presents to the PS, for TLS, an ID.AK.AUT from the Komp-CA (SAN with PS_HOST).
# It cannot route by protocol, so everything goes to LIANA over TLS: LIANA also sees the PS's HTTP requests
# as HTTPS (ANCL_TLS_MANDATORY cannot be tested through the proxy), mTLS (LIANA-186) is kept.
# 80 and 443 are the ports from TIP1-A_4528 (http(s)://<Konnektor>/connector.sds without port, LIANA-184); connector.sds
# and the .kon export point there. 8080 and 8443 stay open as well, as with LIANA itself.
#   LIANA ──CETP──▶ Ereignissenke of the PS, without proxy (PS_CETP or EventTo); CETP is missing from the capture
#   Card APDUs: LIANA → admin port of the proxy (liana.trace.push-url, LIANA-27)
# The proxy continuously writes each session (up to down) to support/traces/_runs/ps-sessions/
# <NNN>-<YYYYMMDD-HHMMSS>.tgr, NNN increments with each up (LIANA-185); export and down also store the HTML report.
# The proxy's TLS keys (both sides) in NSS key log format accumulate across all sessions in one file,
# target/sharedSecrets.txt (LIANA-189.03); enter it once in Wireshark under Preferences → Protocols → TLS → (Pre)-Master-
# Secret log filename; it also decrypts older captures.
# Directly on the host: LIANA's management port 9090 (Control Center, PIN entry on the fake KT, Admin API, .kon export),
# the proxy's WebUI on PS_TIGER_PORT. connector.sds and the .kon export name the proxy addresses
# (liana.kon-export.url, liana.tls.url) so that the PS does not bypass the proxy after service discovery.
#
# Usage from the LIANA root directory:
#   tools/testhub/ps-proxy.sh up        start LIANA and proxy (LIANA_IMAGE set → no build, otherwise liana:ps)
#   tools/testhub/ps-proxy.sh status    containers, addresses, number of messages
#   tools/testhub/ps-proxy.sh export    HTML report, .tgr and logs to support/traces/_runs/<time>-ps-proxy/
#   tools/testhub/ps-proxy.sh down      export, then stop and remove everything
# Variables:
#   PS_HOST        address under which the PS reaches this machine (default: IP of en0, otherwise localhost); appears in
#                  connector.sds, the .kon export and the SAN of the proxy certificate
#   PS_CETP        host:port of the PS Ereignissenke (CETP, liana.events.redirect); if unset LIANA delivers to EventTo.
#                  All subscriptions go to this one sink, whatever EventTo the PS specifies
#   PS_CLIENT_P12  p12 of the PS for mTLS (LIANA-186), preferably under target/ps-proxy/: the proxy uses it to identify itself
#                  to LIANA, LIANA lists the certificate in liana.tls.client-certs (before CS1). Password from
#                  PS_CLIENT_P12_PASS_FILE (default: <p12 without .p12>.pass), it never appears in any output; the script
#                  repackages the p12 for Tiger with the test password liana (also old RC2-40 p12)
#   PS_CLIENT_AUTH=1  ANCL_CAUT_MANDATORY (liana.tls.client-auth): LIANA requires a known client certificate
#   PS_UPSTREAM    address of a real Konnektor (e.g. 10.150.82.102): the proxy goes there via HTTPS instead of to
#                  LIANA, no LIANA container; in responses it replaces PS_UPSTREAM with PS_HOST (connector.sds)
#   PS_RENEW_CERT=1  new proxy certificate; otherwise it is kept (certificate pinning in the PS) as long as key type and SAN match
#   PS_TLS_LIKE_KONNEKTOR=1  TLS handshake with the cipher suites and signature algorithms of the secunet Konnektor in the PS lab
#   PS_TLS_KEY     p256 (default), bp256 (brainpoolP256r1 like C.AK.AUT) or rsa: key of the proxy certificate (rsa for a PS with TLS_USE_ECC_FOR_CS off)
#   PS_LIANA_CONFIG  custom application.yaml for LIANA (Informationsmodell of the PS, cards, profile), mounted as
#                  /work/config/application.yaml; if unset the image's boot state (M1, CS1, WP1, KT-01).
#                  Epikur (MEpikur, Epikur, ap2): tools/testhub/ps-proxy/liana-epikur.yaml
#   PS_HTTP_PORT (80), PS_HTTPS_PORT (443), PS_HTTP_ALT_PORT (8080), PS_HTTPS_ALT_PORT (8443; empty = off),
#   PS_MGMT_PORT (9090), PS_TIGER_PORT (9080), TIGER_PROXY_IMAGE
set -euo pipefail

LIANA_DIR=$(pwd)
RUNS=$LIANA_DIR/support/traces/_runs
WORK=$LIANA_DIR/target/ps-proxy
IMAGE=${LIANA_IMAGE:-liana:ps}
TIGER_IMAGE=${TIGER_PROXY_IMAGE:-gematik1/tiger-proxy-image:4.4.5}
NET=liana-ps-net
PS_HOST=${PS_HOST:-$(ipconfig getifaddr en0 2>/dev/null || echo localhost)}
PS_CETP=${PS_CETP:-}
PS_TLS_KEY=${PS_TLS_KEY:-p256}
HTTP_PORT=${PS_HTTP_PORT:-80}
HTTPS_PORT=${PS_HTTPS_PORT:-443}
HTTP_ALT_PORT=${PS_HTTP_ALT_PORT-8080}
HTTPS_ALT_PORT=${PS_HTTPS_ALT_PORT-8443}
# Base URLs for connector.sds and .kon: standard ports omitted
HTTP_URL=http://$PS_HOST$([[ $HTTP_PORT == 80 ]] || echo ":$HTTP_PORT")
HTTPS_URL=https://$PS_HOST$([[ $HTTPS_PORT == 443 ]] || echo ":$HTTPS_PORT")
MGMT_PORT=${PS_MGMT_PORT:-9090}
TIGER_PORT=${PS_TIGER_PORT:-9080}
# liana-ps-tiger-tls, -cetp and -nginx existed until LIANA-189.03; down cleans them up too
CONTAINERS=(liana-ps-liana liana-ps-tiger)
LEGACY=(liana-ps-tiger-tls liana-ps-tiger-cetp liana-ps-nginx)
SESSIONS=$RUNS/ps-sessions
PKI=$LIANA_DIR/support/pki

# Server identity of the proxy: like ID.AK.AUT from the same Komp-CA, SAN additionally with PS_HOST
server_identity() {
  local tmp=$WORK/pki san="DNS:liana,DNS:localhost,IP:127.0.0.1"
  mkdir -p "$tmp"
  if [[ $PS_HOST =~ ^[0-9.]+$ ]]; then san+=",IP:$PS_HOST"; elif [[ $PS_HOST != localhost ]]; then san+=",DNS:$PS_HOST"; fi
  # A PS with certificate pinning holds on to the end-entity certificate: keep the existing one as long as key type and SAN
  # match; PS_RENEW_CERT=1 reissues. For import into the PS: target/ps-proxy/pki/server.pem or server.cer (DER)
  if [[ -f $tmp/server.p12 && -f $tmp/server.key-type && $(cat "$tmp/server.key-type") == "$PS_TLS_KEY $san" \
        && ${PS_RENEW_CERT:-0} != 1 ]]; then
    echo "Proxy-Zertifikat ($PS_TLS_KEY) unverändert: $(openssl x509 -in "$tmp/server.pem" -noout -fingerprint -sha256 | cut -d= -f2)"
    return 0
  fi
  if [[ $PS_TLS_KEY == rsa ]]; then
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$tmp/server.key.pem" 2>/dev/null
  elif [[ $PS_TLS_KEY == bp256 ]]; then
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:brainpoolP256r1 -pkeyopt ec_param_enc:named_curve \
      -out "$tmp/server.key.pem"
  else
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve \
      -out "$tmp/server.key.pem"
  fi
  openssl req -new -key "$tmp/server.key.pem" -subj "/C=DE/O=LIANA NOT-VALID/CN=LIANA ID.AK.AUT ps-proxy TEST-ONLY" \
    -out "$tmp/server.csr"
  openssl x509 -req -in "$tmp/server.csr" -CA "$PKI/server/komp-ca.pem" -CAkey "$PKI/server/komp-ca.key.pem" \
    -set_serial "0x$(openssl rand -hex 8)" -sha256 -days 365 -out "$tmp/server.pem" 2>/dev/null \
    -extfile <(printf '%s\n' "basicConstraints=critical,CA:FALSE" \
      "keyUsage=critical,digitalSignature$([[ $PS_TLS_KEY == rsa ]] && echo ,keyEncipherment)" \
      "extendedKeyUsage=clientAuth,serverAuth" "subjectAltName=$san")
  openssl pkcs12 -export -inkey "$tmp/server.key.pem" -in "$tmp/server.pem" -certfile "$PKI/server/komp-ca.pem" \
    -name server -passout pass:liana -out "$tmp/server.p12"
  openssl x509 -in "$tmp/server.pem" -outform DER -out "$tmp/server.cer"
  chmod 644 "$tmp/server.p12"
  echo "$PS_TLS_KEY $san" > "$tmp/server.key-type"
  echo "Proxy-Zertifikat ($PS_TLS_KEY) neu: $san, $(openssl x509 -in "$tmp/server.pem" -noout -fingerprint -sha256 | cut -d= -f2)"
}

# mTLS of the PS: repackage p12 (Tiger reads the test password liana), certificate for liana.tls.client-certs
client_identity() {
  local p12=$PS_CLIENT_P12 pass=${PS_CLIENT_P12_PASS_FILE:-${PS_CLIENT_P12%.p12}.pass} tmp=$WORK/pki
  [[ -f $p12 && -f $pass ]] || { echo "PS_CLIENT_P12 oder Passwortdatei $pass fehlt" >&2; exit 1; }
  openssl pkcs12 -legacy -in "$p12" -passin "file:$pass" -nodes -out "$tmp/ps-client.all.pem" 2>/dev/null \
    || openssl pkcs12 -in "$p12" -passin "file:$pass" -nodes -out "$tmp/ps-client.all.pem" 2>/dev/null \
    || { echo "$p12 lässt sich mit dem Passwort aus $pass nicht öffnen" >&2; exit 1; }
  chmod 600 "$tmp/ps-client.all.pem"
  openssl x509 -in "$tmp/ps-client.all.pem" -out "$tmp/ps-client.pem"
  openssl pkcs12 -export -in "$tmp/ps-client.all.pem" -name ps-client -passout pass:liana -out "$tmp/client.p12"
  rm -f "$tmp/ps-client.all.pem"
  chmod 644 "$tmp/client.p12" "$tmp/ps-client.pem"
  echo "mTLS des PS: $(openssl x509 -in "$tmp/ps-client.pem" -noout -subject | sed 's/^subject=//')"
}

tiger() { # <extra docker arguments…>
  local file=$LIANA_DIR/tools/testhub/ps-proxy/tiger.yaml java_opts=()
  local like=$([[ ${PS_TLS_LIKE_KONNEKTOR:-0} == 1 ]] && echo 1)
  if [[ -n ${PS_UPSTREAM:-} || -n $like ]]; then
    file=$WORK/tiger.yaml
    # Handshake like the secunet Konnektor: cipher suites in its order, only its six signature algorithms in the
    # CertificateRequest (PS_TLS_LIKE_KONNEKTOR=1)
    local suites="TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    { if [[ -n $like ]]; then sed "s/^  tls:\$/  tls:\\
    serverSslSuites: [$suites]/" "$LIANA_DIR/tools/testhub/ps-proxy/tiger.yaml"
      else cat "$LIANA_DIR/tools/testhub/ps-proxy/tiger.yaml"; fi
      # replace the Konnektor's address in responses (connector.sds) with PS_HOST
      [[ -z ${PS_UPSTREAM:-} ]] || {
        printf '  modifications:\n    - condition: "isResponse"\n      targetElement: "$.body"\n'
        printf '      regexFilter: "%s"\n      replaceWith: "%s"\n' "${PS_UPSTREAM//./\\\\.}" "$PS_HOST"; }
    } > "$file"
    [[ -z $like ]] || java_opts=(-e "JAVA_TOOL_OPTIONS=-Djdk.tls.server.SignatureSchemes=rsa_pkcs1_sha256,rsa_pkcs1_sha384,rsa_pkcs1_sha512,ecdsa_secp256r1_sha256,ecdsa_secp384r1_sha384,ecdsa_secp521r1_sha512")
  fi
  # the image sets TIGERPROXY_PROXYPORT=9090, which would take precedence over the configured proxyPort
  docker run -d --name liana-ps-tiger --network "$NET" --platform linux/amd64 \
    -e SPRING_CONFIG_LOCATION=file:/app/tiger-config/ -e TIGERPROXY_PROXYPORT=7000 \
    ${PS_UPSTREAM:+-e "PS_UPSTREAM_HTTPS=https://$PS_UPSTREAM"} \
    -v "$file:/app/tiger-config/application.yaml:ro" \
    -v "$WORK/pki/server.p12:/app/tiger-config/server.p12:ro" ${java_opts[@]+"${java_opts[@]}"} "$@" "$TIGER_IMAGE" >/dev/null
}

up() {
  for c in "${CONTAINERS[@]}" "${LEGACY[@]}"; do
    if docker ps -a --format '{{.Names}}' | grep -qx "$c"; then
      echo "$c läuft schon, erst tools/testhub/ps-proxy.sh down" >&2; exit 1
    fi
  done
  [[ -n ${LIANA_IMAGE:-} || -n ${PS_UPSTREAM:-} ]] || docker build -q -t "$IMAGE" "$LIANA_DIR" >/dev/null
  server_identity
  local client_p12=$PKI/clients/cs1-p256.p12 tls_env=()
  if [[ -n ${PS_CLIENT_P12:-} ]]; then
    client_identity
    client_p12=$WORK/pki/client.p12
    tls_env+=(-v "$WORK/pki/ps-client.pem:/opt/liana/pki/ps/ps-client.pem:ro"
      -e "LIANA_TLS_CLIENT_CERTS=/opt/liana/pki/ps/ps-client.pem,/opt/liana/pki/clients/cs1-p256.pem,/opt/liana/pki/clients/cs1-bp256.pem")
  fi
  [[ ${PS_CLIENT_AUTH:-0} != 1 ]] || tls_env+=(-e LIANA_TLS_CLIENT_AUTH=true)
  docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET" >/dev/null

  # session file: sequence number after the highest existing one, timestamp of the start
  mkdir -p "$SESSIONS" && chmod 777 "$SESSIONS"
  local last session
  last=$(ls "$SESSIONS" 2>/dev/null | sed -n 's/^\([0-9][0-9]*\)-.*\.tgr$/\1/p' | sort -n | tail -1)
  session=$(printf '%03d-%s.tgr' $((10#${last:-0} + 1)) "$(date +%Y%m%d-%H%M%S)")
  echo "$session" > "$WORK/session"
  : > "$SESSIONS/$session" && chmod 666 "$SESSIONS/$session"

  local keylog=$LIANA_DIR/target/sharedSecrets.txt liana_env=() ports=()
  touch "$keylog" && chmod 666 "$keylog"
  for port in "$HTTP_PORT" "$HTTPS_PORT" "$HTTP_ALT_PORT" "$HTTPS_ALT_PORT"; do
    [[ -z $port ]] || ports+=(-p "$port:7000")
  done
  [[ -z $PS_CETP ]] || liana_env+=(-e "LIANA_EVENTS_REDIRECT=$PS_CETP")
  tiger -v "$client_p12:/app/tiger-config/client.p12:ro" \
    -v "$keylog:/keys/sharedSecrets.txt" -e PS_KEYLOG_FILE=/keys/sharedSecrets.txt \
    -e "PS_SESSION_FILE=/sessions/$session" -v "$SESSIONS:/sessions" -p "$TIGER_PORT:8080" "${ports[@]}"

  local config=()
  [[ -z ${PS_LIANA_CONFIG:-} ]] || config=(-v "$(cd "$(dirname "$PS_LIANA_CONFIG")" && pwd)/$(basename "$PS_LIANA_CONFIG"):/work/config/application.yaml:ro")
  if [[ -z ${PS_UPSTREAM:-} ]]; then
    docker run -d --name liana-ps-liana --network "$NET" -p "$MGMT_PORT:9090" \
      -e "LIANA_KON_EXPORT_URL=$HTTP_URL" -e "LIANA_TLS_URL=$HTTPS_URL" \
      -e LIANA_TRACE_PUSH_URL=http://liana-ps-tiger:8080 ${liana_env[@]+"${liana_env[@]}"} ${config[@]+"${config[@]}"} \
      ${tls_env[@]+"${tls_env[@]}"} \
      "$IMAGE" >/dev/null
  fi

  printf 'warte auf LIANA und Proxy'
  for _ in $(seq 1 120); do
    if { [[ -n ${PS_UPSTREAM:-} ]] || [[ $(docker inspect -f '{{.State.Health.Status}}' liana-ps-liana 2>/dev/null) == healthy ]]; } \
      && curl -sf -o /dev/null "http://localhost:$TIGER_PORT/webui"; then
      echo; status; return 0
    fi
    printf .; sleep 2
  done
  echo; echo "Zeitüberschreitung beim Start, siehe docker logs liana-ps-liana / liana-ps-tiger" >&2; exit 1
}

# first Clientsystem of the Informationsmodell (liana.tls.client-certs belongs to it, its .kon is shown in status)
first_client() {
  curl -sf "http://localhost:$MGMT_PORT/admin/infomodel" 2>/dev/null \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["clientSystems"][0])' 2>/dev/null || echo CS1
}

status() {
  docker ps -a --filter name=liana-ps- --format '  {{.Names}}\t{{.Status}}'
  cat <<EOF
PS → LIANA      $HTTP_URL/connector.sds   $HTTPS_URL/connector.sds
                zusätzlich: ${HTTP_ALT_PORT:-–} (HTTP), ${HTTPS_ALT_PORT:-–} (HTTPS)
CETP            $( [[ -n $PS_CETP ]] && echo "LIANA → $PS_CETP, ohne Proxy" || echo "direkt an EventTo (PS_CETP nicht gesetzt)")
Tiger-WebUI     http://localhost:$TIGER_PORT/webui
Sitzung         $SESSIONS/$(cat "$WORK/session" 2>/dev/null || echo –)
TLS-Schlüssel   $LIANA_DIR/target/sharedSecrets.txt (Wireshark: TLS → Pre-Master-Secret log)
Control Center  http://$PS_HOST:$MGMT_PORT/      .kon: http://$PS_HOST:$MGMT_PORT/admin/clients/$(first_client)/config.kon
EOF
}

export_run() {
  local out
  out=$RUNS/$(date +%Y%m%d-%H%M%S)-ps-proxy
  mkdir -p "$out"
  echo "LIANA $(git rev-parse --short HEAD) ($IMAGE), PS_HOST $PS_HOST, PS_CETP ${PS_CETP:-–}" > "$out/run.txt"
  curl -sf -o "$out/ps-proxy-report.html" "http://localhost:$TIGER_PORT/webui/getMessagesAsHtmlPage" || true
  curl -sf -o "$out/ps-proxy.tgr" "http://localhost:$TIGER_PORT/webui/trafficLog.tgr" || true
  for c in "${CONTAINERS[@]}" "${LEGACY[@]}"; do
    docker logs "$c" > "$out/${c#liana-ps-}.log" 2>&1 || true
  done
  echo "Export: $out"
}

down() {
  docker ps --format '{{.Names}}' | grep -qx liana-ps-tiger && export_run
  docker ps -a --filter name=liana-ps- --format '  entferne {{.Names}} ({{.Status}})'
  for c in "${CONTAINERS[@]}" "${LEGACY[@]}"; do docker rm -f "$c" >/dev/null 2>&1 || true; done
  docker network rm "$NET" >/dev/null 2>&1 || true
}

case ${1:-} in
  up) up ;;
  status) status ;;
  export) export_run ;;
  down) down ;;
  *) sed -n '2,/^set -euo/p' "$0" | sed '$d'; exit 2 ;;
esac

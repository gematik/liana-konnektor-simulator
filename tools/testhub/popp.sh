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

# The Testhub's PoPP test suite against LIANA (LIANA-26). Testhub state with LIANA (docs/intern.md): there LIANA is the service liana
# in infra/docker/compose-local.yaml (LIANA-104), configuration in infra/docker/liana/. Usage from the LIANA root directory:
#   tools/testhub/popp.sh up     build the LIANA image, start the PoPP part of the Testhub with LIANA
#   tools/testhub/popp.sh test   run scenario UC_PoPP_1_2a_Valid_ehealth, report to support/traces/_runs/
#   tools/testhub/popp.sh zeta   ZETA scenario SMCB_AUTH_REAL_KONNEKTOR (popp-client gets the token via the SMC-B from
#                                LIANA, LIANA-52), report to support/traces/_runs/
#   tools/testhub/popp.sh abnahme  whole PoPP suite (all automatic scenarios, including those without LIANA), the eH-KT scenario
#                                „abgelaufene eGK“ (expired eGK) with egkCardImageInvalid.xml from the Testhub cards in KT-01/1, then zeta
#   tools/testhub/popp.sh down   stop LIANA and the stack
#   tools/testhub/popp.sh all    up + test
#   tools/testhub/popp.sh report HTML export of the local Tiger proxy (runs as long as the Workflow UI is open) into the
#                                latest run folder; test exports it after the scenario anyway (LIANA-37)
# TESTHUB_DIR (default ../ti2.0-testhub), LIANA_IMAGE (default liana:dev, if set → no build),
# PORT_LIANA_ADMIN (9090), PORT_LOCAL_TIGER_PROXY_ADMIN (6900), TAGS (Cucumber filter for test and zeta), LIANA_TRACE_PUSH_URL (card APDUs to a Tiger proxy, e.g. the
# suite's local one: http://host.docker.internal:6900), WORKFLOW_UI=1 (Tiger Workflow UI in the browser, stays open),
# EGK_IMAGE (test, zeta: insert this image into KT-01 slot 1 before the run; file name, ICCSN or absolute path from card-images;
# afterwards POST /admin/reset),
# KARTOS_TERMINAL=1 (up, phase 2, LIANA-81: KT-01 is the eHealth KT `kartos terminal`, container `kartos-terminal` from
# the same image and binary as LIANA; LIANA sets infrastructure.terminals.KT-01.type=sicct and talks to KT-01 via SICCT/TLS.
# Slots as for KT-01 in the Testhub configuration: 1 eGK (KT01_EGK), 2 SMC-B (KT01_SMCB), 3 gSMC-KT (TLS identity);
# pairing preset (SICCT_SHARED_SECRET). Control interface /api/v1 on 4743 (insert/remove/PIN/faults, LIANA-72–74, LIANA-118, host port
# PORT_KARTOS_CONTROL). In between the Tiger proxy `tiger-sicct` (tools/testhub/tiger-sicct/, TLS intercepted with
# ID.SMKT.AUT of the gSMC-KT, WebUI on PORT_TIGER_SICCT, default 6910); test exports its log as
# tiger-sicct-report.html and tiger-sicct.tgr; SICCT_TIGER=0 omits it. EGK_IMAGE only works with the fake terminal),
# LIANA_CARD_TERMINATE_SECURE_MESSAGING=true (up, LIANA-28: LIANA terminates the PoPP service's Trusted Channel with the
# gSMC-KT from infrastructure.terminals.<KT>.gsmc-kt; plaintext to LIANA_TRACE_PUSH_URL; fake and SICCT KT),
# TIGER_VERSION (the suite's Tiger, e.g. 4.4.6-SNAPSHOT from ~/.m2), TIGER_PROXY_IMAGE (image of the docker-tiger-proxy),
# POPP_ENV (stage of the PoPP service: local = popp-server from the Testhub, tu, ru, ru-dev = service run by RISE; popp-client
# via POPP_SERVER_URL, suite via -Dpopp.env, hosts as in the Testhub's tiger/popp-environments.yaml).
set -euo pipefail

LIANA_DIR=$(pwd)
TESTHUB_DIR=${TESTHUB_DIR:-$LIANA_DIR/../ti2.0-testhub}
TESTHUB_DIR=$(cd "$TESTHUB_DIR" && pwd)
DOCKER_DIR=$TESTHUB_DIR/infra/docker
IMAGE=${LIANA_IMAGE:-liana:dev}
# Platform of the LIANA image: a locally built one (without LIANA_IMAGE) has the Docker host's, an existing one its
# own; otherwise the Testhub default linux/amd64 (the registry image exists only for that)
if [[ -z ${LIANA_PLATFORM:-} ]]; then
  if [[ -z ${LIANA_IMAGE:-} ]]; then LIANA_PLATFORM=$(docker version -f '{{.Server.Os}}/{{.Server.Arch}}')
  else LIANA_PLATFORM=$(docker image inspect -f '{{.Os}}/{{.Architecture}}' "$IMAGE" 2>/dev/null || echo linux/amd64); fi
fi
ADMIN=http://localhost:${PORT_LIANA_ADMIN:-9090}
RUNS=$LIANA_DIR/support/traces/_runs
REPORT_URL=http://localhost:${PORT_LOCAL_TIGER_PROXY_ADMIN:-6900}/webui/getMessagesAsHtmlPage
export LIANA_RESOLV_CONF=$RUNS/liana-resolv.conf
# Only the PoPP part of the stack; compose pulls in the dependencies (ZETA, DBs).
SERVICES=(resolv-writer canopy docker-tiger-proxy otel-collector liana popp-server popp-zeta-pdp-opa popp-zeta-ingress popp-client)
# Additional variables for the service liana (KARTOS_TERMINAL=1), included in the Testhub as LIANA_ENV_FILE
export LIANA_ENV_FILE=$RUNS/liana.env
POPP_TAGS='@TCID:UC_PoPP_1_2a_Valid_ehealth'
ZETA_TAGS='@TCID:SMCB_AUTH_REAL_KONNEKTOR'
SUITE_TAGS='not @MODUS:Manuell'
# Expired eGK from the Testhub's test/vsdm-testsuite/src/test/resources/data/cards, in the container /opt/liana/testhub-cards
# (C.CH.AUT until 2025-04-05, ICCSN …168583, KVNR X110639491, LIANA-177); the suite's images (EgkType: …179865…abgelaufen2025,
# …180787…revoked) are not public (LIANA-42).
EXPIRED_EGK=/opt/liana/testhub-cards/egkCardImageInvalid.xml
# Phase 2 (KARTOS_TERMINAL=1): card images for KT-01 from the Testhub folders, pairing between LIANA and kartos
KT01_EGK=${KT01_EGK:-$TESTHUB_DIR/test/vsdm-testsuite/src/test/resources/data/cards/EGK_80276883110000168584_gema5.xml}
KT01_SMCB=${KT01_SMCB:-$TESTHUB_DIR/test/vsdm-testsuite/src/test/resources/private/smcb/smcbCardImage.xml}
SICCT_SHARED_SECRET=${SICCT_SHARED_SECRET:-a0a1a2a3a4a5a6a7a8a9aaabacadaeaf}
TIGER_SICCT_URL=http://localhost:${PORT_TIGER_SICCT:-6910}
EXPIRED_TCID='@TCID:UC_PoPP_1_2a_eGK_expired_Invalid_eHealth'
POPP_ENV=${POPP_ENV:-local}
case $POPP_ENV in
  local) ;;
  tu) POPP_HOST=popp.test.poppservice.de ;;
  ru) POPP_HOST=popp.ref.poppservice.de ;;
  ru-dev) POPP_HOST=popp.dev.poppservice.de ;;
  *) echo "POPP_ENV=$POPP_ENV unbekannt (local, tu, ru, ru-dev)" >&2; exit 2 ;;
esac
# Only for compose, not exported: Tiger reads environment variables as configuration, POPP_SERVER_URL would otherwise override
# the suite's popp.server.url (expected iss).
POPP_SERVER_URL=${POPP_HOST:+wss://$POPP_HOST/popp/practitioner/api/v1/token-generation-ehc}

grep -q '^  liana:' "$DOCKER_DIR/compose-local.yaml" || {
  echo "Service liana fehlt in $DOCKER_DIR/compose-local.yaml – Testhub-Stand mit LIANA auschecken (docs/intern.md)" >&2; exit 1; }

docker29() { (( $(docker version -f '{{.Server.Version}}' | cut -d. -f1) >= 29 )); }

compose() {
  local files=(-f "$DOCKER_DIR/compose-local.yaml")
  docker29 && files+=(-f "$LIANA_DIR/tools/testhub/compose-docker29.yaml")
  # the Testhub reads TIGER_PROXY_IMAGE itself (docker-tiger-proxy)
  POPP_SERVER_URL=$POPP_SERVER_URL LIANA_IMAGE=$IMAGE LIANA_PLATFORM=$LIANA_PLATFORM docker compose "${files[@]}" --env-file "$DOCKER_DIR/.env" \
    --env-file "$DOCKER_DIR/.env.popp-suite" --profile full "$@"
}

wait_for() { # $1 description, $2… command
  local what=$1; shift
  for _ in $(seq 1 90); do "$@" >/dev/null 2>&1 && return 0; sleep 2; done
  echo "Zeitüberschreitung: $what" >&2; return 1
}

# Cross-check popp-client ↔ .kon export: what popp-client gets according to Compose must match what LIANA exports for C1
# (support/kon/kon-format.md). Only report differences, the Testhub configuration takes precedence.
check_kon() {
  local kon env
  kon=$(curl -sf "$ADMIN/admin/clients/C1/config.kon") || { echo "Warnung: kein .kon für C1" >&2; return 0; }
  env=$(compose config --format json popp-client) || { echo "Warnung: compose config für popp-client fehlgeschlagen" >&2; return 0; }
  KON=$kon ENV=$env python3 -I -c '
import json, os
k = json.loads(os.environ["KON"])
e = json.loads(os.environ["ENV"])["services"]["popp-client"]["environment"]
want = {"CONNECTOR_END_POINT_URL": k["url"].rstrip("/"),
        "CONTEXT_MANDANT_ID": k["mandantId"], "CONTEXT_WORKPLACE_ID": k["workplaceId"],
        "CONTEXT_CLIENT_SYSTEM_ID": k["clientSystemId"]}
bad = [f"{n}: popp-client {e.get(n)}, .kon {v}" for n, v in want.items() if e.get(n) != v]
print("\n".join(["Warnung: popp-client passt nicht zum .kon-Export:"] + bad) if bad else "popp-client passt zum .kon-Export von C1")'
}

up() {
  mkdir -p "$RUNS"
  [[ -n ${LIANA_IMAGE:-} ]] || docker build -q -t "$IMAGE" "$LIANA_DIR" >/dev/null
  [[ -f $LIANA_RESOLV_CONF ]] || : > "$LIANA_RESOLV_CONF"
  compose up -d canopy                                   # also creates testhub_network
  local canopy_ip network
  canopy_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' tiger-canopy)
  network=$(docker inspect -f '{{range $n, $_ := .NetworkSettings.Networks}}{{$n}}{{end}}' tiger-canopy)  # <project>_testhub_network
  printf '# LIANA popp.sh: Canopy als einziger Resolver (wie resolv-writer im Testhub)\nnameserver %s\n' "$canopy_ip" > "$LIANA_RESOLV_CONF"
  docker rm -f liana >/dev/null 2>&1 || true   # LIANA from an earlier docker run (before LIANA-104)
  : > "$LIANA_ENV_FILE"
  if [[ ${KARTOS_TERMINAL:-0} == 1 ]]; then
    local kt_host=kartos-terminal advertise=()
    if [[ ${SICCT_TIGER:-1} != 0 ]]; then
      tiger_sicct "$network"
      kt_host=tiger-sicct
      # The service description names the proxy's address; LIANA matches it to the request via this IP (TUC_KON_054)
      advertise=(-e "TERMINAL_ADVERTISE_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' tiger-sicct)")
    fi
    kartos_terminal "$network" ${advertise[@]+"${advertise[@]}"}
    [[ ${SICCT_TIGER:-1} == 0 ]] || tiger_sicct_ready
    # KT-01 via SICCT instead of the fake terminal (infrastructure.terminals.KT-01, LIANA-98); KT-02 stays an empty
    # fake KT, workplace W1 only with KT-01
    printf '%s\n' LIANA_INFRASTRUCTURE_TERMINALS_KT_01_TYPE=sicct "LIANA_INFRASTRUCTURE_TERMINALS_KT_01_HOST=$kt_host" \
      "LIANA_INFRASTRUCTURE_TERMINALS_KT_01_SHARED_SECRET=$SICCT_SHARED_SECRET" \
      LIANA_INFOMODEL_WORKPLACES_0__TERMINALS=KT-01 > "$LIANA_ENV_FILE"
  fi
  # compose passes LIANA_TRACE_PUSH_URL and LIANA_CARD_TERMINATE_SECURE_MESSAGING through to the service liana
  compose up -d --force-recreate liana
  wait_for "LIANA Admin-API" curl -sf "$ADMIN/admin/info"
  # Via SICCT, LIANA adds KT-01 after startup (TUC_KON_054/050) and then reports the cards
  [[ ${KARTOS_TERMINAL:-0} != 1 ]] || wait_for "KT-01 über SICCT mit SMC-B" sh -c 'docker logs liana 2>&1 | grep -q "CARD/INSERTED KT-01/2 "'
  check_kon
  compose up -d "${SERVICES[@]}"
  wait_for "popp-client healthy" sh -c '[ "$(docker inspect -f "{{.State.Health.Status}}" popp-client)" = healthy ]'
  echo "Testhub mit LIANA läuft (PoPP-Stufe $POPP_ENV, Testhub-Branch $(git -C "$TESTHUB_DIR" rev-parse --abbrev-ref HEAD))."
}

# eHealth KT (decision-11): kartos terminal from /opt/liana/bin/kartos of the LIANA image as a separate process in the Compose network.
# Slots in name order from $RUNS/kartos-terminal/images (1 eGK, 2 SMC-B, 3 gSMC-KT with the TLS identity); the
# pairing with LIANA (shared secret and key of ID.SAK.AUT) is preset in $RUNS/kartos-terminal/state, as if
# LIANA had paired earlier (TUC_KON_053). No
# own announcements: LIANA finds KT-01 via a service request to the configured host (TUC_KON_054 ManuallyAdded).
kartos_terminal() { # $1 Compose network, $2… further docker run options
  local network=$1 dir=$RUNS/kartos-terminal
  shift
  rm -rf "$dir" && mkdir -p "$dir/images" "$dir/state"
  cp "$KT01_EGK" "$dir/images/1_$(basename "$KT01_EGK")"
  cp "$KT01_SMCB" "$dir/images/2_$(basename "$KT01_SMCB")"
  cp "$LIANA_DIR/support/images/gsmckt-valid.xml" "$dir/images/3_gsmckt-valid.xml"
  # pairing block bound to LIANA's ID.SAK.AUT (LIANA-88, gemSpec_KT TIP1-A_3046-01): key as SubjectPublicKeyInfo
  local key
  key=$(openssl x509 -in "$LIANA_DIR/support/pki/server/sak-aut-bp256.pem" -pubkey -noout \
    | openssl pkey -pubin -outform DER | od -An -v -tx1 | tr -d ' \n')
  printf '[{"shared_secret":"%s","konnektor_keys":["%s"],"created_at":"2026-10-09T00:00:00Z","known_ips":[]}]' \
    "$SICCT_SHARED_SECRET" "$key" > "$dir/state/pairing.json"
  docker rm -f kartos-terminal >/dev/null 2>&1 || true
  # --no-healthcheck: the LIANA image's HEALTHCHECK checks LIANA itself (/admin/ready, LIANA-107), only kartos runs here
  docker run -d --name kartos-terminal --network "$network" --network-alias kartos-terminal --no-healthcheck "$@" \
    -p "${PORT_KARTOS_CONTROL:-4743}:4743" -e TERMINAL_CONTROL_ADDR=0.0.0.0:4743 \
    -e TERMINAL_STATE_DIR=/kartos/state -e TERMINAL_ANNOUNCE_ON_STARTUP=false -e TERMINAL_ANNOUNCE_INTERVAL_SECS=0 \
    -e TERMINAL_FRIENDLY_NAME=kartos-kt-01 -e TERMINAL_ADVERTISE_MAC=02:00:00:4C:49:01 -v "$dir:/kartos" --entrypoint /opt/liana/bin/kartos \
    "$IMAGE" -v terminal --workdir /kartos/images >/dev/null
  wait_for "kartos terminal" sh -c 'docker logs kartos-terminal 2>&1 | grep -q "kartos-terminal server listening"'
}

# Tiger proxy on the SICCT path (LIANA-81): tiger-sicct accepts SICCT/TLS on 4742 and forwards to kartos-terminal
# (tools/testhub/tiger-sicct/application.yaml). socat in the proxy's network namespace forwards the UDP service request
# to kartos; kartos answers to the client address from the request (SICCT) and announces the proxy's IP
# and port 4742 (TERMINAL_ADVERTISE_IP), so LIANA connects to the proxy. Image as for the
# Testhub's docker-tiger-proxy (TIGER_PROXY_IMAGE, otherwise gematik1/tiger-proxy-image:4.4.5).
# Order: tiger_sicct only starts the container (Docker assigns the IP immediately, kartos announces it), then
# kartos_terminal, only then tiger_sicct_ready. Tiger resolves the route target kartos-terminal at startup; if
# the container does not exist yet, the JVM caches the "unknown host" and LIANA's first connection fails with 4028.
tiger_sicct() { # $1 Compose network
  docker rm -f tiger-sicct tiger-sicct-udp >/dev/null 2>&1 || true
  docker run -d --name tiger-sicct --network "$1" --network-alias tiger-sicct --platform linux/amd64 \
    -p "${PORT_TIGER_SICCT:-6910}:8080" -e SPRING_CONFIG_LOCATION=file:/app/tiger-config/ -e TIGERPROXY_PROXYPORT=4742 \
    -v "$LIANA_DIR/tools/testhub/tiger-sicct/application.yaml:/app/tiger-config/application.yaml:ro" \
    -v "$LIANA_DIR/support/pki/kt/smkt-aut-gsmckt-valid.p12:/app/tiger-config/smkt-aut.p12:ro" \
    -v "$LIANA_DIR/support/pki/server/sak-aut-bp256.p12:/app/tiger-config/sak-aut.p12:ro" \
    "${TIGER_PROXY_IMAGE:-gematik1/tiger-proxy-image:4.4.5}" >/dev/null
}

# After kartos_terminal: service request relay in the proxy's network namespace, then wait until the proxy is ready.
tiger_sicct_ready() {
  docker run -d --name tiger-sicct-udp --network container:tiger-sicct alpine/socat \
    UDP4-RECVFROM:4742,fork UDP4-SENDTO:kartos-terminal:4742 >/dev/null
  wait_for "tiger-sicct" curl -sf -o /dev/null "$TIGER_SICCT_URL/webui"
}

# All traffic of the suite's local Tiger proxy as a standalone HTML page (like "Export as HTML" in the WebUI):
# SOAP popp-client → LIANA, card APDUs, ZETA, PoPP WebSocket.
report() {
  local out=${1:-$(ls -d "$RUNS"/*-popp-* "$RUNS"/*-zeta-* 2>/dev/null | sort | tail -1)}
  curl -sf -o "$out/tiger-proxy-report.html" "$REPORT_URL" && echo "HTML-Report: $out/tiger-proxy-report.html"
}

# Waits until Tiger writes the scenario's Rbel log (scenario finished, proxy still running), then exports.
report_after_scenario() { # $1 run folder, $2 marker file from the start, $3 suite (popp, zeta)
  local logs=$TESTHUB_DIR/test/$3-testsuite/target/rbellogs
  for _ in $(seq 1 900); do
    if [[ -d $logs ]] && find "$logs" -name '*.html' -newer "$2" | grep -q .; then
      sleep 2; report "$1" && return 0
    fi
    sleep 1
  done
  echo "Warnung: kein HTML-Report exportiert" >&2
}

# Inserts $1 into KT-01 slot 1; a card already inserted is replaced.
insert_egk() {
  curl -sf -X PUT -H 'Content-Type: application/json' -d "{\"image\":\"$1\"}" "$ADMIN/admin/terminals/KT-01/slots/1" >/dev/null \
    || { echo "Image $1 lässt sich nicht in KT-01/1 stecken" >&2; return 1; }
  echo "KT-01/1: $1"
}

run_tests() { # $1 suite (popp, zeta), $2 Cucumber filter, $3 run name, $4 eGK image for KT-01/1 (optional)
  local suite=$1 tags=$2 egk=${4:-} out
  [[ -z $egk ]] || insert_egk "$egk" || return 1
  out=$RUNS/$(date +%Y%m%d-%H%M%S)-$3$([[ $POPP_ENV == local ]] || echo "-$POPP_ENV")
  mkdir -p "$out"
  local rc=0
  touch "$out/.start"
  report_after_scenario "$out" "$out/.start" "$suite" &
  local exporter=$!
  # install the suite's Testhub modules (rbel-fluent-api …) as SNAPSHOT, otherwise they are missing after a version jump
  (cd "$TESTHUB_DIR" && ./mvnw -B -q -pl "test/$suite-testsuite" -am install -DskipTests -Dskip.inttests=true ${TIGER_VERSION:+-Dversion.tiger="$TIGER_VERSION"} \
    && ./mvnw -B -pl "test/$suite-testsuite" verify -Dskip.inttests=false \
    -Dtiger.lib.activateWorkflowUi="$([[ ${WORKFLOW_UI:-0} == 1 ]] && echo true || echo false)" \
    ${TIGER_VERSION:+-Dversion.tiger="$TIGER_VERSION"} -Dpopp.env="$POPP_ENV" -Dcucumber.filter.tags="$tags") > "$out/mvn.log" 2>&1 || rc=$?
  kill "$exporter" 2>/dev/null || true; wait "$exporter" 2>/dev/null || true
  rm -f "$out/.start"
  echo "$suite-testsuite, Filter: $tags${egk:+, KT-01/1: $egk}" > "$out/tags.txt"
  [[ -z $egk ]] || curl -sf -X POST "$ADMIN/admin/reset" >/dev/null || echo "Warnung: POST /admin/reset fehlgeschlagen" >&2
  local t=$TESTHUB_DIR/test/$suite-testsuite/target
  for d in failsafe-reports site/serenity cucumber-reports rbellogs; do
    [[ -d $t/$d ]] && cp -R "$t/$d" "$out/" || true
  done
  docker logs liana > "$out/liana.log" 2>&1 || true
  if docker inspect kartos-terminal >/dev/null 2>&1; then
    docker logs kartos-terminal > "$out/kartos-terminal.log" 2>&1 || true
    curl -sf -o "$out/tiger-sicct-report.html" "$TIGER_SICCT_URL/webui/getMessagesAsHtmlPage" \
      && curl -sf -o "$out/tiger-sicct.tgr" "$TIGER_SICCT_URL/webui/trafficLog.tgr" \
      && echo "SICCT-Verkehr: $out/tiger-sicct-report.html, $out/tiger-sicct.tgr" || true
  fi
  docker logs popp-client > "$out/popp-client.log" 2>&1 || true
  echo "PoPP-Stufe $POPP_ENV, Tiger der Suite ${TIGER_VERSION:-aus pom.xml}, docker-tiger-proxy $(docker inspect -f '{{.Config.Image}}' docker-tiger-proxy 2>/dev/null)" > "$out/versions.txt"
  grep -E "Tests run:|FAILED|ERROR\]" "$out/mvn.log" | tail -8 || true
  echo "Report: $out (mvn exit $rc)"
  return $rc
}

case ${1:-} in
  up) up ;;
  test) run_tests popp "${TAGS:-$POPP_TAGS}" popp-ehkt "${EGK_IMAGE:-}" ;;
  zeta) run_tests zeta "${TAGS:-$ZETA_TAGS}" zeta-konnektor "${EGK_IMAGE:-}" ;;
  abnahme) rc=0
    run_tests popp "$SUITE_TAGS and not $EXPIRED_TCID" popp-suite || rc=$?
    run_tests popp "$EXPIRED_TCID" popp-ehkt-expired "$EXPIRED_EGK" || rc=$?
    run_tests zeta "$ZETA_TAGS" zeta-konnektor || rc=$?
    exit $rc ;;
  down) docker rm -f kartos-terminal tiger-sicct-udp tiger-sicct >/dev/null 2>&1 || true; compose down ;;
  all) up; run_tests popp "${TAGS:-$POPP_TAGS}" popp-ehkt ;;
  report) report "${2:-}" ;;
  *) sed -n '2,28p' "$0"; exit 2 ;;
esac

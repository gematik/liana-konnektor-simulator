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

# eHealth KT suite (../tiger-ehealth-kt-e2e, branch Development_1.x) against LIANA (LIANA-106). The suite controls cards and PIN pad via the robot interface (POST /api/robot/robotCommand),
# which LIANA offers on port 9997; robot terminal 1 is KT-01, eGK in slot 1, authorized card in slot 2.
# LIANA runs as container liana-ehkt, the suite via Maven in a second container in its network namespace (like
# e2e.sh: the suite's GEMCRYPT web service on localhost:8080, LIANA HTTP on 18080). The suite stays unchanged, its
# configuration (tiger.yaml, konnektor.yaml) is overridden via -D: Konnektor testkon1 points to LIANA, CETP goes through
# the suite's cetpProxy (4449) so that the TGR steps see the events. LIANA gets the Aufrufkontext C1/M1/W1 of the features
# into its Informationsmodell via the environment.
# Usage from the LIANA root directory:
#   tools/testhub/ehkt.sh                  the scenarios LIANA supports (CI, expected green)
#   tools/testhub/ehkt.sh all              all scenarios without @Ignore (nightly, LIANA-100; the others are red, LIANA-106)
#   tools/testhub/ehkt.sh '<tag expression>'
# LIANA_IMAGE (default liana:ehkt, if set → no build), EHKT_SUITE_DIR (default ../tiger-ehealth-kt-e2e), MAVEN_IMAGE
# (default maven:3.9-eclipse-temurin-21), EHKT_TIMEOUT (seconds for the Maven run, default 1800). Run output goes to
# support/traces/_runs/.
# EHKT_SICCT=1 (LIANA-112.15): KT-01 is the eHealth KT `kartos terminal` (container liana-ehkt-kartos from the same image)
# instead of a fake KT, LIANA talks to it via SICCT/TLS, with the Tiger proxy liana-ehkt-tiger in between
# (tools/testhub/tiger-sicct/, WebUI on PORT_TIGER_SICCT, default 6911) as with popp.sh KARTOS_TERMINAL=1. Boot: egk-valid
# in slot 1, smcb-valid in 2, gSMC-KT in 3; the robot inserts and removes cards via the kartos control interface
# (infrastructure.terminals.KT-01.control). The run contains tiger-sicct.tgr and tiger-sicct-report.html.
set -euo pipefail

LIANA_DIR=$(pwd)
SUITE_DIR=$(cd "${EHKT_SUITE_DIR:-$LIANA_DIR/../tiger-ehealth-kt-e2e}" && pwd)
RUNS=$LIANA_DIR/support/traces/_runs
IMAGE=${LIANA_IMAGE:-liana:ehkt}
MAVEN_IMAGE=${MAVEN_IMAGE:-maven:3.9-eclipse-temurin-21}
KON=testkon1
SICCT=${EHKT_SICCT:-0}
NET=liana-ehkt-net
SICCT_SHARED_SECRET=a0a1a2a3a4a5a6a7a8a9aaabacadaeaf
TIGER_SICCT_URL=http://localhost:${PORT_TIGER_SICCT:-6911}
# KMS for the Komfortsignatur (EE_KT_T_SIGNATUR_COMFORTSIGNATUR, the suite's kms.yaml: EHEX on 8500): credentials of the LIANA KMS
KMS_PASSWORD=$(awk '/^  kms:/{k=1} k&&/password:/{gsub(/"/, "", $2); print $2; exit}' "$LIANA_DIR/liana-app/src/main/resources/application.yaml")
SUPPORTED="@TCID:GET_CARDS or @TCID:EE_KT_T_GET_CARDTERMINALS or @TCID:EE_KT_T_PIN_VERIFY_SMB_HBA or @TCID:EE_KT_T_PIN_MAGT_ABSCHLUSS_0005 or @TCID:EE_KT_T_DISABLE or @TCID:EE_KT_T_PIN_DISABLE_FALSCHE_EINGABE or @TCID:EE_KT_T_PIN_CHANGE_AMTS_REP"
# EE_KT_T_SIGNATUR (LIANA-112.11): QES with the HBA in SC4 (G2.1) or SC2 (G2), the ROBOT enters PIN.QES on the PIN pad.
# The scenarios only check status OK; SignDocument has no Crypt, LIANA signs per TAB_KON_900 with the key of the
# card generation. SC2 stays hba-valid (G2.1, ECC): the G2.0 HBA support/images/g20/hba-g20 (RSA, LIANA-112.12) allows
# one signature per PIN.QES, STAPELSIGNATUR_RSA enters the PIN only once
SUPPORTED="$SUPPORTED or @TCID:EE_KT_T_SIGNATUR_EINFACH_RSA or @TCID:EE_KT_T_SIGNATUR_EINFACH_ECC"
SUPPORTED="$SUPPORTED or @TCID:EE_KT_T_SIGNATUR_COMFORTSIGNATUR_ or @TCID:EE_KT_T_SIGNATUR_STAPELSIGNATUR_RSA"
SUPPORTED="$SUPPORTED or @TCID:EE_KT_T_SIGNATUR_STAPELSIGNATUR_ECC"
# EE_KT_T_KVK_READ (LIANA-113): eGK compartments SC5 and SC7 hold KVKs as in the lab (kvk-valid, liana.robot.egk), only on the
# fake KT; with EHKT_SICCT=1 kartos inserts no KVK
SUPPORTED="$SUPPORTED or @TCID:EE_KT_T_KVK_READ"
case ${1:-} in
  "") TAGS=$SUPPORTED ;;
  all) TAGS="not @Ignore" ;;
  *) TAGS=$1 ;;
esac

[[ -n ${LIANA_IMAGE:-} ]] || docker build -q -t "$IMAGE" "$LIANA_DIR" >/dev/null
out=$RUNS/$(date +%Y%m%d-%H%M%S)-ehkt
mkdir -p "$out"
echo "tiger-ehealth-kt-e2e $(git -C "$SUITE_DIR" rev-parse --short HEAD), LIANA $(git rev-parse --short HEAD) ($IMAGE), Tags: $TAGS$( [[ $SICCT == 1 ]] && echo ", KT-01 über SICCT (kartos terminal)")" | tee "$out/run.txt"

cleanup() {
  docker rm -f liana-ehkt-suite liana-ehkt-sink liana-ehkt liana-ehkt-udp liana-ehkt-tiger liana-ehkt-kartos >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
cleanup
# LIANA-112.15: the PIN pad of the robot KTs waits for „ROBOT gibt Verifikationspin ein“, which comes after the call
sicct=(-e LIANA_ROBOT_AWAIT_PIN=true)
if [[ $SICCT == 1 ]]; then
  docker network create "$NET" >/dev/null
  # Tiger proxy in front of kartos (popp.sh tiger_sicct): Docker assigns the IP immediately, kartos announces it
  docker run -d --name liana-ehkt-tiger --network "$NET" --network-alias tiger-sicct --platform linux/amd64 \
    -p "${PORT_TIGER_SICCT:-6911}:8080" -e SPRING_CONFIG_LOCATION=file:/app/tiger-config/ -e TIGERPROXY_PROXYPORT=4742 \
    -v "$LIANA_DIR/tools/testhub/tiger-sicct/application.yaml:/app/tiger-config/application.yaml:ro" \
    -v "$LIANA_DIR/support/pki/kt/smkt-aut-gsmckt-valid.p12:/app/tiger-config/smkt-aut.p12:ro" \
    -v "$LIANA_DIR/support/pki/server/sak-aut-bp256.p12:/app/tiger-config/sak-aut.p12:ro" \
    "${TIGER_PROXY_IMAGE:-gematik1/tiger-proxy-image:4.4.5}" >/dev/null
  # kartos terminal (popp.sh kartos_terminal): pairing bound to LIANA's ID.SAK.AUT, PIN script instead of auto PIN; the new
  # PIN for ChangePin is the old one, as on the fake KT (CORRECT)
  kdir=$out/kartos-terminal
  mkdir -p "$kdir/images" "$kdir/state"
  cp "$LIANA_DIR/support/images/egk-valid.xml" "$kdir/images/1_egk-valid.xml"
  cp "$LIANA_DIR/support/images/smcb-valid.xml" "$kdir/images/2_smcb-valid.xml"
  cp "$LIANA_DIR/support/images/gsmckt-valid.xml" "$kdir/images/3_gsmckt-valid.xml"
  key=$(openssl x509 -in "$LIANA_DIR/support/pki/server/sak-aut-bp256.pem" -pubkey -noout \
    | openssl pkey -pubin -outform DER | od -An -v -tx1 | tr -d ' \n')
  printf '[{"shared_secret":"%s","konnektor_keys":["%s"],"created_at":"2026-10-09T00:00:00Z","known_ips":[]}]' \
    "$SICCT_SHARED_SECRET" "$key" > "$kdir/state/pairing.json"
  docker run -d --name liana-ehkt-kartos --network "$NET" --network-alias kartos-terminal --no-healthcheck \
    -e "TERMINAL_ADVERTISE_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' liana-ehkt-tiger)" \
    -e TERMINAL_CONTROL_ADDR=0.0.0.0:4743 -e TERMINAL_STATE_DIR=/kartos/state -e TERMINAL_ANNOUNCE_ON_STARTUP=false \
    -e TERMINAL_ANNOUNCE_INTERVAL_SECS=0 -e TERMINAL_FRIENDLY_NAME=kartos-kt-01 -e TERMINAL_ADVERTISE_MAC=02:00:00:4C:49:01 \
    -e TERMINAL_INPUT_MODE=script -e TERMINAL_AUTO_PIN_MODIFY=123456 \
    -v "$kdir:/kartos" --entrypoint /opt/liana/bin/kartos "$IMAGE" -v terminal --workdir /kartos/images >/dev/null
  for _ in $(seq 1 30); do
    docker logs liana-ehkt-kartos 2>&1 | grep -q "kartos-terminal server listening" && break
    sleep 1
  done
  docker run -d --name liana-ehkt-udp --network container:liana-ehkt-tiger alpine/socat \
    UDP4-RECVFROM:4742,fork UDP4-SENDTO:kartos-terminal:4742 >/dev/null
  for _ in $(seq 1 60); do curl -sf -o /dev/null "$TIGER_SICCT_URL/webui" && break; sleep 1; done
  sicct+=(--network "$NET" -e LIANA_INFRASTRUCTURE_TERMINALS_KT_01_TYPE=sicct
    -e LIANA_INFRASTRUCTURE_TERMINALS_KT_01_HOST=tiger-sicct
    -e "LIANA_INFRASTRUCTURE_TERMINALS_KT_01_SHARED_SECRET=$SICCT_SHARED_SECRET"
    -e LIANA_INFRASTRUCTURE_TERMINALS_KT_01_CONTROL=http://kartos-terminal:4743
    # TIP1-A_4538-02: if the working connection drops (observed: Tiger proxy closes both sides), LIANA reconnects
    # after at most 10 s instead of the default 10 minutes
    -e LIANA_CTM_SERVICE_DISCOVERY_CYCLE=10s)
fi
# eGK of compartments SC3/SC4 (EF_EHKT_PIN_MANAGMENT, LIANA-109): the suite's G2.1 image with all MRPINs enabled;
# egk-valid has MRPIN.NFD and MRPIN.DPE disabled, the scenarios check VERIFIABLE before DisablePin
EHKT_EGK=/opt/liana/ehkt-images/egk_G21_80276883110000129018.xml
# Signature scenarios (LIANA-112.11): HBA also in SC4, workplace W2 for switching under Komfortsignatur, profile EHEX
# with the KMS on 8500 as in the suite's kms.yaml (SAK_COMFORT_SIGNATURE)
docker run -d --name liana-ehkt -e QUARKUS_HTTP_PORT=18080 -e LIANA_ROBOT_PORT=9997 \
  -v "$SUITE_DIR/images_E2E_5V:/opt/liana/ehkt-images:ro" -e "LIANA_ROBOT_EGK_SC3=$EHKT_EGK" -e "LIANA_ROBOT_EGK_SC4=$EHKT_EGK" \
  -e 'LIANA_INFOMODEL_CLIENT_SYSTEMS_1_=C1' \
  -e 'LIANA_INFOMODEL_WORKPLACES_1__ID=W1' -e 'LIANA_INFOMODEL_WORKPLACES_1__MANDANTS_0_=M1' \
  -e 'LIANA_INFOMODEL_WORKPLACES_1__CLIENT_SYSTEMS_0_=C1' -e 'LIANA_INFOMODEL_WORKPLACES_1__TERMINALS_0_=KT-01' \
  -e 'LIANA_INFOMODEL_WORKPLACES_2__ID=W2' -e 'LIANA_INFOMODEL_WORKPLACES_2__MANDANTS_0_=M1' \
  -e 'LIANA_INFOMODEL_WORKPLACES_2__CLIENT_SYSTEMS_0_=C1' -e 'LIANA_INFOMODEL_WORKPLACES_2__TERMINALS_0_=KT-01' \
  -e LIANA_ROBOT_BERECHTIGT_SC4=hba-valid -e LIANA_VENDOR=EHEX -e LIANA_KMS_PORT=8500 "${sicct[@]}" \
  "$IMAGE" >/dev/null
# Upstream of the suite's cetpProxy: in tiger.yaml its own admin port 11502. With TLS CETP (ANCL_TLS_MANDATORY)
# the proxy fails the handshake there, without TLS (default, LIANA-117) it appends that port's HTTP 400 to the CETP message and
# the TGR steps do not find $.body.Event.Topic.text; without a peer Tiger 3.x discards the event (LIANA-95).
# socat accepts and discards it (qes.sh)
docker run -d --name liana-ehkt-sink --network container:liana-ehkt alpine/socat \
  -u TCP-LISTEN:1234,fork,reuseaddr OPEN:/dev/null >/dev/null
for _ in $(seq 1 60); do
  docker logs liana-ehkt 2>&1 | grep -q "Admin-API auf Port\|Listening on" && break
  docker inspect -f '{{.State.Running}}' liana-ehkt | grep -q true || { docker logs liana-ehkt >&2; exit 1; }
  sleep 1
done
# Via SICCT, LIANA adds KT-01 after startup (TUC_KON_054/050) and then reports the cards
if [[ $SICCT == 1 ]]; then
  for _ in $(seq 1 60); do docker logs liana-ehkt 2>&1 | grep -q "CARD/INSERTED KT-01/2 " && break; sleep 1; done
fi

# Reports from an earlier run would otherwise be counted too
rm -rf "$SUITE_DIR/target/failsafe-reports"
rc=0
# timeout: in the full run Maven hung after the test JVM aborted (LIANA-106)
# rbel.request.timeout: Tiger 4.4.5 waits after each step until all messages in the proxy are paired (the suite's tiger.yaml:
# 200 s). A VerifyPin that waits for the PIN as on a real KT would thus hold up the following robot step „ROBOT gibt
# Verifikationspin ein“ until LIANA's PIN timeout (30 s) (LIANA-68); 10 s is below that.
docker run --rm --name liana-ehkt-suite --network container:liana-ehkt -v "$SUITE_DIR:/suite" -v "$HOME/.m2:/root/.m2" -w /suite \
  "$MAVEN_IMAGE" timeout "${EHKT_TIMEOUT:-1800}" mvn -B verify -Dfmt.skip -DskipUTs=true -Djacoco.skip=true \
  "-Dcucumber.filter.tags=$TAGS" \
  -Dtiger.lib.activateWorkflowUi=false -Dtiger.rbel.request.timeout=10 \
  -Dtiger.pssim.konnektor=$KON -Dkonnektor.$KON.url=https://127.0.0.1:8443 \
  -Dtiger.pssim.config.cetpServer.ipAddress=127.0.0.1 -Dtiger.pssim.config.cetpServer.port=4449 \
  -Dtiger.servers.cetpProxy.tigerProxyConfiguration.directReverseProxy.port=1234 \
  -Dconnector.$KON.login.connectorIp=127.0.0.1 "-Dconnector.$KON.login.password=$KMS_PASSWORD" \
  -Dtiger.smartcard.configuration.roboter_ip=127.0.0.1 -Dtiger.smartcard.configuration.roboter_port=9997 \
  > "$out/suite.log" 2>&1 || rc=$?
docker logs liana-ehkt > "$out/liana.log" 2>&1 || true
if [[ $SICCT == 1 ]]; then
  docker logs liana-ehkt-kartos > "$out/kartos.log" 2>&1 || true
  docker logs liana-ehkt-tiger > "$out/tiger-sicct.log" 2>&1 || true
  curl -sf -o "$out/tiger-sicct-report.html" "$TIGER_SICCT_URL/webui/getMessagesAsHtmlPage" || true
  curl -sf -o "$out/tiger-sicct.tgr" "$TIGER_SICCT_URL/webui/trafficLog.tgr" || true
fi
cleanup
cp -r "$SUITE_DIR/target/failsafe-reports" "$out/" 2>/dev/null || true
grep -E "Tests run:.*Fail" "$out/suite.log" | tail -1 | tee "$out/summary.txt" || true
echo "Report: $out"
exit $rc

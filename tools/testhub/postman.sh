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

# Konnektor PoPP Postman collections (konnektor-popp-testsuite) against LIANA in the Testhub stack (LIANA-40). Requires a
# running stack (tools/testhub/popp.sh up): popp-bridge talks to the popp-server directly via WebSocket
# (useSimulation=true, without ZETA), newman talks to LIANA via the docker-tiger-proxy (ip=liana, port 80; SOAP endpoints like popp-client liana:8082).
# Usage from the LIANA root directory:
#   tools/testhub/postman.sh up              build the popp-bridge image from the test suite and start it in the Testhub network
#   tools/testhub/postman.sh run [GF_002 …]  run collections (default all 17), report to support/traces/_runs/
#   tools/testhub/postman.sh down            stop popp-bridge
# KMS (GF_001, GF_015, FF_011, FF_012): LIANA with profile EHEX. The collections use {{ip}} for Konnektor and KMS,
# hence ip=liana without port: newman reaches the docker-tiger-proxy via Canopy (port 80, route liana → LIANA:8080),
# the popp-bridge (without Canopy) reaches LIANA directly, the KMS on kmsPort 9090 (management port, /rest/mgmt).
# POPP_SUITE_DIR (default ../konnektor-popp-testsuite), PORT_POPP_BRIDGE (8091, bridge from the host),
# POPP_BRIDGE_SERVER_URL (default ws://popp-server:8443/popp/practitioner/api/v1/token-generation-ehc).
set -euo pipefail

LIANA_DIR=$(pwd)
SUITE_DIR=${POPP_SUITE_DIR:-$LIANA_DIR/../konnektor-popp-testsuite}
SUITE_DIR=$(cd "$SUITE_DIR" && pwd)
COLLECTIONS_DIR=$SUITE_DIR/Postman/Collections
ENV_FILE=$LIANA_DIR/tools/testhub/postman/liana.postman_environment.json
RUNS=$LIANA_DIR/support/traces/_runs
RESOLV_CONF=$RUNS/liana-resolv.conf   # Canopy as resolver, written by popp.sh up: liana → docker-tiger-proxy
BRIDGE_IMAGE=popp-bridge:local
NEWMAN_IMAGE=postman/newman:6-alpine
SERVER_URL=${POPP_BRIDGE_SERVER_URL:-ws://popp-server:8443/popp/practitioner/api/v1/token-generation-ehc}

network() {
  docker inspect -f '{{range $n, $_ := .NetworkSettings.Networks}}{{$n}}{{end}}' tiger-canopy 2>/dev/null \
    || { echo "Testhub-Stack läuft nicht – erst tools/testhub/popp.sh up" >&2; exit 1; }
}

up() {
  local net
  net=$(network)
  docker build -q -t "$BRIDGE_IMAGE" "$SUITE_DIR/Postman/bridge" >/dev/null
  docker rm -f popp-bridge >/dev/null 2>&1 || true
  # The bridge only reads popp-server.sim-url (PoPPBridgeClient), POPP_SERVER_URL applies to /bridge/start/zeta.
  docker run -d --name popp-bridge --network "$net" --network-alias popp-bridge -p "${PORT_POPP_BRIDGE:-8091}:8081" \
    -e JAVA_TOOL_OPTIONS="-Dpopp-server.sim-url=$SERVER_URL" "$BRIDGE_IMAGE" >/dev/null
  for _ in $(seq 1 60); do
    curl -sf "http://localhost:${PORT_POPP_BRIDGE:-8091}/bridge/status" >/dev/null && break; sleep 1
  done
  echo "popp-bridge läuft (Suite $(git -C "$SUITE_DIR" rev-parse --short HEAD), PoPP-Server $SERVER_URL)."
}

run() {
  local net out names=("$@") rc=0
  net=$(network)
  [[ ${#names[@]} -gt 0 ]] || names=($(ls "$COLLECTIONS_DIR" | sed -n 's/^EE_KON_POPP_\(.*\)\.postman_collection\.json$/\1/p'))
  out=$RUNS/$(date +%Y%m%d-%H%M%S)-postman
  mkdir -p "$out"
  echo "konnektor-popp-testsuite $(git -C "$SUITE_DIR" rev-parse --short HEAD), Collections: ${names[*]}" > "$out/collections.txt"
  for n in "${names[@]}"; do
    local c=EE_KON_POPP_$n r=0
    curl -sf -X POST "http://localhost:${PORT_LIANA_ADMIN:-9090}/admin/reset" >/dev/null || echo "Warnung: POST /admin/reset fehlgeschlagen" >&2
    # vendor profile as kmsVendorName of the environment (EHEX): the KMS for findInLog & co. (LIANA-55)
    curl -sf -X PUT -H 'Content-Type: application/json' -d '{"vendor":"EHEX"}' \
      "http://localhost:${PORT_LIANA_ADMIN:-9090}/admin/vendor" >/dev/null || echo "Warnung: Profil EHEX nicht gesetzt" >&2
    # FF_005 needs an inserted HBA (LIANA-56); the boot YAML inserts none so that the popp-client only sees eGK and SMC-B
    [[ $n == FF_005 ]] && { curl -sf -X PUT -H 'Content-Type: application/json' -d '{"image":"hba-valid"}' \
      "http://localhost:${PORT_LIANA_ADMIN:-9090}/admin/terminals/KT-01/slots/3" >/dev/null || echo "Warnung: HBA nicht gesteckt" >&2; }
    docker run --rm --network "$net" -v "$RESOLV_CONF:/etc/resolv.conf:ro" \
      -v "$COLLECTIONS_DIR:/work/Collections:ro" -v "$ENV_FILE:/work/liana.postman_environment.json:ro" -v "$out:/out" \
      "$NEWMAN_IMAGE" run "/work/Collections/$c.postman_collection.json" -e /work/liana.postman_environment.json \
      --insecure --verbose -r cli,junit,json \
      --reporter-junit-export "/out/$c.xml" --reporter-json-export "/out/$c.json" > "$out/$c.log" 2>&1 || r=$?
    (( r == 0 )) && echo "grün  $n" || { echo "rot   $n"; rc=1; }
  done | tee "$out/summary.txt"
  grep -q '^rot' "$out/summary.txt" && rc=1
  docker logs liana > "$out/liana.log" 2>&1 || true
  docker logs popp-bridge > "$out/popp-bridge.log" 2>&1 || true
  echo "Report: $out"
  return $rc
}

case ${1:-} in
  up) up ;;
  run) shift; run "$@" ;;
  down) docker rm -f popp-bridge >/dev/null 2>&1 || true ;;
  *) sed -n '2,10p' "$0"; exit 2 ;;
esac

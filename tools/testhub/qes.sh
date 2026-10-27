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

# Konnektor QES suite (../tiger-konnektor-qes) against LIANA per vendor profile: Informationsmodell (LIANA-91), ExternalAuthenticate
# (KUC/HSK_1606_*, LIANA-64).
# LIANA runs as container liana-qes-<profile>-<product>, the suite via Maven in a second container in its
# network namespace: this way
# the suite's GEMCRYPT web service gets its hard-wired localhost:8080 (LIANA HTTP moves to 18080), and
# a running Testhub stack on the host does not interfere. The suite stays unchanged, its configuration (tiger.yaml,
# konnektor.yaml) is overridden via -D: Konnektor entry "koco" points to LIANA (credentials of the LIANA KMS, not the
# data from konnektor.yaml; the route ${konnektor.secunet.url} from tiger.yaml has no entry there, it also points
# to LIANA), Aufrufkontext as in the Informationsmodell below, CETP sink 127.0.0.1:7001 (the suite's cetpProxy),
# the suite's CATS process stays off, LIANA provides CATS REST (LIANA-67); the suite hard-codes http://127.0.0.1:9998,
# so LIANA opens the compatibility listener 9998 for KT-01 (LIANA-147). Cards are inserted 1 s after the
# CATS call (insert-delay): between inserting and waiting for CARD/INSERTED, KUC_1601_010 still sets the
# card response and expects the event afterwards. PSO CDS takes 60 ms per signature as on an HBA
# (signature-time): KUC_1602_072 aborts a batch of 80 after about 3.7 s, KUC_1602_073 expects it finished after about
# 7 s. The suite's konnektorClient
# (konnektor-service-client 1.6.2) addresses the KMS with a fixed port per vendor: KOCO 9443 (KoCoBox, LIANA-96),
# SECUNET 8500 (like EHEX), RISE 8443. For KOCO and SECUNET, LIANA_KMS_PORT opens the KMS compatibility listener
# (LIANA-146) on 9443 or 8500; RISE reaches the KMS without any setting on 8443, the HTTPS port of the
# Konnektor interface (LIANA-97). The
# card paths of the CATS steps are relative to the suite (resources/CardImages/…), so its resources/ is placed under
# /work/resources in LIANA.
# Usage from the LIANA root directory:
#   tools/testhub/qes.sh run KOCO|RISE|SECUNET [group|tag expression]   one profile (default: group basis)
#   tools/testhub/qes.sh all [group|tag expression]                      all three profiles in parallel
# Groups: basis (Informationsmodell, ExternalAuthenticate: what is green so far), per KUC/HSK group of the signature service
# (LIANA-112) sign-nonqes 1601, sign-qes 1602, verify-nonqes 1603, verify-qes 1604, defaults 1605, extauth 1606,
# iop 1607, comfort 1608, ecc 1609, signatur all 16xx. Both groups and tag expressions run with the vendor tag, per
# product separately, each with a fresh LIANA, like the suite's nightly (@EBK and @KOCO). Default is @EBK only;
# QES_PRODUCTS="EBK HSK" adds @HSK (first EBK, then HSK, for accepting a ticket).
# Parallel (LIANA-112.14): each profile runs with its own LIANA and suite container in its own network namespace and with
# its own copy of the suite under target/qes-suite/<profile> (rsync without target/ and .git, the suite stays
# unchanged), because Maven would otherwise write into the same target/. QES_PARALLEL=0 runs the profiles one after another.
# The batch scenarios KUC_1602_072/073 measure times; if they are red only in parallel, rerun them individually. The suite
# starts its test JVM with -Xmx8192m (pom.xml, cannot be overridden); three of them overwhelm a Docker VM with 16 GB
# (exit 137), so QES_SUITE_JAVA_OPTS (via JAVA_TOOL_OPTIONS) returns unused heap with Serial GC. That
# suffices for narrow tag lists; with the group signatur a test JVM gets killed even with two parallel suites
# (summary.txt: ABGEBROCHEN), so run the whole group only with QES_PARALLEL=0 (LIANA-112, about 1¼ h per profile and
# product, of which 1 h is the timer in KUC/HSK_1608_025).
# cancelled feature files carry "#@EBK"/"#@HSK" but still have vendor tags, and are thus left out.
# (@MODUS:Automatisch is no use: it is only on the first scenario of a file, KUC_1701_008 (RISE) for example lacks it.)
# The suite's OCSP responder (pkits :8084 behind ocspProxy :8083) starts with the suite in the network namespace of the
# LIANA container and is reachable there at 127.0.0.1:8083; OCSP responses, however, come from LIANA itself (decision-021).
# LIANA_IMAGE (default liana:qes, if set → no build; native e.g. liana:native), QES_SUITE_DIR (default
# ../tiger-konnektor-qes), MAVEN_IMAGE (default maven:3.9-eclipse-temurin-21), QES_PRODUCTS (default EBK),
# QES_PARALLEL (default 1). Run output goes to support/traces/_runs/.
set -euo pipefail

LIANA_DIR=$(pwd)
SUITE_DIR=$(cd "${QES_SUITE_DIR:-$LIANA_DIR/../tiger-konnektor-qes}" && pwd)
RUNS=$LIANA_DIR/support/traces/_runs
IMAGE=${LIANA_IMAGE:-liana:qes}
MAVEN_IMAGE=${MAVEN_IMAGE:-maven:3.9-eclipse-temurin-21}
PRODUCTS=${QES_PRODUCTS:-EBK}
PARALLEL=${QES_PARALLEL:-1}
COPIES=$LIANA_DIR/target/qes-suite
SUITE_JAVA_OPTS=${QES_SUITE_JAVA_OPTS:--XX:+UseSerialGC -XX:MinHeapFreeRatio=10 -XX:MaxHeapFreeRatio=20}
SCENARIOS='@KUC_1601_008 or @KUC_1603_008 or @KUC_1701_008 or @KUC_1701_031 or @KUC_1702_007 or @HSK_1601_008 or @HSK_1603_008 or @HSK_1701_008 or @HSK_1701_031 or @HSK_1702_007'
# ExternalAuthenticate (LIANA-64)
for n in $(seq -w 1 13); do SCENARIOS+=" or @KUC_1606_0$n or @HSK_1606_0$n"; done
# Groups of the signature service: feature tags @KUC_16nn_*/@HSK_16nn_* from the suite's feature files
kuc() {
  case $1 in
    sign-nonqes) echo 1601 ;; sign-qes) echo 1602 ;; verify-nonqes) echo 1603 ;; verify-qes) echo 1604 ;;
    defaults) echo 1605 ;; extauth) echo 1606 ;; iop) echo 1607 ;; comfort) echo 1608 ;; ecc) echo 1609 ;;
    signatur) echo '16[0-9][0-9]' ;; *) echo "Unbekannte Gruppe: $1" >&2; return 1 ;;
  esac
}
SMCB_ICCSN=80276883110000165043   # the suite's SMC_B_G21_A_80276883110000165043, SM-B_Verwaltet of M1 (KUC_1601_008: 4013)
SMCB_ICCSN_2=80276883110000168871 # SMC_B_G21_A_80276883110000168871 (ECC-only, KUC/HSK_1606_013), likewise for M1

start_liana() {
  local vendor=$1 name=$2 kms_port=8500
  [[ $vendor == KOCO ]] && kms_port=9443
  docker rm -f "$name" >/dev/null 2>&1 || true
  # Informationsmodell as in the suite's README: mandant m1 without SMC-B, assigned to workplace and Clientsystem
  docker run -d --name "$name" -v "$SUITE_DIR/resources:/work/resources:ro" \
    -e QUARKUS_HTTP_PORT=18080 -e LIANA_VENDOR="$vendor" -e LIANA_CATS_TERMINALS_0__PORT=9998 \
    -e LIANA_CATS_TERMINALS_0__INSERT_DELAY=1s \
    -e LIANA_INFRASTRUCTURE_TERMINALS_KT_01_SIGNATURE_TIME=60ms \
    -e LIANA_KMS_PORT=$kms_port \
    -e 'LIANA_INFOMODEL_MANDANTS_0_=M1' -e 'LIANA_INFOMODEL_MANDANTS_1_=m1' \
    -e 'LIANA_INFOMODEL_CLIENT_SYSTEMS_0_=CS1' -e 'LIANA_INFOMODEL_CLIENT_SYSTEMS_1_=cs1' \
    -e 'LIANA_INFOMODEL_WORKPLACES_0__MANDANTS_0_=M1' -e 'LIANA_INFOMODEL_WORKPLACES_0__MANDANTS_1_=m1' \
    -e 'LIANA_INFOMODEL_WORKPLACES_0__CLIENT_SYSTEMS_0_=CS1' -e 'LIANA_INFOMODEL_WORKPLACES_0__CLIENT_SYSTEMS_1_=cs1' \
    -e "LIANA_INFOMODEL_SMB_VERWALTET_0__ICCSN=$SMCB_ICCSN" -e 'LIANA_INFOMODEL_SMB_VERWALTET_0__MANDANTS_0_=M1' \
    -e "LIANA_INFOMODEL_SMB_VERWALTET_1__ICCSN=$SMCB_ICCSN_2" -e 'LIANA_INFOMODEL_SMB_VERWALTET_1__MANDANTS_0_=M1' \
    "$IMAGE" >/dev/null
  # upstream of the suite's cetpProxy (directReverseProxy localhost:1234): without a peer the Tiger proxy discards
  # the event instead of logging it (ignoreConnectionErrors does not help); socat accepts and discards it
  docker rm -f "$name-sink" >/dev/null 2>&1 || true
  docker run -d --name "$name-sink" --network "container:$name" alpine/socat \
    -u TCP-LISTEN:1234,fork,reuseaddr OPEN:/dev/null >/dev/null
  for _ in $(seq 1 60); do
    if docker logs "$name" 2>&1 | grep -q "Admin-API auf Port\|Listening on"; then
      # The scenarios insert their cards themselves and remove all of them afterwards (@RemoveAllCardsAfterTest); the cards of the
      # YAML boot state would be counted in the first scenario (two SMC-B → "multiple card handles"), so empty them
      docker run --rm --network "container:$name" curlimages/curl -fsS -X POST \
        http://127.0.0.1:9998/config/card/slots/reset >/dev/null
      return 0
    fi
    docker inspect -f '{{.State.Running}}' "$name" | grep -q true || break
    sleep 1
  done
  docker logs "$name" >&2; echo "LIANA startet nicht" >&2; return 1
}

# group or tag expression → tag expression without vendor and product
selection() {
  local selection=${1:-basis} nr
  if [[ $selection == basis ]]; then
    echo "$SCENARIOS"
  elif [[ $selection =~ ^[a-z-]+$ ]]; then
    nr=$(kuc "$selection") || return 1
    grep -rhoE "^@(KUC|HSK)_${nr}_[0-9]+$" "$SUITE_DIR/src/test/resources/features" | sort -u \
      | paste -sd ' ' - | sed 's/ / or /g'
  else
    echo "$selection"
  fi
}

# A separate run per product with a fresh LIANA, like the suite's nightly (@EBK and @KOCO): the HSK scenarios
# do not switch MGM_LU_ONLINE and assume the boot state; after KUC_1601_026 ("offline") HSK_1601_022 would otherwise
# get 1039 with KOCO. If the expression names only KUC or only HSK tags, the other run is skipped.
run() {
  local vendor=$1 expr rc=0 product
  expr=$(selection "${2:-}") || return 1
  for product in $PRODUCTS; do
    if [[ $product == EBK ]]; then
      [[ $expr == *@HSK_* && $expr != *@KUC_* ]] || run_product "$vendor" EBK "$expr" || rc=1
    else
      [[ $expr == *@KUC_* && $expr != *@HSK_* ]] || run_product "$vendor" HSK "$expr" || rc=1
    fi
  done
  return $rc
}

# Own copy of the suite per profile (without target/ and .git): parallel runs would otherwise share target/
suite_copy() {
  local copy=$COPIES/$(echo "$1" | tr '[:upper:]' '[:lower:]')
  mkdir -p "$copy"
  rsync -a --delete --exclude /target --exclude /.git "$SUITE_DIR/" "$copy/"
  echo "$copy"
}

run_product() {
  local vendor=$1 product=$2 tags out rc=0 id name suite
  tags="($3) and @$vendor and @$product"
  id=$(echo "$vendor-$product" | tr '[:upper:]' '[:lower:]')
  name=liana-qes-$id
  out=$RUNS/$(date +%Y%m%d-%H%M%S)-qes-$id
  mkdir -p "$out"
  echo "tiger-konnektor-qes $(git -C "$SUITE_DIR" rev-parse --short HEAD), LIANA $(git rev-parse --short HEAD) ($IMAGE), Profil $vendor, Tags: $tags" > "$out/run.txt"
  echo "$vendor $product: $out"
  suite=$(suite_copy "$vendor")
  start_liana "$vendor" "$name"
  docker run --rm --name "$name-suite" --network "container:$name" -v "$suite:/suite" -v "$HOME/.m2:/root/.m2" \
    -w /suite -e "JAVA_TOOL_OPTIONS=$SUITE_JAVA_OPTS" \
    "$MAVEN_IMAGE" mvn -B verify -Dfmt.skip -DskipTests=false -Dsurefire.skip=true \
    "-Dcucumber.filter.tags=$tags" \
    -Dtiger.servers.catsCommandline.active=false \
    -Dtiger.pssim.konnektor=koco \
    -Dkonnektor.koco.url=https://127.0.0.1:8443 -Dkonnektor.koco.username=super '-Dkonnektor.koco.password=33ee§§EE' \
    -Dkonnektor.secunet.url=https://127.0.0.1:8443 -Dkonnektor.secunet.tigerProxyRoute=/secunet \
    -Dtiger.pssim.config.context.clientSystemId=CS1 -Dtiger.pssim.config.context.mandantId=M1 \
    -Dtiger.pssim.config.context.workplaceId=WP1 -Dtiger.pssim.config.context.userId=bert \
    -Dtiger.pssim.config.cetpServer.ipAddress=127.0.0.1 -Dtiger.pssim.config.cetpServer.port=7001 \
    > "$out/suite.log" 2>&1 || rc=$?
  docker logs "$name" > "$out/liana.log" 2>&1 || true
  docker rm -f "$name-sink" "$name" >/dev/null 2>&1 || true
  rm -rf "$out/failsafe-reports"
  cp -r "$suite/target/failsafe-reports" "$out/" 2>/dev/null || true
  grep -E "Tests run:.*Fail" "$out/suite.log" | tail -1 > "$out/summary.txt" || true
  # If memory kills the test JVM (Killed), a harmless intermediate summary precedes it: the run is incomplete
  if grep -qE "^Killed|forked VM terminated" "$out/suite.log"; then
    echo "ABGEBROCHEN: Test-JVM der Suite beendet (Killed), Ergebnis unvollständig; $(cat "$out/summary.txt")" > "$out/summary.txt"
    rc=1
  fi
  echo "$vendor $product: $(cat "$out/summary.txt") → $out"
  return $rc
}

case ${1:-} in
  run) shift; [[ -n ${LIANA_IMAGE:-} ]] || docker build -q -t "$IMAGE" "$LIANA_DIR" >/dev/null; run "$@" ;;
  all) shift; [[ -n ${LIANA_IMAGE:-} ]] || docker build -q -t "$IMAGE" "$LIANA_DIR" >/dev/null
       rc=0
       if [[ $PARALLEL == 1 ]]; then
         pids=()
         for v in KOCO RISE SECUNET; do run "$v" "${1:-}" & pids+=($!); done
         for pid in "${pids[@]}"; do wait "$pid" || rc=1; done
       else
         for v in KOCO RISE SECUNET; do run "$v" "${1:-}" || rc=1; done
       fi
       exit $rc ;;
  *) sed -n '2,/^set -euo/p' "$0" | sed '$d'; exit 2 ;;
esac

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

# Konnektor E2E suite (../tiger-konnektor-e2e) against LIANA: the automatic CATS_CS scenarios (EE_KON_CS_*,
# EE_HSK_CS_* with @MODUS:Automatisch, LIANA-65) with vendor profile EHEX. The semi-automatic CATS_CS scenarios
# pause for Wireshark checks (TGR pausiere …) and only run with the Workflow UI.
# LIANA runs as container liana-e2e, the suite via Maven in a second container in its network namespace: this way
# the suite's GEMCRYPT web service gets its hard-wired localhost:8080 (LIANA HTTP moves to 18080), and
# a running Testhub stack on the host does not interfere. The suite stays unchanged, its configuration (tiger.yaml,
# konnektor.yaml, vendorData/) is overridden via -D: Konnektor entry kon66Secunet (vendorData: KMS vendor
# EHEX, port 8500, set to the management port 9090 here) points to LIANA, with the credentials of the LIANA KMS (not the data from konnektor.yaml), Aufrufkontext
# as in the Informationsmodell of application.yaml (M1/CS1/WP1). None of the automatic scenarios needs cards.
# Usage from the LIANA root directory:
#   tools/testhub/e2e.sh [tag expression]   default: the automatic CATS_CS scenarios
# LIANA_IMAGE (default liana:e2e, if set → no build), E2E_SUITE_DIR (default ../tiger-konnektor-e2e), MAVEN_IMAGE
# (default maven:3.9-eclipse-temurin-21). Run output goes to support/traces/_runs/.
set -euo pipefail

LIANA_DIR=$(pwd)
SUITE_DIR=$(cd "${E2E_SUITE_DIR:-$LIANA_DIR/../tiger-konnektor-e2e}" && pwd)
RUNS=$LIANA_DIR/support/traces/_runs
IMAGE=${LIANA_IMAGE:-liana:e2e}
MAVEN_IMAGE=${MAVEN_IMAGE:-maven:3.9-eclipse-temurin-21}
KON=kon66Secunet
SCENARIOS=""
for id in KON_CS_ECC_001 KON_CS_ECC_002 KON_CS_ECC_005 KON_CS_ECC_006 KON_CS_RSA_003 KON_CS_RSA_004 KON_CS_RSA_005 \
  KON_CS_RSA_006 HSK_CS_ECC_001 HSK_CS_ECC_002 HSK_CS_ECC_005 HSK_CS_ECC_006 HSK_CS_RSA_003 HSK_CS_RSA_004 \
  HSK_CS_RSA_005 HSK_CS_RSA_006; do
  SCENARIOS+="${SCENARIOS:+ or }@TCID:EE_$id"
done
TAGS=${1:-"($SCENARIOS) and @MODUS:Automatisch"}
# The suite's failsafe configuration registers the listener org.sonar.java.jacoco.JUnitListener without declaring it as
# a dependency; without it failsafe aborts before the first scenario (ClassNotFoundException)
SONAR_LISTENER=/root/.m2/repository/org/sonarsource/java/sonar-jacoco-listeners/5.14.0.18788/sonar-jacoco-listeners-5.14.0.18788.jar
[[ -f $HOME/.m2/repository/org/sonarsource/java/sonar-jacoco-listeners/5.14.0.18788/sonar-jacoco-listeners-5.14.0.18788.jar ]] ||
  docker run --rm -v "$HOME/.m2:/root/.m2" "${MAVEN_IMAGE:-maven:3.9-eclipse-temurin-21}" mvn -B -q dependency:get \
    -Dartifact=org.sonarsource.java:sonar-jacoco-listeners:5.14.0.18788

[[ -n ${LIANA_IMAGE:-} ]] || docker build -q -t "$IMAGE" "$LIANA_DIR" >/dev/null
out=$RUNS/$(date +%Y%m%d-%H%M%S)-e2e-ehex
mkdir -p "$out"
echo "tiger-konnektor-e2e $(git -C "$SUITE_DIR" rev-parse --short HEAD), LIANA $(git rev-parse --short HEAD) ($IMAGE), Profil EHEX, Tags: $TAGS" | tee "$out/run.txt"

docker rm -f liana-e2e >/dev/null 2>&1 || true
docker run -d --name liana-e2e -e QUARKUS_HTTP_PORT=18080 -e LIANA_VENDOR=EHEX "$IMAGE" >/dev/null
for _ in $(seq 1 60); do
  docker logs liana-e2e 2>&1 | grep -q "Admin-API auf Port\|Listening on" && break
  docker inspect -f '{{.State.Running}}' liana-e2e | grep -q true || { docker logs liana-e2e >&2; exit 1; }
  sleep 1
done

rc=0
docker run --rm --network container:liana-e2e -v "$SUITE_DIR:/suite" -v "$HOME/.m2:/root/.m2" -w /suite \
  "$MAVEN_IMAGE" mvn -B verify -Dfmt.skip -DskipTests=false -Dsurefire.skip=true \
  "-Dcucumber.filter.tags=$TAGS" \
  -Dmaven.test.additionalClasspath=$SONAR_LISTENER \
  -Dtiger.lib.activateWorkflowUi=false \
  -Dtiger.pssim.konnektor=$KON \
  -Dkonnektor.$KON.ip=127.0.0.1 -Dkonnektor.$KON.url=https://127.0.0.1:8443 \
  -Dkonnektor.$KON.username=super "-Dkonnektor.$KON.password=33ee§§EE" \
  -Dlogin.username=super "-Dlogin.password=33ee§§EE" -Dlogin.connectorPort=9090 \
  -Dtiger.pssim.config.context.clientSystemId=CS1 -Dtiger.pssim.config.context.mandantId=M1 \
  -Dtiger.pssim.config.context.workplaceId=WP1 -Dtiger.pssim.config.context.userId=bert \
  -Dtiger.pssim.config.cetpServer.ipAddress=127.0.0.1 -Dtiger.pssim.config.cetpServer.port=7001 \
  > "$out/suite.log" 2>&1 || rc=$?
docker logs liana-e2e > "$out/liana.log" 2>&1 || true
docker rm -f liana-e2e >/dev/null 2>&1 || true
cp -r "$SUITE_DIR/target/failsafe-reports" "$out/" 2>/dev/null || true
grep -E "Tests run:.*Fail" "$out/suite.log" | tail -1 | tee "$out/summary.txt" || true
echo "Report: $out"
exit $rc

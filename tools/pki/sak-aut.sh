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

# ID.SAK.AUT for the Konnektor's TLS connection to eHealth KTs (LIANA-75, TUC_KON_050 step 3): brainpoolP256r1,
# issued by the existing LIANA Komp-CA (support/pki/server/komp-ca.*, tools/pki/konnektor-tls.sh), the rest of the
# test PKI stays unchanged. Test material only. Writes support/pki/server/sak-aut-bp256.{pem,p12}; afterwards, origin and
# fingerprint belong in support/pki/server/SOURCE.md.
#
#   tools/pki/sak-aut.sh
set -euo pipefail

cd "$(dirname "$0")/../.."
SERVER=support/pki/server
PASS=liana
DAYS=1826                       # A_24483: 5 years for TLS certificates
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:brainpoolP256r1 -pkeyopt ec_param_enc:named_curve \
  -out "$tmp/sak-aut.key.pem"
openssl req -new -key "$tmp/sak-aut.key.pem" -subj "/C=DE/O=LIANA NOT-VALID/CN=LIANA ID.SAK.AUT bp256 TEST-ONLY" \
  -out "$tmp/sak-aut.csr"
openssl x509 -req -in "$tmp/sak-aut.csr" -CA "$SERVER/komp-ca.pem" -CAkey "$SERVER/komp-ca.key.pem" \
  -set_serial "0x$(openssl rand -hex 8)" -sha256 -days "$DAYS" -out "$SERVER/sak-aut-bp256.pem" \
  -extfile <(printf '%s\n' "basicConstraints=critical,CA:FALSE" "keyUsage=critical,digitalSignature" \
    "extendedKeyUsage=clientAuth")
openssl pkcs12 -export -inkey "$tmp/sak-aut.key.pem" -in "$SERVER/sak-aut-bp256.pem" -certfile "$SERVER/komp-ca.pem" \
  -name sak-aut -passout "pass:$PASS" -out "$SERVER/sak-aut-bp256.p12"
printf '%s  %s  bis %s\n' "$SERVER/sak-aut-bp256.pem" \
  "$(openssl x509 -in "$SERVER/sak-aut-bp256.pem" -noout -fingerprint -sha256 | cut -d= -f2)" \
  "$(openssl x509 -in "$SERVER/sak-aut-bp256.pem" -noout -enddate | cut -d= -f2)"

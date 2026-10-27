#!/bin/sh
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

# Fresh TSL for the image (LIANA-180): downloads the TSL from <url> and uses it if it is complete, contains CA certificates
# and its TSLSequenceNumber is not lower than that of the checked-in copy; otherwise the copy, with a warning.
# Never fails (the online TSL must not break a build). Runs in the Docker build (stage tsl of the Dockerfiles), also locally.
# Usage: tools/pki/tsl-fetch.sh <checked-in TSL> <target> [<url>]   (default URL: RU)
set -u
baseline=$1
target=$2
url=${3:-https://download-ref.tsl.ti-dienste.de/ECC/ECC-RSA_TSL-ref.xml}
mkdir -p "$(dirname "$target")"
fetched=$target.download

seq() { grep -o 'TSLSequenceNumber>[0-9]*<' "$1" | head -1 | tr -dc '0-9'; }

baseline_seq=$(seq "$baseline")
reason=""
if ! curl -fsSL --retry 2 --connect-timeout 10 --max-time 60 -o "$fetched" "$url" 2>"$fetched.err"; then
  reason="Abruf gescheitert: $(tail -1 "$fetched.err")"
elif ! tail -c 200 "$fetched" | grep -q 'TrustServiceStatusList>'; then
  reason="unvollständig (kein Ende von TrustServiceStatusList)"
elif ! grep -q 'X509Certificate>' "$fetched"; then
  reason="ohne X509Certificate"
else
  fetched_seq=$(seq "$fetched")
  if [ -z "$fetched_seq" ]; then
    reason="ohne TSLSequenceNumber"
  elif [ -n "$baseline_seq" ] && [ "$fetched_seq" -lt "$baseline_seq" ]; then
    reason="SequenceNumber $fetched_seq älter als die eingecheckte $baseline_seq"
  fi
fi

if [ -z "$reason" ]; then
  mv "$fetched" "$target"
  echo "TSL: $url, SequenceNumber $(seq "$target"), SHA-256 $(sha256sum "$target" | cut -c1-16)…"
else
  cp "$baseline" "$target"
  echo "WARNUNG TSL: $url $reason; eingecheckte Kopie, SequenceNumber $baseline_seq, SHA-256 $(sha256sum "$target" | cut -c1-16)…"
fi
rm -f "$fetched" "$fetched.err"
exit 0

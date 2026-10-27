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

# Converts gematik spec PDFs to docs/specs/text/<name>.txt (UTF-8, LF).
# Afterwards rebuild the AFO index:
#   python3 -I tools/specs/afo_index.py docs/specs/text support/afo/afo-index.csv
# Requires: pdftotext (poppler-utils).
set -euo pipefail

if [[ $# -eq 0 ]]; then
  echo "Aufruf: $0 <spec.pdf> [...]" >&2
  exit 2
fi

root="$(cd "$(dirname "$0")/../.." && pwd)"
out="$root/docs/specs/text"
mkdir -p "$out"

for pdf in "$@"; do
  name="$(basename "$pdf" .pdf)"
  pdftotext -enc UTF-8 "$pdf" "$out/$name.txt"
  perl -pi -e 's/\r$//' "$out/$name.txt"
  echo "$pdf -> docs/specs/text/$name.txt"
done
echo "Nicht vergessen: docs/specs/INDEX.md ergänzen und AFO-Index neu bauen."

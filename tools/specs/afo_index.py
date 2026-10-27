#!/usr/bin/env python3
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

"""Builds support/afo/afo-index.csv from the spec texts in docs/specs/text/.

gematik AFOs have the form
    <AFO-ID> -<title>
    <Text ...>
    [<=]
Index columns: afo_id;spec;zeile;abschnitt;titel;kurztext
`zeile` is 1-based and matches `Read <file> offset=<zeile>`.

Usage (from the repo root):
    python3 -I tools/specs/afo_index.py docs/specs/text support/afo/afo-index.csv
"""
import csv
import re
import sys
from pathlib import Path

AFO_START = re.compile(
    r"^(?P<id>(?:[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*-)?A_\d+(?:-\d+)?)\s+-\s*(?P<title>.*)$"
)
AFO_END = "[<=]"
# Section heading, but not a table-of-contents line ("..... 12")
SECTION = re.compile(r"^(?P<num>\d+(?:\.\d+)*)\s+(?P<name>[^\s.].{2,120})$")
TOC_LINE = re.compile(r"\.{4,}\s*\d+\s*$")
NOISE = re.compile(r"^(input\.docx|Version: |Seite \d+ von \d+|© gematik|\f)")
MAX_TEXT = 400


def spec_name(path: Path) -> str:
    return path.stem


def scan(path: Path):
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    section = ""
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        m_sec = SECTION.match(line)
        if m_sec and not TOC_LINE.search(line):
            section = f"{m_sec['num']} {m_sec['name'].strip()}"
        m = AFO_START.match(line)
        if not m:
            i += 1
            continue
        start = i
        body = [m["title"]]
        j = i + 1
        closed = AFO_END in line
        while j < len(lines) and not closed and j - i < 400:
            nxt = lines[j].strip()
            if AFO_START.match(nxt):  # next AFO without a proper end marker
                break
            if not NOISE.match(nxt):
                body.append(nxt)
            if AFO_END in nxt:
                closed = True
            j += 1
        title = m["title"].replace(AFO_END, "").strip()
        text = " ".join(b for b in body[1:] if b).replace(AFO_END, "").strip()
        text = re.sub(r"\s+", " ", text)
        if len(text) > MAX_TEXT:
            text = text[: MAX_TEXT - 1] + "…"
        yield {
            "afo_id": m["id"],
            "spec": spec_name(path),
            "zeile": start + 1,
            "abschnitt": section,
            "titel": title,
            "kurztext": text,
        }
        i = j if closed else i + 1


def main(src: str, dst: str) -> int:
    src_dir, out = Path(src), Path(dst)
    rows = []
    for path in sorted(src_dir.glob("*.txt")):
        rows.extend(scan(path))
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=["afo_id", "spec", "zeile", "abschnitt", "titel", "kurztext"],
            delimiter=";",
        )
        w.writeheader()
        w.writerows(rows)
    specs = {r["spec"] for r in rows}
    print(f"{len(rows)} AFOs aus {len(specs)} Specs -> {out}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1], sys.argv[2]))

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

"""License notices of the Rust crates linked into the kartos binaries (THIRD-PARTY-NOTICES.txt).

Called from tools/kartos/build.sh with the kartos checkout and the features of the build:

    python3 -I tools/kartos/third-party-notices.py <kartos-checkout> <features> > tools/kartos/THIRD-PARTY-NOTICES.txt

The crates come from `cargo tree` (normal dependencies of kartos-cli, all four binary targets), the texts from
the LICENSE, COPYING and NOTICE files of the crate sources (`cargo fetch`). Identical texts appear only once, with
all crates that ship them. kartos' own crates are covered by tools/kartos/LICENSE.
"""

import json
import os
import subprocess
import sys

TARGETS = ["x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl", "aarch64-apple-darwin", "x86_64-apple-darwin"]
PREFIXES = ("LICENSE", "LICENCE", "COPYING", "NOTICE", "COPYRIGHT", "UNLICENSE")


def cargo(src, *args):
    return subprocess.run(["cargo", *args], cwd=src, check=True, capture_output=True, text=True).stdout


def crates(src, features):
    found = {}
    for target in TARGETS:
        out = cargo(src, "tree", "--locked", "-p", "kartos-cli", "--no-default-features", "--features", features,
                    "-e", "normal", "--target", target, "--prefix", "none", "--format", "{p}|{l}")
        for line in out.splitlines():
            package, license_expr = line.split("|", 1)
            name, version = package.split(" ")[:2]
            if not (name.startswith("kartos") or name == "brainpool-rustls"):
                found[(name, version.lstrip("v"))] = license_expr.replace(" (*)", "").replace(" (proc-macro)", "")
    return found


def main():
    src, features = sys.argv[1], sys.argv[2]
    cargo(src, "fetch", "--locked", "-q")
    meta = json.loads(cargo(src, "metadata", "--locked", "--format-version", "1"))
    packages = {(p["name"], p["version"]): p for p in meta["packages"]}
    texts = {}
    listing = []
    for key, license_expr in sorted(crates(src, features).items()):
        package = packages[key]
        directory = os.path.dirname(package["manifest_path"])
        files = [f for f in sorted(os.listdir(directory)) if f.upper().startswith(PREFIXES)]
        if package.get("license_file") and package["license_file"] not in files:
            files.append(package["license_file"])
        if not files:
            sys.exit(f"{key[0]} {key[1]}: keine Lizenzdatei")
        listing.append(f"{key[0]} {key[1]} ({license_expr}) {package.get('repository') or ''}".rstrip())
        for f in files:
            with open(os.path.join(directory, f), encoding="utf-8", errors="replace") as handle:
                text = handle.read().strip()
            texts.setdefault(text, []).append(f"{key[0]} {key[1]} ({f})")

    print("Third-party software in the kartos binaries (tools/kartos/kartos-*)")
    print("=" * 67)
    print()
    print("kartos itself is licensed under the Apache License 2.0 (tools/kartos/LICENSE). The binaries statically link")
    print(f"the following {len(listing)} Rust crates. For crates offered under a choice of licenses, all license texts")
    print("shipped by the crate are reproduced below.")
    print()
    print("\n".join(listing))
    for text, users in texts.items():
        print()
        print("-" * 80)
        print("Used by: " + ", ".join(users))
        print("-" * 80)
        print()
        print(text)


if __name__ == "__main__":
    main()

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

"""ID.SMKT.AUT of a gSMC-KT from the card image as PKCS#12 (LIANA-81).

Like kartos terminal (crates/kartos-terminal/src/tls/mod.rs, extract_tls_material), picks the first
brainpoolP256r1 X.509 certificate in the image and the private key whose attribute P matches the
certificate. A Tiger proxy on the SICCT path uses it to identify itself to LIANA as this KT.

Usage: python3 -I tools/pki/smkt-identity.py support/images/gsmckt-valid.xml support/pki/kt/smkt-aut-gsmckt-valid.p12 liana
"""
import sys
import xml.etree.ElementTree as ET

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, pkcs12, BestAvailableEncryption

image, out, password = sys.argv[1:4]
nodes = list(ET.parse(image).iter("child"))


def attrs(node):
    return {a.get("id"): (a.text or "").strip() for a in node.findall("./attributes/attribute")}


def brainpool_cert(body):
    try:
        cert = x509.load_der_x509_certificate(bytes.fromhex(body))
    except ValueError:
        return None
    key = cert.public_key()
    return cert if isinstance(key, ec.EllipticCurvePublicKey) and key.curve.name == "brainpoolP256r1" else None


cert = next(c for c in (brainpool_cert(attrs(n).get("body", "")) for n in nodes
                        if n.get("objectType") == "TransparentElementaryFile") if c)
point = cert.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint).hex().upper()
scalar = next(a["privateKey"] for a in map(attrs, nodes) if a.get("P", "").upper() == point)
key = ec.derive_private_key(int(scalar, 16), ec.BrainpoolP256R1())
with open(out, "wb") as f:
    f.write(pkcs12.serialize_key_and_certificates(b"smkt-aut", key, cert, None,
                                                   BestAvailableEncryption(password.encode())))
print(f"{out}: {cert.subject.rfc4514_string()}, gültig bis {cert.not_valid_after_utc:%Y-%m-%d}")

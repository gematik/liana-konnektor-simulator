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

"""Test PoPP service for the Trusted Channel (elcSessionkey4SM, gemSpec_COS 15): CVC chain and key (LIANA-28).

A kartos IT uses it to act as the PoPP service towards LIANA (hop A). `kartos pipe --anchors support/pki/sm/anchors`
registers the root as trust anchor, the PoPP service imports its end-entity CVC via MSE SET DST and PSO VERIFY
CERTIFICATE as in the real flow; LIANA picks up the key along the way. Profile as in gemSpec_PKI 6.4 (CPI 70,
brainpoolP256r1, CHAT oid_cvc_fl_ti): the root with ecdsa-with-SHA256 and all flags as in Tab_PKI_937, the PoPP service with
authS_gemSpec-COS-G2_ecc-with-sha256 without flags; both signed with ECDSA-SHA256 over the body, the root self-signed. Test material only, unrelated to the TI test PKI.

Usage: python3 -I tools/pki/sm-popp-cvc.py support/pki/sm
"""
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

ROOT = bytes.fromhex("4445544553540001")         # "DETEST" || 00 01
CHR = bytes.fromhex("000A80276001011699902801")  # 12 bytes, like CHRs derived from an ICCSN
OID_AUTH_ECC_SHA256 = bytes.fromhex("2B2403050301")  # 1.3.36.3.5.3.1
OID_ECDSA_SHA256 = bytes.fromhex("2A8648CE3D040302")  # 1.2.840.10045.4.3.2, verification key of the root
OID_CVC_FL_TI = bytes.fromhex("2A8214004C048118")    # 1.2.276.0.76.4.152
EFFECTIVE = bytes([2, 6, 1, 0, 0, 1])            # 2026-10-01
EXPIRATION = bytes([4, 9, 1, 2, 3, 1])           # 2049-12-31
ROOT_FLAGS = bytes([0xFF] * 7)                   # root as in Tab_PKI_937: b0 b1 = 11 (CA, root)


def tlv(tag: bytes, value: bytes) -> bytes:
    n = len(value)
    length = bytes([n]) if n < 0x80 else (bytes([0x81, n]) if n <= 0xFF else bytes([0x82, n >> 8, n & 0xFF]))
    return tag + length + value


def cvc(car: bytes, chr_: bytes, oid: bytes, flags: bytes, subject: ec.EllipticCurvePrivateKey,
        signer: ec.EllipticCurvePrivateKey) -> bytes:
    point = subject.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    body = tlv(b"\x7F\x4E",
               tlv(b"\x5F\x29", b"\x70")
               + tlv(b"\x42", car)
               + tlv(b"\x7F\x49", tlv(b"\x06", oid) + tlv(b"\x86", point))
               + tlv(b"\x5F\x20", chr_)
               + tlv(b"\x7F\x4C", tlv(b"\x06", OID_CVC_FL_TI) + tlv(b"\x53", flags))
               + tlv(b"\x5F\x25", EFFECTIVE)
               + tlv(b"\x5F\x24", EXPIRATION))
    r, s = decode_dss_signature(signer.sign(body, ec.ECDSA(hashes.SHA256())))
    return tlv(b"\x7F\x21", body + tlv(b"\x5F\x37", r.to_bytes(32, "big") + s.to_bytes(32, "big")))


out = Path(sys.argv[1])
(out / "anchors").mkdir(parents=True, exist_ok=True)
root = ec.generate_private_key(ec.BrainpoolP256R1())
popp = ec.generate_private_key(ec.BrainpoolP256R1())
(out / "anchors" / "root.cvc").write_bytes(cvc(ROOT, ROOT, OID_ECDSA_SHA256, ROOT_FLAGS, root, root))
(out / "popp.cvc").write_bytes(cvc(ROOT, CHR, OID_AUTH_ECC_SHA256, bytes(7), popp, root))
(out / "popp-key.pem").write_bytes(popp.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                      serialization.NoEncryption()))
print(f"{out}/anchors/root.cvc (CHR {ROOT.hex().upper()}), {out}/popp.cvc (CHR {CHR.hex().upper()}), {out}/popp-key.pem")

# Signer-Zertifikate PoPP (nur Zertifikate, keine Schlüssel)

Signer von SignedScenarios, wie sie bei SecureSendAPDU im x5c-Header ankommen. Tests prüfen damit TUC_KON_037
gegen die TSL aus `../tsl/`.

| Datei | Aussteller | Rolle (Admission) | Herkunft |
|---|---|---|---|
| `tu-apdu-sig-oid_popp.pem` | GEM.KOMP-CA55 TEST-ONLY | oid_popp 1.2.276.0.76.4.293 | x5c[0] im Trace `support/vendor/traces/popp-kon-tu/popp-client.tgr` (PoPP-Service der TU, `apdu-sig.ru.popp.rise`) |
| `bridge-oid_popp.pem` | GEM.KOMP-CA61 TEST-ONLY | oid_popp | konnektor-popp-testsuite `popp-bridge/.../certs/oid293` (Stand dbe8cfb); gleiches Zertifikat wie im Testhub-Image `gematik1/popp-server:2.9.0` |
| `bridge-oid_popp-token.pem` | GEM.KOMP-CA61 TEST-ONLY | oid_popp-token 1.2.276.0.76.4.320 | `.../certs/oid320`, signiert in EE_KON_POPP_FF_013 neu → 4700 |
| `bridge-oid_tigw_zugm.pem` | GEM.KOMP-CA55 TEST-ONLY | oid_tigw_zugm 1.2.276.0.76.4.309, C.FD.OSIG | `.../certs/oid309`, signiert in EE_KON_POPP_FF_016 neu → 4700 |

Gültig bis 2030 (KOMP-CA61) bzw. 2031 (KOMP-CA55). Alle TEST-ONLY / NOT-VALID.

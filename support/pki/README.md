# Test-PKI

Nur Testmaterial, keine echten Identitäten, keine Produktivschlüssel.

| Verzeichnis | Inhalt | Gebraucht ab |
|---|---|---|
| `tsl/` (vorhanden) | RU-TSL der gematik; Quelle der CA-Zertifikate für TUC_KON_037 (`liana.pki.tsl`) | LIANA-24 |
| `popp/` (vorhanden) | Signer-Zertifikate PoPP (oid_popp, oid_popp-token, oid_tigw_zugm), nur Zertifikate | LIANA-24 |
| `replay/` (vorhanden) | Replay-CA und Signer im PoPP-Profil, nur Tests: Szenarien für SecureSendAPDU neu signieren (`liana.pki.imported-cas`) | LIANA-23/24 |
| `ocsp/` | OCSP-Responder-Zertifikate bzw. statische Responses; LIANA prüft offline (offlineAllowNoCheck) | bei Bedarf |
| `kt/` (vorhanden) | ID.SMKT.AUT der Test-gSMC-KT `gsmckt-valid` als PKCS#12, für den Tiger-Proxy in der SICCT-Strecke (`tools/pki/smkt-identity.py`); ID.SAK.AUT liegt unter `server/` | LIANA-81 |
| `server/` (vorhanden) | ID.AK.AUT / TLS-Serveridentität zum Primärsystem und KMS, Komp-CA (`tools/pki/konnektor-tls.sh`) | LIANA-58 |
| `sm/` (vorhanden) | Test-PoPP-Service mit eigener CVC-Root (`anchors/root.cvc`, `popp.cvc`, Schlüssel), nur kartos-ITs für den Trusted Channel (`tools/pki/sm-popp-cvc.py`) | LIANA-28 |
| `clients/` (vorhanden) | Client-Zertifikate der Clientsysteme (ANCL_CCERT_LIST), PKCS#12 für den `.kon`-Export | LIANA-58 |

Jede Datei bekommt in `SOURCE.md` Herkunft und Ablaufdatum.

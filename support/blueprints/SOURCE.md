# APDU-Blueprints

Referenz-APDU-Sequenzen: die SignedScenarios, die der PoPP-Service je Sequenz schickt. Testhub-PoPP vergleicht sie im
Tiger-Traffic mit diesen Dateien (`ApduValidator`), je nach Pfad unterschiedlich:

- Konnektor-Pfad (`CONTACT_CONNECTOR`, `validateApdusforEHealthKT`): Sequenzen **0, 1, 3**; Sequenz 2 prüft der Testhub
  hier nicht. Derzeit ruft das eH-KT-Szenario die Prüfung gar nicht auf: der Schritt „die empfangenen APDUs sind
  korrekt“ ist in `UC_PoPP_1_2a_Valid.feature:82` auskommentiert (gematik-Commit f23ed802); reaktiviert mit LIANA-44.
- Standard-Kartenleser (`CONTACT_STANDARD`/`_VIRTUAL`, `validateApdusforStdKT`): Sequenzen 0, 1, 2.

| Datei | Szenario | Inhalt | Konnektor-Pfad |
|---|---|---|---|
| `poppApdusSequence0.json` | SceOpenEgk | SELECT eGK-Root `D2760001448000`, READ BINARY SFI 11 | geprüft; im TU-Lauf identisch |
| `poppApdusSequence1.json` | SceReadCvc | READ BINARY SFI 07, SFI 06, GET DATA | geprüft; im TU-Lauf identisch |
| `poppApdusSequence2.json` | Trusted Channel | MSE SET AT + GENERAL AUTHENTICATE | **das schickt der PoPP-Service auch auf dem Konnektor-Pfad** (TU-Lauf `support/vendor/traces/popp-kon-tu/`, byteidentisch); nicht geprüft |
| `poppApdusSequence2Connector.json` | Trusted Channel mit CVC-Kette | MSE SET AT, 2× (MSE SET DST + PSO VERIFY CERTIFICATE), GENERAL AUTHENTICATE | im TU-Lauf nicht gesehen, in der Suite ungenutzt (`VALID_APDU_SEQUENCE_2_CONNECTOR_FILE`); LIANA-Trace-Tests spielen ihn statt Sequenz 2 ab, weil egk-valid den CV-Schlüssel des PoPP-Service erst per PSO VERIFY CERTIFICATE kennt (LIANA-23) |
| `poppApdusSequence3.json` | GENERAL AUTHENTICATE + SceReadX.509 | GENERAL AUTHENTICATE, SELECT ESIGN, READ BINARY SFI 04 im Klartext | geprüft; der TU-PoPP-Service schickt Sequenz 3 als Secure Messaging (CLA `0C`, flüchtiger Schlüssel), also nicht wie der Blueprint |

- Quelle: <https://github.com/gematik/ti2.0-testhub>, Pfad `test/popp-testsuite/src/test/resources/blueprints/`
- Version: Release **3.19.0**; `ApduValidator` gelesen auf Testhub-Commit `42d89f5b` (2026-10-08)
- Commit: `48cde0b22b7d82b85ec139ee807ec5d4352fabe9` (2026-10-08)
- Lizenz: Apache 2.0
- Nicht übernommen: `poppApdusSequence1Contactless.json` (kontaktlos, kein Konnektor-Pfad).
- Nie automatisch überschreiben; Änderungen nur mit neuem Quell-Commit.

# TSL (Vertrauensanker für TUC_KON_037)

| Datei | Inhalt |
|---|---|
| `ECC-RSA_TSL-ref.xml` | gematik-TSL der Referenzumgebung (RU), TSLSequenceNumber 10713, SHA-256 `3d528bcd…9e84` |
| `BNetzA-VL.xml` | BNetzA-VL (ETSI TS 119 612) aus der Konnektor-QES, TSLSequenceNumber 1, SHA-256 `9cbc6fe9…` |

- Heruntergeladen 2026-10-08 von `https://download-ref.tsl.ti-dienste.de/ECC/ECC-RSA_TSL-ref.xml`
  (ListIssueDateTime 2026-10-01, NextUpdate 2026-10-31).
- Enthält unter anderem GEM.KOMP-CA55 TEST-ONLY (Signer des PoPP-Service der TU, Trace `popp-kon-tu`) und
  GEM.KOMP-CA61 TEST-ONLY (Signer des PoPP-Service im Testhub und in der Konnektor-Testsuite).
- LIANA nimmt daraus die CA-Zertifikate (TSPService `CA/PKC`). Die XML-Signatur, ServiceStatus und NextUpdate prüft
  LIANA nicht; eine abgelaufene TSL bleibt nutzbar, solange die CA-Zertifikate gelten (KOMP-CA55/61 bis 2031).
- Aktualisieren: Datei neu laden, Sequenznummer und Hash hier und in `TrustSpaceTest` nachziehen.
- Die Images ziehen die TSL beim Build frisch (LIANA-180, `tools/pki/tsl-fetch.sh`); diese Datei ist der Rückfall und
  die Grundlage aller Tests. Am 2026-10-20 lieferte die RU SequenceNumber 10715 (107 statt 123 CA/PKC): entfallen sind
  16 eGK-CAs (u. a. GEM.EGK-CA41/44, ATOS.EGK-CA25, Aussteller der C.CH.AUT.R2048 der Testkarten); die Aussteller der
  C.CH.AUT.E256 von egk-valid (GEM.EGK-CA57) und der Suite-eGKs bleiben.

## BNetzA-VL

- Kopiert 2026-10-19 aus `tiger-konnektor-qes` 0f274c4c, `resources/TSL/BNetzA-VL.xml`.
- Enthält die Test-QCAs der TI, darunter GEM.HBA-qCA6 TEST-ONLY und GEM.HBA-qCA24 TEST-ONLY: Aussteller der
  QES-Zertifikate in den HBA-Images und den CAdES-Dateien der Suite (`support/vendor/signatures/cades`).
- LIANA nimmt daraus die Zertifikate der TSPServices `CA/QC` und `NationalRootCA-QC` (TUC_PKI_030, LIANA-112.07),
  ohne Signatur, ServiceStatus und History zu prüfen. Einträge, die BouncyCastle nicht lesen kann, fallen weg.
- Die ältere Schlüsselgeneration von GEM.HBA-qCA6 (AKI `95:CE:68…`, Datei `Textdokument_standard.env.QES.ECC.Rise.txt`
  aus dem stornierten KUC_1604_026) steht in keiner VL der Suite.

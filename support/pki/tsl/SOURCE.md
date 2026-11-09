# TSL (Vertrauensanker für TUC_KON_037)

| Datei | Inhalt |
|---|---|
| `ECC-RSA_TSL-ref.xml` | gematik-TSL der Referenzumgebung (RU), TSLSequenceNumber 10717, SHA-256 `f8a9f7e4…0b88189` |
| `BNetzA-VL.xml` | Pseudo-BNetzA-VL der gematik (ETSI TS 119 612), TSLSequenceNumber 60, SHA-256 `af597543…cc265474` |

- Heruntergeladen 2026-11-05 von `https://download-ref.tsl.ti-dienste.de/ECC/ECC-RSA_TSL-ref.xml`
  (ListIssueDateTime 2026-10-28, NextUpdate 2026-11-27).
- Enthält unter anderem GEM.KOMP-CA55 TEST-ONLY (Signer des PoPP-Service der TU, Trace `popp-kon-tu`) und
  GEM.KOMP-CA61 TEST-ONLY (Signer des PoPP-Service im Testhub und in der Konnektor-Testsuite).
- LIANA nimmt daraus die CA-Zertifikate (TSPService `CA/PKC`). Die XML-Signatur, ServiceStatus und NextUpdate prüft
  LIANA nicht; eine abgelaufene TSL bleibt nutzbar, solange die CA-Zertifikate gelten (KOMP-CA55/61 bis 2031).
- `tools/pki/CertExpiry.java` scheitert 7 Tage vor NextUpdate. Aktualisieren: Datei neu laden, Sequenznummer, Hash und
  Daten hier nachziehen, `./mvnw verify`.
- Die Images ziehen die TSL beim Build frisch (LIANA-180, `tools/pki/tsl-fetch.sh`); diese Datei ist der Rückfall und
  die Grundlage aller Tests. Am 2026-10-20 lieferte die RU SequenceNumber 10715 (107 statt 123 CA/PKC): entfallen sind
  16 eGK-CAs (u. a. GEM.EGK-CA41/44, ATOS.EGK-CA25, Aussteller der C.CH.AUT.R2048 der Testkarten); die Aussteller der
  C.CH.AUT.E256 von egk-valid (GEM.EGK-CA57) und der Suite-eGKs bleiben.

## BNetzA-VL

- Heruntergeladen 2026-11-05 von `https://download-testref.tsl.ti-dienste.de/P-BNetzA/Pseudo-BNetzA-VL.xml` (öffentlich,
  Hash daneben als `.sha2`, stimmt), ListIssueDateTime 2026-03-17, NextUpdate 2029-03-17. Die DistributionPoints in der
  Datei (`download-testref.bnetzavl.telematik-test`, `download-bak-testref…`) trennen auch im VPN jede Anfrage.
- Ersetzt Sequenz 1 aus `tiger-konnektor-qes` (`resources/TSL/BNetzA-VL.xml`, NextUpdate 2026-02-18). Dazu kommen unter
  anderem GEM.HBA-qCA28, -qCA44 und -qCA51; 12 Zertifikate entfallen, darunter MESIG.HBA-qCA1/4 und GEM.qRCA2.
- Aktualisieren: Datei neu laden, Sequenznummer, Hash und Daten hier nachziehen, `./mvnw verify`.
- Enthält die Test-QCAs der TI, darunter GEM.HBA-qCA6, -qCA24, -qCA28 und -qCA51 TEST-ONLY: Aussteller der
  QES-Zertifikate in den HBA-Images und den CAdES-Dateien der Suite (`support/vendor/signatures/cades`).
- LIANA nimmt daraus die Zertifikate der TSPServices `CA/QC` und `NationalRootCA-QC` (TUC_PKI_030, LIANA-112.07),
  ohne Signatur, ServiceStatus und History zu prüfen. Einträge, die BouncyCastle nicht lesen kann, fallen weg.
- Die ältere Schlüsselgeneration von GEM.HBA-qCA6 (AKI `95:CE:68…`, Datei `Textdokument_standard.env.QES.ECC.Rise.txt`
  aus dem stornierten KUC_1604_026) steht in keiner VL der Suite.

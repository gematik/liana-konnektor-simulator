# Signierte Dokumente (Testdaten für SignDocument und VerifyDocument)

Kopiert 2026-10-19 (PAdES: LIANA-112.08, XAdES: LIANA-112.09, S/MIME: LIANA-112.10) aus `tiger-konnektor-qes` 0f274c4c, `src/test/resources/testdata/` (Unterordner wie dort). Hier liegen nur die Originale; die von den Konnektoren der Hersteller erzeugten Signaturen
liegen mit denselben Unterordnern unter `support/vendor/signatures/` und werden nicht veröffentlicht
(`support/vendor/README.md`):

| Ordner | Szenarien | Inhalt |
|---|---|---|
| `cades/` | KUC_1607_001–006, 011, 012, 015–021, 031–033, KUC_1604_008, 026 | CAdES von KOCO, RISE, SECUNET mit RSA (GEM.HBA-qCA24, GEM.SMCB-CA24), Originale `MedicationRequest_42.xml`, `erezept.xml`; `CAdES_1_mod.bin` ist manipuliert |
| `cades/IOP-ECC/` | KUC_1607_200–220 | CAdES mit ECC (GEM.HBA-qCA6, GEM.SMCB-CA51), Original `Textdokument_standard.txt` |
| `cades/testwoche/` | KUC_1609_013–024, 028–036 | CAdES mit ECC aus der Testwoche, Originale der detached-Signaturen |
| `pades/` | KUC_1607_046–060 (Auswahl A1A, A2A), KUC_1602_090, KUC_1604_013, KUC_1605_009 | PAdES von KOCO, RISE, SECUNET mit RSA (`sig.rsa.*`); unsignierte Dokumente PDF/A-1A, -1B, -2A, PDF/A-3A (A_18780) und PDF 1.7 ohne PDF/A-Kennung |
| `pades/IOP-ECC/` | KUC_1607_229–243 (Auswahl A1A, A2A) | PAdES mit ECC von KOCO, RISE, SECUNET |
| `xades/` | KUC_1607_009, 010, 014, KUC_1602_044, 077, 214, KUC_1609_001 | NFD-Signaturen (Richtlinie `urn:gematik:fa:sak:nfdm:r1:v1`) von KOCO, RISE, SECUNET mit RSASSA-PSS (GEM.HBA-qCA24); Original `NFDM_Beispiel_1.4.xml` (ISO-8859-15) |
| `xades/IOP-ECC/` | KUC_1607_208, 209, 213 | NFD-Signaturen mit ECC (GEM.HBA-qCA6) |
| `smime/` | KUC_1601_001, KUC_1603_001, KUC_1603_010 | `eMail10k.txt` (MIME-Nachricht, CRLF), `SMimeMessage_without_ContentType.txt` (S/MIME signed-data ohne Content-Type, RSA, GEM.SMCB-CA8) |

- Die detached-Signaturen sind über die Originale mit CRLF signiert. In der Suite liegen die Originale mit LF und
  werden so geschickt; LIANA weicht aus (Abweichung `DETACHED_CONTENT_LF`, docs/handbuch.md).
- `Textdokument_standard.env.QES.ECC.Rise.txt` (KUC_1604_026, storniert) stammt von einer GEM.HBA-qCA6, die in keiner
  VL der Suite steht. Die Tests nutzen die Datei nicht.
- Golden Data: nie automatisch überschreiben. Ein neuer Stand der Suite wird von Hand nachgezogen.

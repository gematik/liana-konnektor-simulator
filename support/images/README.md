# Kartenimages

Erster Ordner von `liana.card-images` (LIANA-98). LIANA indexiert die Images beim Start nach Dateiname und ICCSN (EF.GDO); ein Slot-Eintrag in `liana.infrastructure.terminals` wählt per Dateiname (`egk-valid`, erster Ordner gewinnt), ICCSN (eindeutig) oder absolutem Pfad. Fehlt ein Image oder ist eine ICCSN mehrdeutig, bricht der Start ab.

## Format

gematik-Objektsystem-XML (`<card version="3">…<objectSystem>`), Endung **`.xml`**. Dasselbe Format nutzen Testhub, CATS und die Kartenproduktion. Ausgeführt werden die Images von kartos (`kartos pipe <image>`, decision-7). Den ATR liest LIANA aus dem Attribut `coldAnswerToReset`.

Die Images enthalten private Testschlüssel. Es sind Testkarten ohne echte Identitäten, für die Produktion nicht verwendbar.

## Benötigt für Phase 1 (Testhub-PoPP, 3 eH-KT-Szenarien)

`hba-valid` steckt nur im Testprofil (KT-01/3) und für Postman FF_005 (`tools/testhub/postman.sh`), nicht in der Boot-YAML: popp-client sieht weiter nur eGK und SMC-B.

`smcb-valid` ist eine öffentliche SMC-B aus ti2.0-testhub (GEM.SMCB-CA57); der ZETA-Guard des Testhubs vertraut der CA (LIANA-33).

| Name | Karte | Zweck | Lieferant | im Repo |
|---|---|---|---|---|
| `egk-valid` | eGK G2.1 (ICCSN 80276883110000168584, KVNR X110630769) | Gutfall `_Valid_ehealth` | ti2.0-testhub, `client/card-terminal-client-simservice/src/main/resources/attached_assets/EGK_80276883110000168584_gema5.xml`, Commit `dba609ce`, Apache 2.0 | ja |
| `egk-expired` | eGK G2.1, C.CH.AUT abgelaufen | `_expired_Invalid_eHealth` | PoPP-Testsuite: `EGK_80276883110000179865_gema5_abgelaufen2025.xml` (`EgkType.EGK_80276883110000179865_EXPIRED`), nicht öffentlich, Bezug laut `test/popp-testsuite/doc/readmeDev.md` im Testhub | nein |
| (Ersatz für `egk-expired`) | eGK G2.1 (ICCSN 80276883110000168583, KVNR X110639491), C.CH.AUT und CVC abgelaufen (C.CH.AUT bis 2025-04-05) | `_expired_Invalid_eHealth` über LIANA: PoPP-Service lehnt ab mit 79116 „Failed to validate CVC chain: reason=certificate is expired“ | ti2.0-testhub, `test/vsdm-testsuite/src/test/resources/data/cards/egkCardImageInvalid.xml` (seit `5b8fb174`, vorher card-terminal-client-simservice, Commit `dba609ce`), Apache 2.0; im Container `/opt/liana/testhub-cards`, `abnahme` steckt die Karte per Admin-API (LIANA-42, LIANA-177) | nein, Mount |
| `egk-revoked` | eGK G2.1, C.CH.AUT widerrufen (OCSP) | `_OCSP_revoked_Invalid_eHealth` | PoPP-Testsuite: `EGK_80276883110000180787_revoked_gema5.xml` (`EgkType.EGK_80276883110000180787_REVOKED`), Bezug wie oben | nein |
| `smcb-valid` | SMC-B G2.1 (ICCSN 80276883110000168650, Praxis Münchhausen-Hohenfels, C.HCI.AUT von GEM.SMCB-CA57 bis 2030-04-06, PIN.SMC 123456 regulär) | ZETA-Anmeldung des popp-client über den Konnektor (LIANA-29–32); der ZETA-Guard des Testhubs vertraut der CA (`smcb-trust-roots.p12` enthält GEM.SMCB-CA44 und CA57) | öffentlich: ti2.0-testhub, `client/card-terminal-client-simservice/src/main/resources/attached_assets/SMC_B_80276883110000168650_gema5.xml`, Apache 2.0; einzige Änderung: PIN.SMC von Transport-PIN 54321 auf 123456 regulär (`secret`, `transportStatus`), wie nach dem Ändern der Transport-PIN | ja |
| `hba-valid` | HBA G2.1 (ICCSN 80276883119000000020, Maximilian Graf Popówitsch, Objektsystem 4.8.0, Arzt, C.HP.QES von GEM.HBA-qCA28/qCA51, C.HP.AUT/ENC von GEM.HBA-CA44/CA57, alle bis 2031-06-03, CVC-Root DEGXX890225, MF-AID D27600014601, PIN.CH und PIN.QES regulär 123456) | Postman FF_005: StartCardSession auf einen HBA → 4209 (LIANA-56); TUC_KON_001 erkennt den HBA; VerifyPin PIN.CH, ReadCardCertificate, ExternalAuthenticate (LIANA-61); SignDocument QES, Trusted Channel (LIANA-112) | gematik-intern, vom User bereitgestellt (`HBA_80276883119000000020_gema5.xml`, generiert 2026-10-20). **Geändert:** PIN.CH und PIN.QES von Transport-PIN auf 123456 regulär (`transportStatus` regularPassword, `secret` `26123456FFFFFFFF`), sonst unverändert; SHA-256 original `fba88a8e…14edb3be0`, Ergebnis `26a863af…10ed170c`. Alle Zertifikate der Karte sind im OCSP der RU gesperrt (Veröffentlichung auf GitHub). **Ersetzt in LIANA-197** `HBA_G21_A_80276883110000138484.xml` aus tiger-konnektor-e2e (Commit `880b30cd`, SHA-256 `ec5a157c…10fe15`). GEM.HBA-qCA28 und qCA51 stehen nicht in der BNetzA-VL im Repo, VerifyDocument meldet QES-Signaturen der Karte deshalb INVALID | ja |

## Benötigt für Phase 2 (SICCT gegen `kartos terminal`)

`kartos terminal` lädt alle Images seines Arbeitsverzeichnisses in Namensreihenfolge in die Slots; die gSMC-KT erkennt es am Inhalt und nimmt aus ihr die TLS-Identität (C.SMKT.AUT2 mit PrK.SMKT.AUT.E256, brainpoolP256r1). Mit `--workdir support/images` stecken eGK, gSMC-KT, HBA und SMC-B in den Slots 1–4 (LIANA-70).

| Name | Karte | Zweck | Lieferant | im Repo |
|---|---|---|---|---|
| `gsmckt-valid` | gSMC-KT G2.1 (ICCSN 80276883110000148887, Objektsystem 4.4.1-2, C.SMKT.AUT2 brainpoolP256r1 von GEM.KOMP-CA51 TEST-ONLY bis 2028-07-18, dazu C.SMKT.AUT RSA von GEM.KOMP-CA41) | Sicherheitsmodul und TLS-Identität des eHealth-KT `kartos terminal` (decision-11) | tiger-konnektor-e2e (gematik-intern), `src/test/resources/testdata/CardImages/SMC_KT_80276883110000148887_gema5-original.xml`, Commit `880b30cd`, SHA-256 `80ae0601…17faac`. **Korrigiert:** In `PrK.SMKT.AUT.E256` waren `P` (öffentlicher Punkt) und `privateKey` (Skalar) vertauscht – `privateKey` enthielt den öffentlichen Punkt des C.SMKT.AUT2, `P` den 32-Byte-Skalar. Getauscht, sonst nichts geändert; Ergebnis SHA-256 `fe8954a7…e35c2d`. Die übrigen SMC-KT-Images dort haben denselben Fehler (`…129161_JHO`, `…148887_IBK`) bzw. nur RSA (`SMC-KT_G21_…107711`); andere Quellen gibt es lokal nicht (kartos erwartet `SMC_KT_80276883110000168581_gema5_ECC.xml` aus `simulation.icc-images`) | ja |

## Benötigt für den Trusted Channel (LIANA-28)

Im Unterordner `gsmc-kt/` (eigener Eintrag in `liana.card-images`), damit `kartos terminal --workdir support/images` keine zweite gSMC-KT in die Slots steckt. `infrastructure.terminals.<id>.gsmc-kt` wählt daraus die Identität von LIANA als Terminal gegenüber der Karte (LIANA-99).

| Name | Karte | Zweck | Lieferant | im Repo |
|---|---|---|---|---|
| `gsmc-kt/gsmckt-root6` | gSMC-KT G2.1 (CHR 000A80276883110000152716, Objektsystem 4.4.1-2), `PrK.SMC.AUTD_RPS_CVC.E256` mit `EF.C.SMC.AUTD_RPS_CVC.E256` (bis 2028-09-19) unter `EF.C.CA_SMC.CS.E256` (DEGXX120223, bis 2031-07-31), CVC-Root DEGXX870222 wie `egk-valid` | Hop B des Trusted Channels: LIANA als Terminal mit elcSessionkey4SM gegenüber der Karte | tiger-ehealth-kt-e2e (gematik-intern), `images_E2E_5V/root6/IMG_gSMCKT_G21_TU_root6.xml`, Commit `9de79b3`, unverändert, SHA-256 `bad945ca…94d9da` | ja |

`gsmckt-valid` taugt dafür nicht: sein `EF.C.SMC.AUTD_RPS_CVC.E256` läuft (2028-07-18) nach seinem CA-Zertifikat ab (2028-04-08), jede Karte lehnt den Import nach G2_N095.900.b.11.ii mit 6A80 ab. Dieselbe Kette haben `SMC_KT_G21_80276883110000148887_IBK` (tiger-konnektor-e2e); die übrigen gSMC-KT-Images dort sind abgelaufen.

## gSMC-K für den Trusted Channel zum HBA (LIANA-112.13)

Im Unterordner `gsmc-k/` (eigener Eintrag in `liana.card-images`), aus demselben Grund nicht im Workdir von `kartos terminal`. `infrastructure.konnektor.gsmc-k.image` wählt daraus die Quellkarte für TUC_KON_005 „gegenseitig+TC“ gSMC-K↔HBA (TUC_KON_154/158). Die übrigen Identitäten der gSMC-K (ID.AK.AUT, ID.SAK.AUT) kommen weiter aus PKCS#12.

| Name | Karte | Zweck | Lieferant | im Repo |
|---|---|---|---|---|
| `gsmc-k/gsmc-k` | gSMC-K (ICCSN 80276883119000000019), `PrK.SAK.AUTD_CVC.E256` mit `EF.C.SAK.AUTD_CVC.E256` (CHR 000A80276883119000000019, Flagliste …01, bis 2031-10-19) unter `EF.C.CA_SAK.CS.E256` (DEGXX130226, bis 2034-02-04), CVC-Root DEGXX890225; zum HBA (Root DEGXX860220) über drei Cross-CVCs der TSL | PSO COMPUTE DIGITAL SIGNATURE im SE #2 des HBA: Stapel und Komfortsignatur | gematik-intern, vom User bereitgestellt (`SMC_K_80276883119000000019_gema5.xml`, 2026-10-20), unverändert, SHA-256 `d9987568…49cbea` | ja |

Ein erstes Image derselben Quelle (`SMC_K_80276883119000000017_gema5.xml`) taugt nicht: sein CA-CVC (DEGXX100218) lief am 2026-03-07 ab, das Rollen-CVC gilt länger, der HBA lehnt den Import nach G2_N095.900.b.11.ii mit 6A80 ab.

## Karten der Generation G2.0 (RSA, LIANA-112.12)

Im Unterordner `g20/` (eigener Eintrag in `liana.card-images`), aus demselben Grund nicht im Workdir von `kartos terminal`. Die Tests stecken die Karte per Image-Pfad (`SignDocumentQesKartosIT.hbaG20`).

| Name | Karte | Zweck | Lieferant | im Repo |
|---|---|---|---|---|
| `g20/hba-g20` | HBA G2.0 (ICCSN 80276883119000000021, Kevin Sigmuntowskí, Objektsystem 4.3.1), nur RSA: PrK.HP.QES.R2048 (keyIdentifier 04, signPSS) mit C.HP.QES.R2048 von GEM.HBA-qCA28 TEST-ONLY, C.HP.AUT/ENC.R2048 von GEM.HBA-CA44, alle bis 2031-06-03, PIN.CH und PIN.QES regulär 123456, PIN.QES erlaubt eine Signatur je Eingabe (startSSecList `{(1,01),(2,00fa)}`) | SignDocument QES mit RSA nach TAB_KON_900 (TUC_KON_150 mit dem HBA G2.0); die Konnektor-QES steckt in KUC_1602_080/081 (RSA-PSS) eine Karte derselben Art | gematik-intern, vom User bereitgestellt (`HBA_80276883119000000021_gema5_g2.xml`, generiert 2026-10-20). **Geändert:** PIN.CH und PIN.QES von Transport-PIN auf 123456 regulär, sonst unverändert; SHA-256 original `68bf0eaf…d40cf9b45`, Ergebnis `fe4877e4…a887ce`. Zertifikate im OCSP der RU gesperrt. **Ersetzt in LIANA-197** `HBA_G2_A_80276883110000145607.xml` aus tiger-konnektor-qes (Commit `0f274c4c`, SHA-256 `38b0b829…1a99f8`). GEM.HBA-qCA28 steht nicht in der BNetzA-VL im Repo, VerifyDocument meldet die Signatur deshalb INVALID | ja |

Ablauf und Sperrung prüft der PoPP-Service, nicht LIANA. Die Images müssen nur korrekt ausgeliefert werden.

Nie automatisch überschreiben. Ein Austausch nur mit neuem Quell-Commit in dieser Tabelle.

## KVK (LIANA-113)

Im Unterordner `kvk/` (eigener Eintrag in `liana.card-images`), nicht im Workdir von `kartos terminal`: Die KVK ist eine Speicherkarte ohne COS. kartos simuliert sie nicht; das Fake-KT führt sie selbst aus (`KvkCard`), wie ein SICCT-Terminal mit synchronen Karten ([SICCT] 5.5.8.1). Format: XML mit Wurzel `kvk`, Attribut `atr` (Hex) und Element `template` (VersichertenDatenTemplate ab Tag `60` bis zum Prüfbyte, Hex), Aufbau nach KBV-Merkblatt KVK 2.05.

| Name | Karte | Zweck | Lieferant | im Repo |
|---|---|---|---|---|
| `kvk/kvk-valid` | KVK, erfundene Daten (Testkasse LIANA, Erika Mustermann, gültig bis 12/2030), Prüfsumme korrekt; ATR `A2131091` frei gewählt, die Werte der KVK-Spec (Ziffer 6.2) liegen nicht vor | `EE_KT_T_KVK_READ` (eGK-Fächer SC5 und SC7 des Robots), ReadKVK | LIANA, selbst erstellt | ja |

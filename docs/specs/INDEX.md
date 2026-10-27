# Spec-Index

Texte in `docs/specs/text/` (nur intern, nicht veröffentlicht), AFOs in `support/afo/afo-index.csv` (Stand 2026-10-13: 3 511 AFOs aus 12 Specs; die ProdT-Steckbriefe führen AFOs nur tabellarisch und liefern keine Indexeinträge, sind aber grep-bar).

| Spec | Version | Datei | AFOs | Relevant ab Phase | Wofür |
|---|---|---|---|---|---|
| gemSpec_Kon | 5.28.0 | `gemSpec_Kon_V5.28.0.txt` | 571 | 0 | Dienstverzeichnis, Infomodell, CardService (Start/SecureSend/StopCardSession), Fehlercodes, TUC_KON_* |
| gemProdT_Kon_PTV6 | 6.0.4-1 | `gemProdT_Kon_PTV6_6.0.4-1_V1.0.0.txt` | – | 1 | Welche AFOs für PTV6 gelten |
| gemSpec_eGK_ObjSys_G2.1 | 4.7.1 | `gemSpec_eGK_ObjSys_G2_1_V4.7.1.txt` | 149 | 1 | eGK-Objektsystem: FIDs, SFIs, ATR, EF.GDO/Version2/DIR, Zertifikate |
| gemSpec_SMC-B_ObjSys_G2.1 | 5.2.1 | `gemSpec_SMC-B_ObjSys_G2_1_V5.2.1.txt` | 124 | 5 | SMC-B-Objektsystem (PrK.HCI.AUT.E256, PIN.SMC) |
| gemSpec_KT | 3.17.1 | `gemSpec_KT_V3.17.1.txt` | 368 | 2 | eHealth-KT: TLS mit C.SMKT.AUT, Pairing (EHEALTH TERMINAL AUTHENTICATE), Service Discovery, Keep-Alive, PERFORM VERIFICATION, Abweichungen von [SICCT] (SlotID, FU-Typen) |
| SICCT (TeleTrusT) | 1.2.3 (30.09.2016) | `SICCT-Spezifikation_V_1.2.3.txt` | – | 2 | Kodierung zu gemSpec_KT: Envelope (§6.2.4.2, Tabelle 16), CT-Session (§6.2.4.3), Ereignisnachrichten 84/85/80/81 (§6.2.4.4, Tabelle 17), Keep-Alive (§6.2.4.5), Kommandos (Kap. 5). Öffentlich: teletrust.de/fileadmin/docs/projekte/sicct/SICCT-Spezifikation_V_1.2.3_vom_30.09.2016.pdf; keine AFO-IDs, Suche über Abschnittsnummern (LIANA-71) |
| SICCT Errata (TeleTrusT) | 1.0 (05.05.2021) | `SICCT-Errata_V_1.0.txt` | – | 2 | Korrekturen zu SICCT 1.2.3: Discovery-Tag `8A` um TLS 1.3 (`40`) ergänzt (§6.2.3.1), TLS ≥ 1.2, kein TLS 1.0/1.1 (§6.4.1.1), REQUEST ICC nur redaktionell (§5.13), 2D-Code in Display-DOs und OUTPUT, SW `6402` bei MODIFY VERIFICATION DATA. Öffentlich: teletrust.de/fileadmin/user_upload/Errata-Sheet-SICCT_Spezifikation-123_V1_20210505.pdf (LIANA-57) |
| gemSpec_COS | 3.14.0 | `gemSpec_COS_V3.14.0.txt` | 1326 | 1 | Secure Messaging (13.2 Kommando, 13.3 Antwort; G2_N032.*–G2_N034.*), elcSessionkey4SM (15), Kommandos (14). Die meisten Anforderungen tragen nur `G2_N…`-IDs, die nicht im Index stehen: `grep -n 'G2_N032.300' docs/specs/text/gemSpec_COS_V3.14.0.txt`. Öffentlich: gemspec.gematik.de/downloads/gemSpec/gemSpec_COS/gemSpec_COS_V3.14.0.pdf (LIANA-28) |
| gemSpec_Krypt | 2.51.0 | `gemSpec_Krypt_V2.51.0.txt` | 256 | 0 | Brainpool, TLS-Vorgaben, JWS-Algorithmen |
| gemSpec_PKI | 2.28.0 | `gemSpec_PKI_V2.28.0.txt` | 276 | 1 | TSL, OCSP, Zertifikatsprofile, CVC |
| gemSpec_OID | 3.26.0 | `gemSpec_OID_V3.26.0.txt` | 9 | 1 | `oid_popp`, Rollen-OIDs |
| gemProdT_PoPP_Service | 1.1.0-0 | `gemProdT_PoPP_Service_PTV_1.1.0-0_V1.1.0.txt` | – | 1 | PoPP-Service-Anforderungen (Gegenseite des Tunnels) |
| gemSpec_FM_VSDM | 2.9.0 | `gemSpec_FM_VSDM_V2.9.0.txt` | 129 | 6 | Fachmodul VSDM im Konnektor: I_VSDService/ReadVSD (3.2.1, VSDM-A_2567 ff.), Rückgabe von PD/VD/GVD und Status-Container (4.4), Fehlercodes; ReadVSD vollständig LIANA-103, ohne Onlineprüfung für den vsdm-client des Testhubs LIANA-119 (LIANA-105) |
| gemSpec_VSDM_2 | 1.5.0 | `gemSpec_VSDM_2_V1.5.0.txt` | 130 | 5 | ZETA-Client-Authentisierung (A_26984), Offline-Fallback (A_28038) |
| gemILF_PS | 2.29.0 | `gemILF_PS_V2.29.0.txt` | 106 | 3 | Sicht des Primärsystems auf den Konnektor |
| gemSpec_OM | 1.19.0 | `gemSpec_OM_V1.19.0.txt` | 67 | 3 | Fehlermeldungen (GERROR), Operations & Maintenance |
| KBV-Merkblatt KVK (KBV_ITA_VGEX_Merkblatt_KVK) | 2.05 (20.07.2012) | nicht im Repo (© KBV) | – | 6 | KVK-Datenstruktur für ReadKVK (LIANA-113): Tags und Längen des VersichertenDatenTemplates (1.1, Tabelle 1), Zeichensatz DIN 66003 (1.3/1.4), SELECT FILE mit der KVK-AID und READ BINARY bis 6282 (4.1/4.2). Öffentlich: update.kbv.de/ita-update/Service-Informationen/KBV_ITA_VGEX_Merkblatt_KVK.pdf, Klassifizierung „Extern“. Die eigentliche KVK-Spec (ATR-Header, Ziffer 6.2) liegt nicht vor; keine AFO-IDs |

## Fehlt noch (Blocker je Phase)

| Dokument | Gebraucht ab | Wofür |
|---|---|---|
| gemSpec_ZETA / gemSST_PS_ZETA_V | Phase 5 | weitere Konnektoroperationen neben ExternalAuthenticate? |
| ILF_VSDM_2 | Phase 6 | Pfad des VSDM2-Offline-Fallbacks |
| gemSpec_SST_PS_VSDM | Phase 6 | Schnittstelle zum Primärsystem: VSDM-A_2608, VSDM-A_2677, VSDM-A_2695/2696 und VSDM-A_2710/2711 zu ReadKVK stehen im Steckbrief PTV6, der Text nicht im Repo; umgesetzt nach gemSpec_FM_VSDM 3.2.2 und gemILF_PS (LIANA-113) |
| gemSpec_HBA_ObjSys_G2.1 | Phase 6 | PIN.CH/PIN.QES/PUK und RSA-Zertifikate des HBA: LIANA-109, LIANA-111, LIANA-112 |
| gemSpec_FM_NFDM | Phase 6 | NFD/DPE lesen, schreiben, löschen: LIANA-114 |
| gemSpec_FM_AMTS | Phase 6 | Einwilligung, eMP: LIANA-115 |
| KVK-Spec (Technische Spezifikation der Versichertenkarte) | Phase 6 | ATR-Header, ATR-Data, DIR-Data (Ziffer 6.2) der KVK; LIANA-113 prüft sie nicht, das KT setzt SELECT/READ BINARY um |

## Hersteller-Specs (nicht im Repo)

KMS-Schnittstellen von RISE, KOCO und EHEX liegen nur lokal unter `docs/specs/vendor/` (per `.gitignore` ausgeschlossen, siehe README dort). Für SECUNET gibt es keine Spec.

Herkunft: gematik-Fachportal, Klassifizierung „öffentlich“. Neue Versionen: PDF konvertieren, alte `.txt` ersetzen, Index neu bauen, Tabelle anpassen.

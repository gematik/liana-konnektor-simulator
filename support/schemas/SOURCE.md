# Konnektor-Schemas

Hier liegen die WSDL- und XSD-Dateien der Konnektor-Außenschnittstelle, gepinnt auf eine Version. Sie dienen **nur** der Validierung der SOAP-Templates in Tests; LIANA generiert daraus keinen Code.

- Quelle: <https://github.com/gematik/api-telematik>
- Version: Release **6.0.3** (Tag `ebk_6.0.3`, Branch `main_ebk`)
- Commit: `d3f0cf527cb9c07644f00c1aed49554438581dee` (2026-01-12)
- Lizenz: Apache 2.0
- Gebraucht ab: Phase 0 (`connector.sds`, Dienstverzeichnis), Phase 1 (EventService, CardService, CertificateService, Infomodell-Header), VSDService ab LIANA-119, Prüfungsnachweis und UFS ab LIANA-141, KvkService ab LIANA-113

## Umfang

Übernommen sind alle Dateien direkt unter `conn/` plus ihr transitiver Import-Abschluss aus `tel/` und `ext/`. Die Verzeichnisstruktur ist unverändert, damit relative `schemaLocation`s auflösen. Aus den Fachmodulen nur `conn/vsds/VSDService.{wsdl,xsd}` (Fachmodul VSDM, ReadVSD, LIANA-119; Namespace `…/vsds/VSDService/v5.2`, Schema-Version 5.2.0) und `conn/vsds/KvkService.{wsdl,xsd}` (ReadKVK, LIANA-113; Namespace `…/vsds/KvkService/v4.0`, Schema-Version 4.0.0), Import-Abschluss schon vorhanden (`ConnectorContext.xsd`, `tel/error`). Für die XML-Dokumentvalidierung unter der Signaturrichtlinie NFDM (TUC_KON_080 (A), LIANA-112.09) `fa/nfds/NFD_Document_v1_4.xsd` mit `fa/nfds/common/NFDM_Common_v1_1.xsd` (Import `ext/xmldsig-core-schema.xsd` schon vorhanden). Für die Onlineprüfung (LIANA-141) zusätzlich `fa/vsds/Pruefungsnachweis.xsd` (Prüfungsnachweis, Namespace `http://ws.gematik.de/fa/vsdm/pnw/v1.0`, CDM 1.0.0) und der UFS des Fachdienstes `cm/uf/{UFS.wsdl,CmUfServiceRequest.xsd,CmUfServiceResponse.xsd}` mit `cm/common/CmCommon.xsd` (GetUpdateFlags, SOAPAction `http://ws.gematik.de/cm/uf/WSDL/v1.0#getupdateflags`; `tel/error` schon vorhanden). Nicht übernommen: die übrigen Fachmodule (`conn/nfds`, `fa/nfds/DPE_Document.xsd`, `conn/phrs`, `conn/amtss`, `conn/tbauth`), aus `cm/` der CCS (`cm/cc`, kommt mit LIANA-102) und alle anderen Top-Level-Ordner.

Die WSDL des VSDService nennt als SOAPAction `http://ws.gematik.de/conn/vsds/VSDService/v6.0#ReadVSD`, obwohl Schema und WSDL den Namespace v5.2 haben. LIANA wertet den Namespace der SOAPAction nicht aus, nur die Operation dahinter. Die WSDL des KvkService nennt für ReadKVK die SOAPAction `http://ws.gematik.de/conn/vsds/KvkService/v4.0#ReadVDT`; LIANA nimmt sie und `#ReadKVK` an.

Die PoPP-Operationen (`StartCardSession`, `SecureSendAPDU`, `StopCardSession`) stehen in `conn/CardService_v8_2_1.{wsdl,xsd}`.

Hinweis: `ext/xml.xsd` importiert `http://www.w3.org/2001/03/xml.xsd`. Für die Validierung ohne Netz muss die Schema-Factory das auf eine lokale Kopie umleiten oder externe Zugriffe sperren.

## SOAP 1.1

`ext/soap-envelope-1.1.xsd` ist nicht Teil von api-telematik: das Schema des SOAP-1.1-Umschlags (Namespace `http://schemas.xmlsoap.org/soap/envelope/`), für die Validierung der SOAP-Faults (`soap/Fault.xml`, LIANA-69).

- Quelle: <https://schemas.xmlsoap.org/soap/envelope/>, abgerufen 2026-10-09
- SHA-256: `9c66f88b79ad60d6d5b63839bbb709b0cdfd591898c35ac187c3c272c47b52ae`
- Lizenz: W3C Software License (Kopf der Datei)

## Aktualisieren

Neuen Tag auschecken, denselben Abschluss neu kopieren und Version/Commit hier eintragen. Die Dateien nie von Hand ändern.

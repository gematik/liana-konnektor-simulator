# Golden Traces

Referenzmitschnitte der Außenkommunikation im Tiger-Format `.tgr` (decision-9), je Szenario ein Unterordner mit README (Quelle, Stand, was der Trace zeigt). Sie sind Referenz, nicht Testausgabe: Testläufe schreiben nach `_runs/` (gitignored), Golden Traces werden nur bewusst und mit Begründung aktualisiert.

| Ordner | Szenario | Quelle |
|---|---|---|
| `connector-sds/` | popp-client holt `connector.sds` | von Hand |
| `../vendor/traces/popp-kon-tu/` | popp-client ↔ TU-Konnektor, PoPP-Token für eGK (12 SOAP-Paare) | Log, `tools/traces/log2tgr.py` |
| `../vendor/traces/ps-epikur/` | Primärsystem Epikur pairt mit LIANA über `ps-proxy.sh` (22 HTTP-Paare, LIANA-189) | Tiger-Export aus dem PS-Labor |
| `sicct/` | SICCT-Umschläge zu `kartos terminal` (kein `.tgr`, sondern der kartos-Wire-Trace in JSONL): Testvektoren des SICCT-Codecs | `kartos terminal --trace`, `tools/traces/sicct-wire-session.py` |
| `../vendor/traces/vsdm/` | tiger-vsdm-e2e-testsuite ↔ secunet-Konnektor in der TU, ReadVSD mit Onlineprüfung (9 HTTP-Paare inkl. Roboter) | Tiger-Export aus dem Lab (LIANA-101) |

Mitschnitte aus Produkten der Hersteller liegen unter `support/vendor/traces/` und werden nicht veröffentlicht (`support/vendor/README.md`).

## Format

Eine JSON-Zeile je Nachricht, die Rohnachricht (HTTP inklusive Header) Base64 in `rawMessageContent`:

```json
{"uuid":"…","sequenceNumber":0,"senderHostname":"popp-client:43210","receiverHostname":"liana:8080","messageKind":"REQUEST","timestamp":"…","rawMessageContent":"R0VUIC9jb25uZWN0b3Iuc2RzIEhUVFAvMS4x…"}
```

Traces entstehen von Hand, aus einem Tiger-Proxy-Mitschnitt oder per Konverter aus einem Log (`tools/traces/log2tgr.py` für popp-client-Logs mit Spring-WS `MessageTracing`). Rohlogs liegen in `_runs/` (gitignored). Lesbar in der Tiger-WebUI.

## Abspielen

`liana-trace-tests` startet das gebaute LIANA, schickt jeden HTTP-Request des Traces und vergleicht per RbelPath:

```java
@TraceReplay(value = "support/traces/connector-sds/popp-client.tgr", config = "liana.kon-export.url=http://liana:8080")
class ConnectorSdsTraceIT {
    @Test
    void diensteWieImTrace(Replay replay) {
        replay.onlyExchange().assertSameAt("$.responseCode", "$.body.ConnectorServices.ServiceInformation.Service.Name");
    }
}
```

- `assertSameAt(pfade…)`: LIANA liefert an jedem Pfad dieselben Werte wie der Trace. Werte, die sich legitim ändern (Zeitstempel, LIANA-Version, später CardHandles), werden nicht genannt.
- `assertThatLianaResponse()`: `RbelElementAssertion` für feste Werte, `andPrintTree()` zeigt bei Fehlschlag den Rbel-Baum.
- Läuft in `./mvnw verify` gegen `quarkus-run.jar`, mit `-Dnative` gegen das native Image.

# Antworten der Tiger-WebUI 4.5.0

Aufgezeichnet am 2026-11-16 für `TigerWebUiTest` und `TraceApiTest` (LIANA-195.03), unverändert; seit LIANA-195.05 liest die Seite Verkehr nur noch die Nachrichtenliste. Sie halten fest, was
die Seite Verkehr von der internen API der Tiger-WebUI (`TigerWebUiController`) erwartet. Ändert ein Tiger-Update diese
API, neu aufzeichnen und den Ordner nach der Version benennen.

| | |
|---|---|
| Image | `gematik1/tiger-proxy-image:4.5.0` (`/webui/version`: `4.5.0-SNAPSHOT`, buildDate 2026-10-28), Admin-Port 8080 |
| Herkunft | gematik, Tiger (https://github.com/gematik/app-Tiger), Apache-2.0 |
| Verkehr | zwei Nachrichten per `POST /traffic`: `ps:40000 → liana:8080` `POST /ws/EventService` und die Antwort |

| Datei | Abruf |
|---|---|
| `getMessagesWithMeta.json` | `GET /webui/getMessagesWithMeta` |
| `getMessagesWithMeta-filter.json` | `GET /webui/getMessagesWithMeta?filterRbelPath=$.sender =~ '.*liana.*'` |

Ein Filter, den Tiger nicht auswerten kann (`$.foo ==`), ergibt dort HTTP 500 mit Springs Fehler-JSON.

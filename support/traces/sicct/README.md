# SICCT-Wire-Trace von kartos terminal

`kartos-wire.jsonl` ist der Wire-Trace (`--trace`, JSONL) einer SICCT-Verbindung zu `kartos terminal`. Er dient als Testvektor für den Umschlag-Codec des SICCT-Adapters (LIANA-75): Jede Zeile nennt Richtung, Nachrichtentyp, FU, Sequenznummer, Datenlänge und den ganzen Umschlag als Hex. Die Gegenseite ist `openssl s_client` (TLS 1.2, brainpoolP256r1, ECDHE-ECDSA-AES128-GCM-SHA256) und nicht LIANA. Die Vektoren stammen also nicht aus dem Code, den sie prüfen.

| | |
|---|---|
| Erzeugt | 2026-10-09 mit `tools/traces/sicct-wire-session.py` gegen `tools/kartos/kartos-darwin-arm64` (kartos 0.7.1, Commit 92925a3) |
| KT | `kartos terminal -w support/images --port 47440 --trace`, `TERMINAL_KEEP_ALIVE_INTERVAL=1`, `TERMINAL_CONTROL_ADDR=127.0.0.1:47441` |
| Ablauf | INIT CT SESSION · GET STATUS (CTS DO) · REQUEST ICC Slot 1 mit ATR · SELECT an ICC 1 (FU 0001) · Steuerschnittstelle: Slot 3 ziehen (Ereignis `85`) und `hba-valid` stecken (`84`) · KEEP ALIVE `80` · CLOSE CT SESSION |

Die Kodierung folgt SICCT 1.2.3 §6.2.4.2 Tabelle 16 (Umschlag) und §6.2.4.4 Tabelle 17 (Ereignisse), siehe `docs/specs/text/SICCT-Spezifikation_V_1.2.3.txt`.

Der Trace ist Referenz und keine Testausgabe. Er wird nur bewusst und mit neuem Eintrag in dieser Tabelle ersetzt.

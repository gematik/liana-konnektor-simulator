# Test-PoPP-Service für den Trusted Channel (nur Tests)

Spielt im kartos-IT `TrustedChannelKartosIT` den PoPP-Service gegenüber LIANA (LIANA-28, Hop A). `kartos pipe --anchors
support/pki/sm/anchors` registriert `anchors/root.cvc` als Vertrauensanker der eGK; der Test-PoPP-Service importiert
`popp.cvc` wie im echten Ablauf per MSE SET DST und PSO VERIFY CERTIFICATE, GENERAL AUTHENTICATE Schritt 1 nennt die CHR
`000A80276001011699902801`.

- `anchors/root.cvc`: Root, CAR = CHR `DETEST 00 01`, selbst signiert, Schlüssel `ecdsa-with-SHA256`, alle Flags wie
  Tab_PKI_937 (kartos braucht beides, damit MSE SET DST den Anker als Prüfschlüssel findet).
- `popp.cvc`: End-Entity-CVC des Test-PoPP-Service, CAR `DETEST 00 01`, von der Root signiert, Schlüssel
  `authS_gemSpec-COS-G2_ecc-with-sha256`, keine Flags.
- Beide nach gemSpec_PKI 6.4: CPI 70, brainpoolP256r1, CHAT `oid_cvc_fl_ti`, gültig 2026-10-01 bis 2049-12-31. Keine
  Identität, kein Bezug zur TI-Test-PKI.
- `popp-key.pem`: privater Schlüssel zu `popp.cvc`, PKCS#8 unverschlüsselt.

Erzeugt 2026-10-12 mit `python3 -I tools/pki/sm-popp-cvc.py support/pki/sm` (cryptography 48). Neu erzeugen ändert nur
Schlüssel und Signaturen; die Testvektoren unter `support/sm/` hängen nicht davon ab.

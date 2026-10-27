# ID.SMKT.AUT der Test-gSMC-KT (nur Tests)

Für den Tiger-Proxy `tiger-sicct` zwischen LIANA und `kartos terminal` (LIANA-81, `tools/testhub/tiger-sicct/`). Der
Proxy bricht TLS auf und weist sich gegenüber LIANA als dasselbe KT aus wie kartos. Schlüssel und Zertifikat stammen
aus dem Kartenimage `support/images/gsmckt-valid.xml` (gematik-Testkarte, TEST-ONLY), ausgewählt wie in kartos
(`extract_tls_material`): erstes brainpoolP256r1-Zertifikat im Image (EF.C.SMKT.AUT), privater Schlüssel mit
passendem `P` (PrK.SMKT.AUT.E256). Erzeugt 2026-10-09 mit
`python3 -I tools/pki/smkt-identity.py support/images/gsmckt-valid.xml support/pki/kt/smkt-aut-gsmckt-valid.p12 liana`
(cryptography 48), PKCS#12-Passwort `liana`.

| Datei | Inhalt | SHA-256 | gültig bis |
|---|---|---|---|
| `smkt-aut-gsmckt-valid.p12` | `CN=80276883110000148887, O=gematikTEST-ONLY - NOT-VALID, C=DE`, brainpoolP256r1, Aussteller `GEM.KOMP-CA51 TEST-ONLY` (in der RU-TSL) | `42:40:80:2E:…:D0:5F:27:11` | 2028-07-18 |

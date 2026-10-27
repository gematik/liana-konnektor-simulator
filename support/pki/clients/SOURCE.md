# Clientsysteme: TLS-Client-Zertifikate (nur Tests)

ANCL_CCERT_LIST (TAB_KON_506-01) für das Konnektor-TLS (LIANA-58): `liana.tls.client-certs` nennt die `.pem`, Clients
nutzen die `.p12` (Passwort `liana`), der `.kon`-Export liefert sie als `credentials` vom Typ `pkcs12`
(`liana.kon-export.credentials.keystore`). Selbst signiert wie die vom Konnektor erzeugten Client-Zertifikate
(TIP1-A_4517-04). Erzeugt 2026-10-09 mit `tools/pki/konnektor-tls.sh`.

| Datei | Inhalt | SHA-256 | gültig bis |
|---|---|---|---|
| `cs1-p256.pem` / `.p12` | `CN=LIANA Clientsystem CS1 p256 TEST-ONLY, O=LIANA NOT-VALID, C=DE`, NIST P-256, EKU clientAuth | `17:B0:3C:F0:…:D2:80:FA` | 2031-10-09 |
| `cs1-bp256.pem` / `.p12` | `CN=LIANA Clientsystem CS1 bp256 TEST-ONLY`, brainpoolP256r1, EKU clientAuth | `84:A4:E5:78:…:8F:4B:12` | 2031-10-09 |

# Replay-PKI (nur Tests)

Eigene Test-CA und ES256-Signer (P-256), mit denen Tests SignedScenarios für SecureSendAPDU signieren: die Trace-Tests
signieren Szenarien aus Golden Traces neu, nachdem sie die `clientSessionId` durch die von LIANA vergebene ersetzt
haben (LIANA-23), die Quarkus-Tests bauen eigene Szenarien. LIANA vertraut der Replay-CA nur, wenn sie importiert
ist (`liana.pki.imported-cas`, CERT_IMPORTED_CA_LIST): im Testprofil und in `@PoppKonTuGegenLiana`.

| Datei | Inhalt |
|---|---|
| `replay-ca.pem` | `CN=LIANA Replay-CA TEST-ONLY, O=LIANA NOT-VALID, C=DE`, selbstsigniert, SHA-256 `9E:F7:00:42:…:97:3C` |
| `replay-ca.key.pem` | privater Schlüssel der CA, PKCS#8, unverschlüsselt; Tests stellen damit abweichende Signer aus (`ReplaySigner.issue`) |
| `popp-signer.pem` | `CN=LIANA Replay PoPP-Signer TEST-ONLY`, ausgestellt von der Replay-CA im Profil des PoPP-Service: C.ZD.SIG (1.2.276.0.76.4.287), KeyUsage nonRepudiation, Rolle oid_popp in Admission; SHA-256 `65:51:F9:D6:…:57:38` |
| `popp-signer.key.pem` | privater Schlüssel des Signers, PKCS#8, unverschlüsselt |

- Signer-Schlüssel erzeugt 2026-10-08 (LIANA-23); CA und Signer-Zertifikat 2026-10-08 (LIANA-24) mit
  `openssl req`/`openssl x509 -req`, gültig bis 2036-10-05. Die Admission-Extension ist die DER-Kodierung aus dem
  TU-Signer (`../popp/tu-apdu-sig-oid_popp.pem`).

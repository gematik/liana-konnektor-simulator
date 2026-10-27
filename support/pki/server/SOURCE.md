# Konnektor-TLS: Serveridentität (nur Tests)

Eigene Test-PKI für die TLS-Serveridentität des Konnektors gegenüber Clientsystemen (ID.AK.AUT, TIP1-A_4514-01) und
das KMS (LIANA-58). Nicht in einer TSL, kein OCSP: Clients vertrauen über den `trustStore` aus dem `.kon`-Export
(Auftraggeber 2026-10-09; echte TSL/OCSP-Prüfung: LIANA-87). Erzeugt 2026-10-09 mit `tools/pki/konnektor-tls.sh`
(openssl 3.6), PKCS#12-Passwort `liana`.

| Datei | Inhalt | SHA-256 | gültig bis |
|---|---|---|---|
| `komp-ca.pem` | `CN=LIANA Komp-CA TEST-ONLY, O=LIANA NOT-VALID, C=DE`, P-256, selbst signiert | `9D:DE:5B:51:…:E7:EE:7F` | 2036-10-08 |
| `komp-ca.key.pem` | privater Schlüssel der CA, PKCS#8, unverschlüsselt (nicht im Container) | | |
| `ak-aut-p256.pem` / `.p12` | `CN=LIANA ID.AK.AUT p256 TEST-ONLY`, NIST P-256 (TAB_KON_866: erzeugt bzw. importiert), Kette mit Komp-CA; Standard in `application.yaml` | `5E:2B:4B:3E:…:2E:4D:50` | 2031-10-10 |
| `ak-aut-bp256.pem` / `.p12` | `CN=LIANA ID.AK.AUT bp256 TEST-ONLY`, brainpoolP256r1 wie C.AK.AUT auf der gSMC-K, Kette mit Komp-CA | `4E:5C:22:1F:…:95:E6:5B` | 2031-10-10 |

Beide Zertifikate: KeyUsage digitalSignature, EKU clientAuth und serverAuth wie C.AK.AUT (Tab_PKI_243), SAN `DNS:liana`, `DNS:localhost`,
`IP:127.0.0.1`; 5 Jahre nach A_24483. Brainpool-Schlüssel kann der PKCS12-KeyStore des JDK nicht lesen, LIANA lädt
über BC.

Am 2026-10-10 (LIANA-59) mit denselben Schlüsseln und derselben Komp-CA neu ausgestellt: vorher fehlte EKU clientAuth,
ohne die BCJSSE das Zertifikat nicht als Client-Zertifikat für CETP zur Ereignissenke anbietet (TIP1-A_4595).

## ID.AK.AUT RSA (LIANA-65)

RSA-Variante der Serveridentität, die LIANA nutzt, wenn TLS_USE_ECC_FOR_CS aus ist (EHEX-KMS). Erzeugt 2026-10-10 mit `tools/pki/konnektor-tls.sh --rsa` von derselben Komp-CA; die übrige PKI dieses Ordners ist unverändert. PKCS#12-Passwort `liana`.

| Datei | Inhalt | SHA-256 | gültig bis |
|---|---|---|---|
| `ak-aut-rsa.pem` / `.p12` | `CN=LIANA ID.AK.AUT rsa TEST-ONLY`, RSA-2048 wie C.AK.AUT.R2048 auf der gSMC-K (TAB_KON_866: nutzbar, nicht neu erzeugbar), KeyUsage digitalSignature und keyEncipherment, EKU clientAuth und serverAuth, SAN wie oben, Kette mit Komp-CA | `F5:73:45:F8:…:13:9C:F8:D0` | 2031-10-10 |

## ID.SAK.AUT zum eHealth-KT (LIANA-75)

Konnektor-Identität für die TLS-Verbindung zu den Kartenterminals (TUC_KON_050 Schritt 3, TIP1-A_3258 auf KT-Seite), erzeugt 2026-10-09 mit `tools/pki/sak-aut.sh` von derselben Komp-CA. Die übrige PKI dieses Ordners ist unverändert. PKCS#12-Passwort `liana`.

| Datei | Inhalt | SHA-256 | gültig bis |
|---|---|---|---|
| `sak-aut-bp256.pem` / `.p12` | `CN=LIANA ID.SAK.AUT bp256 TEST-ONLY`, brainpoolP256r1 wie C.SAK.AUT auf der gSMC-K, KeyUsage digitalSignature, EKU clientAuth, Kette mit Komp-CA | `53:45:BD:33:…:73:B9:CB:ED` | 2031-10-09 |

`kartos terminal` prüft das Client-Zertifikat nicht gegen eine TSL. Die Bindung an den Konnektor entsteht beim Pairing (LIANA-77).

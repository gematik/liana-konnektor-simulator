# konnektor-client

Aufnahmen der Konformitätssuite (`konnektor-client-conformance`, LIANA-139) je Produkt und Version, für die Replay-Tests des Konnektor-Clients (`ReplayTransport`). Aufgezeichnet mit `-Dconformance.record=<datei>` über einen Tiger-Proxy; `Authorization` entfernt die Suite vor dem Ablegen. Nie automatisch überschreiben: eine neue Aufnahme kommt in einen neuen Versionsordner.

| Datei | Produkt | Aufnahme |
|---|---|---|
| `LIANA/0.5.26/cards.tgr` | LIANA 0.5.26, wie oben, `conformance.interactive`, `conformance.destructive`, `conformance.liana-admin` | 2026-10-14, Kartenoperationen (`CardOperationsIT`, LIANA-135): GetCards, ReadCardCertificate, GetCardTerminals, RequestCard, GetPinStatus, VerifyPin, ExternalAuthenticate, JWS, Disable-/EnablePin, ChangePin, UnblockPin, EjectCard; Replay streng in `CardOperationsReplayTest` |
| `LIANA/0.5.24/read-only.tgr` | LIANA 0.5.24, neutrales Profil, Standardkonfiguration, HTTP | 2026-10-14, lesende Prüfungen (`ReadOnlyIT`): connector.sds, GetCards, GetCardTerminals, ReadCardCertificate C.AUT der SMC-B, GetPinStatus PIN.SMC |

Mitschnitte echter Konnektoren liegen beim jeweiligen Szenario, etwa `support/vendor/traces/vsdm/vsdm-read-secunet.tgr` (secunet 2.0.0, TU-Lab); der Client spielt ihn in `SecunetReplayTest` ab.

Aufnehmen:

```bash
./mvnw verify -pl konnektor-client-conformance -am -DskipITs=false -Dtest=none -Dsurefire.failIfNoSpecifiedTests=false \
  -DTI_TEST_KON_PATH=<datei.kon> -Dconformance.record=$PWD/support/traces/konnektor-client/<PRODUKT>/<version>/read-only.tgr
```

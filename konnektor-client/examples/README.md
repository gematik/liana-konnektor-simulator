# Beispiele konnektor-client

Ein lauffähiges Beispiel je Operation (LIANA-135), jeweils mit `main(String[] args)`, Argument ist eine `.kon`. Gebaut als Test-Quellen von `konnektor-client`; `ExamplesTest` lässt jedes `run(Konnektor)` gegen die Aufnahme `support/traces/konnektor-client/LIANA/0.5.26/cards.tgr` laufen.

| Beispiel | Operation |
|---|---|
| `ListCards`, `CardsOfType`, `CardByIccsn`, `CardByHandle`, `CardsByTelematikId` | GetCards (+ ReadCardCertificate für die Telematik-ID) |
| `ListTerminals`, `RequestCard`, `EjectCard` | GetCardTerminals, RequestCard, EjectCard |
| `GetPinStatus`, `VerifyPin`, `ChangePin`, `UnblockPin`, `DisableAndEnablePin` | GetPinStatus, VerifyPin, ChangePin, UnblockPin, DisablePin/EnablePin |
| `ReadCertificate` | ReadCardCertificate |
| `ExternalAuthenticate`, `SignJws` | ExternalAuthenticate |
| `GetJobNumber`, `SignCadesDetached`, `SignPades`, `SignXades`, `SignAll`, `StopSignature`, `ComfortSignature` | GetJobNumber, SignDocument, StopSignature, Activate-/DeactivateComfortSignature, GetSignatureMode (LIANA-136) |
| `EncryptForCard`, `Decrypt` | EncryptDocument, DecryptDocument (LIANA-136) |
| `VerifySignature`, `VerifyCertificate` | VerifyDocument, VerifyCertificate (LIANA-136) |

Die Beispiele aus LIANA-136 prüft `ExamplesTest` bis zum Request (gültig gegen das Schema): LIANA setzt diese Operationen nur bis zur Zugriffsprüfung um, Mitschnitte echter Konnektoren fehlen noch.

Gegen LIANA (Admin-API und `.kon`-Export, docs/handbuch.md „Admin-API“):

```bash
curl -o cs1.kon localhost:9090/admin/clients/CS1/config.kon
./mvnw -q test-compile -pl konnektor-client -am
java -cp "konnektor-client/target/test-classes:konnektor-client/target/classes:$(./mvnw -q -pl konnektor-client dependency:build-classpath -Dmdep.outputFile=/dev/stdout)" \
  de.gematik.liana.konnektor.examples.ListCards cs1.kon
```

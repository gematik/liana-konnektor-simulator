# connector-sds

popp-client (popp-example-impl, `ConnectorServicesFactory`) holt beim Start `GET /connector.sds` über `RestTemplate` und nimmt je Dienst (EventService, CardService) die höchste Version und deren `Endpoint`.

- Quelle: **von Hand** erstellt (2026-10-08, LIANA-6). Request nach dem Verhalten von popp-client, Antwort nach TIP1-A_4528/TIP1-A_4529-02 mit den Dienstversionen, die LIANA anbietet (EventService 7.2.0, CardService 8.2.1). LIANA ist unter `http://liana:8080` erreichbar.
- Kein Mitschnitt eines echten Konnektors; wird ersetzt oder ergänzt, sobald ein aufgezeichneter Trace vorliegt.
- Geprüft von `liana-trace-tests/…/ConnectorSdsTraceIT`.

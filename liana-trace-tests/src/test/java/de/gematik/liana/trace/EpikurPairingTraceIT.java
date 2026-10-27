/*
 * Copyright 2026 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */
package de.gematik.liana.trace;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIfSystemProperty;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Epikur (XML-WS Runtime 4.0.3, Java 25) pairs with LIANA 0.6.50 via {@code
 * tools/testhub/ps-proxy.sh}, epic LIANA-189: reachability check {@code GET /}, service discovery,
 * then the polling of GetResourceInformation, GetCardTerminals, GetCards and GetPinStatus. Replayed
 * with the same LIANA configuration as in the PS lab.
 */
@Tag("vendor-data")
@DisabledIfSystemProperty(
    named = "liana.trace.terminal",
    matches = "sicct",
    disabledReason =
        "Trace mit den Fake-KTs aus liana-epikur.yaml, am eHealth-KT stecken andere Karten")
@TraceReplay("support/vendor/traces/ps-epikur/epikur-pairing.tgr")
@LianaConfig(
    value = "quarkus.config.locations=tools/testhub/ps-proxy/liana-epikur.yaml",
    why =
        "Infomodell von Epikur (MEpikur, Epikur, ap2), Profil SECUNET und gSMC-KT in KT-01/3 wie im PS-Labor")
@LianaConfig(
    value = {"liana.kon-export.url=http://10.150.82.126", "liana.tls.url=https://10.150.82.126"},
    why = "connector.sds nannte die Adresse des Proxys im PS-Labor (PS_HOST)")
@Carry(value = "$..CardHandle.text", why = "CardHandle, vergibt LIANA beim Stecken")
class EpikurPairingTraceIT {

  private static final String SERVICE = "$.body.ConnectorServices.ServiceInformation.Service";

  /** The exchanges whose request contains {@code marker} (path or operation), in trace order. */
  private static List<Exchange> exchanges(Replay replay, String marker) {
    var found =
        replay.exchanges().stream()
            .filter(
                e ->
                    new String(e.request().getRawContent(), StandardCharsets.UTF_8)
                        .contains(marker))
            .toList();
    assertFalse(found.isEmpty(), "kein Request mit " + marker + " im Trace");
    return found;
  }

  @Test
  @DisplayName(
      "LIANA-189 AC #1: jeder Request von Epikur bekommt denselben HTTP-Status wie im PS-Labor (alle 200)")
  void alleAntwortenWieImTrace(Replay replay) {
    replay.exchanges().forEach(e -> e.assertSameAt("$.responseCode"));
    assertEquals(
        List.of("200"),
        replay.exchanges().stream()
            .map(
                e ->
                    e.traceResponse()
                        .findElement("$.responseCode")
                        .orElseThrow()
                        .getRawStringContent())
            .distinct()
            .toList());
  }

  @Test
  @DisplayName("LIANA-189.02 Erreichbarkeitsprüfung: GET / liefert 200 text/html")
  void erreichbarkeit(Replay replay) {
    exchanges(replay, "GET / HTTP")
        .forEach(
            e ->
                e.assertThatLianaResponse()
                    .hasStringContentEqualToAtPosition("$.responseCode", "200"));
  }

  @ParameterizedTest(name = "{0}")
  @ValueSource(
      strings = {
        "EventService",
        "CardTerminalService",
        "CardService",
        "CertificateService",
        "VSDService",
        "KVKService"
      })
  @DisplayName(
      "TIP1-A_4528 / LIANA-189.01 connector.sds: die Dienste, die Epikur verlangt, mit Versionen und "
          + "Endpunkten wie im Trace")
  void dienstverzeichnis(String service, Replay replay) {
    String versions = SERVICE + "[?(@.Name=='" + service + "')].Versions.Version";
    exchanges(replay, "GET /connector.sds")
        .forEach(
            e ->
                e.assertSameAt(
                    versions + ".Version",
                    versions + ".TargetNamespace",
                    versions + ".EndpointTLS.Location"));
  }

  @Test
  @DisplayName(
      "TIP1-A_4607 GetResourceInformation: Result, VPN TI Online, VPN SIS Offline wie im Trace")
  void ressourceninformation(Replay replay) {
    exchanges(replay, "#GetResourceInformation")
        .forEach(
            e ->
                e.assertSameAt(
                    "$..Status.Result.text",
                    "$..VPNTIStatus.ConnectionStatus.text",
                    "$..VPNSISStatus.ConnectionStatus.text"));
  }

  @Test
  @DisplayName("TIP1-A_4604 GetCardTerminals: dieselben KTs wie im Trace")
  void kartenterminals(Replay replay) {
    exchanges(replay, "#GetCardTerminals")
        .forEach(e -> e.assertSameAt("$..Status.Result.text", "$..CardTerminal.CtId.text"));
  }

  /**
   * ICCSN from the trace → ICCSN in LIANA: since 0.7.3 smcb-valid is the public SMC-B from
   * ti2.0-testhub, the PS lab still ran with the earlier one (support/images/README.md).
   */
  private static final Map<String, String> ICCSN =
      Map.of("80276883110000168762", "80276883110000168650");

  @Test
  @DisplayName(
      "TIP1-A_4605-03 GetCards / LIANA-188: eGK, SMC-B und gSMC-KT in KT-01/1–3 wie im Trace")
  void karten(Replay replay) {
    String iccsn = "$..Card.Iccsn.text";
    exchanges(replay, "#GetCards")
        .forEach(
            e -> {
              e.assertSameAt(
                  "$..Status.Result.text",
                  "$..Card.CardType.text",
                  "$..Card.CtId.text",
                  "$..Card.SlotId.text");
              assertEquals(
                  e.traceResponse().findRbelPathMembers(iccsn).stream()
                      .map(
                          v -> ICCSN.getOrDefault(v.getRawStringContent(), v.getRawStringContent()))
                      .toList(),
                  e.lianaResponse().findRbelPathMembers(iccsn).stream()
                      .map(v -> v.getRawStringContent())
                      .toList(),
                  iccsn);
            });
  }

  @Test
  @DisplayName(
      "TUC_KON_022 GetPinStatus: PIN.CH der eGK VERIFIABLE wie im Trace; PIN.SMC VERIFIABLE statt VERIFIED, "
          + "weil die SMC-B im Labor vor dem Pairing per VerifyPin freigeschaltet wurde (nicht im Trace)")
  void pinStatus(Replay replay) {
    var pinStatus = exchanges(replay, "#GetPinStatus");
    pinStatus.stream()
        .filter(e -> raw(e).contains("PIN.CH"))
        .forEach(e -> e.assertSameAt("$..Status.Result.text", "$..PinStatus.text"));
    pinStatus.stream()
        .filter(e -> raw(e).contains("PIN.SMC"))
        .forEach(
            e -> {
              e.assertSameAt("$..Status.Result.text");
              e.assertThatLianaResponse()
                  .hasStringContentEqualToAtPosition("$..PinStatus.text", "VERIFIABLE");
            });
  }

  private static String raw(Exchange exchange) {
    return new String(exchange.request().getRawContent(), StandardCharsets.UTF_8);
  }
}

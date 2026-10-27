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
package de.gematik.liana.postman;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;

/**
 * {@code EE_KON_POPP_GF_015.postman_collection.json} (konnektor-popp-testsuite 9069cae): like
 * GF_001, but with the online feature scope (Leistungsumfang Online) switched off:
 * ensureConnectorOffline sets MGM_LU_ONLINE=Disabled via the KMS (TAB_KON_658), at the end
 * ensureConnectorOnline restores Enabled. PerformPoPP runs the same way offline (A_25860-01,
 * A_26022). For Bridge_responses 4 see {@link EeKonPoppGf001Test}.
 */
@QuarkusTest
@DisplayName("EE_KON_POPP_GF_015 PerformPoPP mit MGM_LU_ONLINE=Disabled")
class EeKonPoppGf015Test extends KmsPostmanCollection {

  @Test
  @Order(1)
  @DisplayName("GetConnector.sds: EndPoint für Services erfolgreich extrahiert")
  void getConnectorSdsRequest() {
    getConnectorSds();
  }

  @Test
  @Order(2)
  @DisplayName("GetCards: Statuscode ist 200, EGK CardHandle erfolgreich extrahiert")
  void getCardsRequest() {
    getCards();
  }

  @Test
  @Order(3)
  @DisplayName(
      "TAB_KON_658 ensureConnectorOffline: ensureKmsParameter MGM_LU_ONLINE=Disabled, status ok")
  void ensureConnectorOffline() {
    assertEquals("ok", kms.ensureOnline("Disabled"));
  }

  @Test
  @Order(4)
  @DisplayName("A_25970-01 StartCardSession: Statuscode ist 200, SessionId erfolgreich extrahiert")
  void startCardSessionRequest() {
    startCardSession();
  }

  @Test
  @Order(5)
  @DisplayName("Bridge_websocket_start")
  void bridgeWebsocketStartRequest() {
    bridge.connect();
  }

  @Test
  @Order(6)
  @DisplayName("Bridge_start: SignedScenario")
  void bridgeStartRequest() {
    bridgeStart();
  }

  @Test
  @Order(7)
  @DisplayName(
      "A_25822-02 SecureSendApdu 1: Prerequest Typ, Alg, Type, ClientSessionId, SequenceCounter, Message Steps exists; Statuscode ist 200")
  void secureSendApdu1() {
    secureSendApdu(signedScenario);
  }

  @Test
  @Order(8)
  @DisplayName(
      "Bridge_responses 1: ScenarioResponse mit den Antwort-APDUs, nächstes SignedScenario")
  void bridgeResponses1() {
    bridgeResponses();
  }

  @Test
  @Order(9)
  @DisplayName(
      "A_25822-02 SecureSendApdu 2: Prerequest Typ, Alg, Type, ClientSessionId, SequenceCounter, Message Steps exists; Statuscode ist 200")
  void secureSendApdu2() {
    secureSendApdu(signedScenario);
  }

  @Test
  @Order(10)
  @DisplayName(
      "Bridge_responses 2: ScenarioResponse mit den Antwort-APDUs, nächstes SignedScenario")
  void bridgeResponses2() {
    bridgeResponses();
  }

  @Test
  @Order(11)
  @DisplayName(
      "A_25822-02 SecureSendApdu 3: Prerequest Typ, Alg, Type, ClientSessionId, SequenceCounter, Message Steps exists; Statuscode ist 200")
  void secureSendApdu3() {
    secureSendApdu(signedScenario);
  }

  @Test
  @Order(12)
  @DisplayName(
      "Bridge_responses 3: ScenarioResponse mit den Antwort-APDUs, nächstes SignedScenario")
  void bridgeResponses3() {
    bridgeResponses();
  }

  @Test
  @Order(13)
  @DisplayName("A_25822-02 SecureSendApdu 4: Statuscode ist 200 (letztes Szenario, timeSpan 0)")
  void secureSendApdu4() {
    secureSendApdu(signedScenario);
  }

  @Test
  @Order(14)
  @DisplayName(
      "Bridge_responses 4: ScenarioResponse mit den Antwort-APDUs (Prüfungen des PoPP-Tokens betreffen den PoPP-Service)")
  void bridgeResponses4() {
    assertFalse(responses.isEmpty(), "Antwort-APDUs von SecureSendApdu 4");
  }

  @Test
  @Order(15)
  @DisplayName("A_25860-01 FindInLog: CARD/SESSION/TIMEOUT ist in Log vorhanden (Timer=PoPP)")
  void findInLogRequest() {
    findInLog("PoPP");
  }

  @Test
  @Order(16)
  @DisplayName("Bridge_websocket_stop")
  void bridgeWebsocketStopRequest() {
    bridgeWebsocketStop();
  }

  @Test
  @Order(17)
  @DisplayName(
      "TAB_KON_658 ensureConnectorOnline: ensureKmsParameter MGM_LU_ONLINE=Enabled, status ok")
  void ensureConnectorOnline() {
    assertEquals("ok", kms.ensureOnline("Enabled"));
  }

  @Test
  @Order(18)
  @DisplayName(
      "A_26022 StopCardSession: Statuscode ist 500, Fehler code ist 4288, Fehler errorText ist Unbekannte Session ID")
  void stopCardSessionRequest() {
    stopCardSessionUnknown();
  }
}

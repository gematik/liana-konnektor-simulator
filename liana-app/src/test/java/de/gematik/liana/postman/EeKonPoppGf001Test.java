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

import static org.junit.jupiter.api.Assertions.assertFalse;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;

/**
 * {@code EE_KON_POPP_GF_001.postman_collection.json} (konnektor-popp-testsuite 9069cae): good case
 * PerformPoPP via the Konnektor, four scenarios up to the last one with timeSpan 0. Afterwards the
 * card session ends with CARD/SESSION/TIMEOUT {@code Timer=PoPP} (A_25860-01, TUC_KON_208 step 7),
 * FindInLog finds the event via the KMS (TIP1-A_4715), StopCardSession returns 4288 (A_26022).
 *
 * <p>In Postman, Bridge_responses 4 checks the PoPP token (patientId, actorId, iat …); the PoPP
 * service issues it, not LIANA. The replacement {@link PoppServiceDouble} has no token, so the step
 * only checks the response APDUs; the token checks run in the cross-check with popp-bridge and PoPP
 * server (LIANA-40 runner).
 */
@QuarkusTest
@DisplayName(
    "EE_KON_POPP_GF_001 PerformPoPP mit CARD/SESSION/TIMEOUT Timer=PoPP im Systemprotokoll")
class EeKonPoppGf001Test extends KmsPostmanCollection {

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
  @DisplayName("A_25970-01 StartCardSession: Statuscode ist 200, SessionId erfolgreich extrahiert")
  void startCardSessionRequest() {
    startCardSession();
  }

  @Test
  @Order(4)
  @DisplayName("Bridge_websocket_start")
  void bridgeWebsocketStartRequest() {
    bridge.connect();
  }

  @Test
  @Order(5)
  @DisplayName("Bridge_start: SignedScenario")
  void bridgeStartRequest() {
    bridgeStart();
  }

  @Test
  @Order(6)
  @DisplayName(
      "A_25822-02 SecureSendApdu 1: Prerequest Typ, Alg, Type, ClientSessionId, SequenceCounter, Message Steps exists; Statuscode ist 200")
  void secureSendApdu1() {
    secureSendApdu(signedScenario);
  }

  @Test
  @Order(7)
  @DisplayName(
      "Bridge_responses 1: ScenarioResponse mit den Antwort-APDUs, nächstes SignedScenario")
  void bridgeResponses1() {
    bridgeResponses();
  }

  @Test
  @Order(8)
  @DisplayName(
      "A_25822-02 SecureSendApdu 2: Prerequest Typ, Alg, Type, ClientSessionId, SequenceCounter, Message Steps exists; Statuscode ist 200")
  void secureSendApdu2() {
    secureSendApdu(signedScenario);
  }

  @Test
  @Order(9)
  @DisplayName(
      "Bridge_responses 2: ScenarioResponse mit den Antwort-APDUs, nächstes SignedScenario")
  void bridgeResponses2() {
    bridgeResponses();
  }

  @Test
  @Order(10)
  @DisplayName(
      "A_25822-02 SecureSendApdu 3: Prerequest Typ, Alg, Type, ClientSessionId, SequenceCounter, Message Steps exists; Statuscode ist 200")
  void secureSendApdu3() {
    secureSendApdu(signedScenario);
  }

  @Test
  @Order(11)
  @DisplayName(
      "Bridge_responses 3: ScenarioResponse mit den Antwort-APDUs, nächstes SignedScenario")
  void bridgeResponses3() {
    bridgeResponses();
  }

  @Test
  @Order(12)
  @DisplayName("A_25822-02 SecureSendApdu 4: Statuscode ist 200 (letztes Szenario, timeSpan 0)")
  void secureSendApdu4() {
    secureSendApdu(signedScenario);
  }

  @Test
  @Order(13)
  @DisplayName(
      "Bridge_responses 4: ScenarioResponse mit den Antwort-APDUs (Prüfungen des PoPP-Tokens betreffen den PoPP-Service)")
  void bridgeResponses4() {
    assertFalse(responses.isEmpty(), "Antwort-APDUs von SecureSendApdu 4");
  }

  @Test
  @Order(14)
  @DisplayName("A_25860-01 FindInLog: CARD/SESSION/TIMEOUT ist in Log vorhanden (Timer=PoPP)")
  void findInLogRequest() {
    findInLog("PoPP");
  }

  @Test
  @Order(15)
  @DisplayName("Bridge_websocket_stop")
  void bridgeWebsocketStopRequest() {
    bridgeWebsocketStop();
  }

  @Test
  @Order(16)
  @DisplayName(
      "A_26022 StopCardSession: Statuscode ist 500, Fehler code ist 4288, Fehler errorText ist Unbekannte Session ID")
  void stopCardSessionRequest() {
    stopCardSessionUnknown();
  }
}

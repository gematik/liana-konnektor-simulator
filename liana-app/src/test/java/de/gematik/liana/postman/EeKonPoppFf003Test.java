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

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;

/**
 * {@code EE_KON_POPP_FF_003.postman_collection.json} (konnektor-popp-testsuite 9069cae): send the
 * first scenario again after the PoPP service has delivered scenario 1 → 4285 „Unerwartetes
 * Sequence-Element“ (A_26069-01, TUC_KON_208); the session is ended afterwards, StopCardSession →
 * 4288.
 */
@QuarkusTest
@DisplayName("EE_KON_POPP_FF_003 SecureSendAPDU mit überholtem sequenceCounter → 4285")
class EeKonPoppFf003Test extends PostmanCollection {

  String firstSignedScenario;

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
  @DisplayName("Bridge_start: SignedScenario und FirstSignedScenario")
  void bridgeStartRequest() {
    bridgeStart();
    firstSignedScenario = signedScenario;
  }

  @Test
  @Order(6)
  @DisplayName("A_25822-02 SecureSendApdu 1: Statuscode ist 200")
  void secureSendApdu1() {
    secureSendApdu(signedScenario);
  }

  @Test
  @Order(7)
  @DisplayName("Bridge_responses 1: SignedScenario (Szenario 1)")
  void bridgeResponses1() {
    bridgeResponses();
  }

  @Test
  @Order(8)
  @DisplayName(
      "A_26069-01 SecureSendApdu 2 mit FirstSignedScenario: Fehler code ist 4285, errorText Unerwartetes Sequence-Element")
  void secureSendApdu2() {
    scenarioFromPoppService(firstSignedScenario);
    assertFault(
        konnektor.secureSendApdu(endpoints, firstSignedScenario),
        "4285",
        "Unerwartetes Sequence-Element");
  }

  @Test
  @Order(9)
  @DisplayName("Bridge_websocket_stop")
  void bridgeWebsocketStopRequest() {
    bridgeWebsocketStop();
  }

  @Test
  @Order(10)
  @DisplayName(
      "A_26022 StopCardSession: Statuscode ist 500, Fehler code ist 4288, errorText Unbekannte Session ID")
  void stopCardSessionRequest() {
    stopCardSessionUnknown();
  }
}

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
 * {@code EE_KON_POPP_FF_014.postman_collection.json} (konnektor-popp-testsuite 9069cae): in the
 * first step, the bridge renames {@code expectedStatusWords} to {@code expectedStatus} and re-signs
 * → 4286 „Inhalt des signierten Szenarios nicht valide“ (A_26069-01 TUC_KON_208).
 */
@QuarkusTest
@DisplayName("EE_KON_POPP_FF_014 expectedStatusWords umbenannt → 4286")
class EeKonPoppFf014Test extends PostmanCollection {

  String manSignedScenario;

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
  @DisplayName("renameFirstExpectedStatusWordsInPayload: ManSignedScenario")
  void renameFirstExpectedStatusWordsInPayload() {
    manSignedScenario =
        PoppServiceDouble.renameFirstExpectedStatusWords(signedScenario, "expectedStatus");
  }

  @Test
  @Order(7)
  @DisplayName(
      "A_26069-01 SecureSendApdu 1: Statuscode ist 500, Fehlercode 4286, Text Inhalt des signierten Szenarios nicht valide")
  void secureSendApdu1() {
    scenarioFromPoppService(manSignedScenario);
    assertFault(
        konnektor.secureSendApdu(endpoints, manSignedScenario),
        "4286",
        "Inhalt des signierten Szenarios nicht valide");
  }

  @Test
  @Order(8)
  @DisplayName("Bridge_websocket_stop")
  void bridgeWebsocketStopRequest() {
    bridgeWebsocketStop();
  }

  @Test
  @Order(9)
  @DisplayName("A_26022 StopCardSession: Statuscode ist 200, Result ist OK")
  void stopCardSessionRequest() {
    stopCardSession();
  }
}

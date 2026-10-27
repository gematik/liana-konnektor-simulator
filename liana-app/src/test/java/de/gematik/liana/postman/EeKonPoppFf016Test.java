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
 * {@code EE_KON_POPP_FF_016.postman_collection.json} (konnektor-popp-testsuite 9069cae): the bridge
 * re-signs scenario 1 with a certificate of the technical role oid_tigw_zugm (1.2.276.0.76.4.309)
 * instead of oid_popp → 4700 „Zertifikat enthält nicht die erwartete Rolle“ (GS-A_4446-16,
 * TUC_KON_037). Signer certificate from the replay CA instead of GEM.KOMP-CA55 (bridge, {@code
 * certs/oid309}).
 */
@QuarkusTest
@DisplayName("EE_KON_POPP_FF_016 Szenario mit Rolle oid_tigw_zugm signiert → 4700")
class EeKonPoppFf016Test extends PostmanCollection {

  String manipulatedSignedScenario;

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
  @DisplayName("resignScenario oid_309: ManipulatedSignedScenario")
  void resignScenario() {
    manipulatedSignedScenario = PoppServiceDouble.resign(signedScenario, "1.2.276.0.76.4.309");
  }

  @Test
  @Order(9)
  @DisplayName(
      "GS-A_4446-16 SecureSendApdu 2: Statuscode ist 500, Fehlercode 4700, Text Zertifikat enthält nicht die erwartete Rolle")
  void secureSendApdu2() {
    scenarioFromPoppService(manipulatedSignedScenario);
    assertFault(
        konnektor.secureSendApdu(endpoints, manipulatedSignedScenario),
        "4700",
        "Zertifikat enthält nicht die erwartete Rolle");
  }

  @Test
  @Order(10)
  @DisplayName("Bridge_websocket_stop")
  void bridgeWebsocketStopRequest() {
    bridgeWebsocketStop();
  }

  @Test
  @Order(11)
  @DisplayName("A_26022 StopCardSession: Statuscode ist 200, Result ist OK")
  void stopCardSessionRequest() {
    stopCardSession();
  }
}

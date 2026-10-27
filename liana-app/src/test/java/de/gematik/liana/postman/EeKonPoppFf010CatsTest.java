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

import de.gematik.liana.adapter.fake.FakeTerminals;
import de.gematik.liana.adapter.fake.Fault;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;

/**
 * {@code EE_KON_POPP_FF_010_cats.postman_collection.json} (konnektor-popp-testsuite 9069cae): at
 * the card terminal (CATS 1.2.0) the card response in the third scenario is manipulated → status
 * Warning with 4284 „APDU konnte nicht verarbeitet werden.“ (A_26069-01 TUC_KON_208, A_25822-02).
 *
 * <p>Deviations from the collection: the manipulation at CATS is replaced by a fault at the fake KT
 * (LIANA-41, status word 6F00 on the first command of scenario 2, MSE SET AT). SOAPAction and
 * bridge body as in the other collections: the collection sends {@code SOAPAction: SecureSendApdu}
 * (instead of {@code …#SecureSendAPDU}), to which LIANA answers with a SOAP fault, and {@code
 * "responses"} instead of {@code "steps"}, to which the PoPP service reports 79511 (LIANA-40, run
 * 20261009-130347).
 */
@QuarkusTest
@DisplayName("EE_KON_POPP_FF_010_cats Kartenantwort am KT manipuliert → Warnung 4284")
class EeKonPoppFf010CatsTest extends PostmanCollection {

  @Inject FakeTerminals terminals;

  @AfterAll
  void clearFault() {
    terminals.terminal("KT-01").clearFault(1);
  }

  @Test
  @Order(1)
  @DisplayName("GetConnector.sds: Status code is 200, EndPoint für Services erfolgreich extrahiert")
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
  @DisplayName("A_25822-02 SecureSendApdu 2: Statuscode ist 200")
  void secureSendApdu2() {
    secureSendApdu(signedScenario);
  }

  @Test
  @Order(9)
  @DisplayName("Bridge_responses 2: SignedScenario (Szenario 2)")
  void bridgeResponses2() {
    bridgeResponses();
  }

  @Test
  @Order(10)
  @DisplayName("CATS: Kartenantwort auf MSE SET AT manipuliert (Fake-KT-Störung 6F00, LIANA-41)")
  void catsManipulatesCardResponse() {
    terminals.terminal("KT-01").fault(1, Fault.statusWord("6F00").onlyFor("002241A4").times(1));
  }

  @Test
  @Order(11)
  @DisplayName(
      "A_26069-01 SecureSendApdu 3: Statuscode ist 200, Result ist Warning, Warnungscode 4284, Warnungstext passt exakt")
  void secureSendApdu3() {
    scenarioFromPoppService(signedScenario);
    var answer = konnektor.secureSendApdu(endpoints, signedScenario);
    assertWarning(answer, "4284", "APDU konnte nicht verarbeitet werden.");
    assertEquals(
        java.util.List.of("6F00"),
        answer.responseApdus(),
        "Antwort der Karte ist die manipulierte");
  }

  @Test
  @Order(12)
  @DisplayName("Bridge_websocket_stop")
  void bridgeWebsocketStopRequest() {
    bridgeWebsocketStop();
  }

  @Test
  @Order(13)
  @DisplayName("A_26022 StopCardSession: Statuscode ist 200, Result ist OK")
  void stopCardSessionRequest() {
    stopCardSession();
  }
}

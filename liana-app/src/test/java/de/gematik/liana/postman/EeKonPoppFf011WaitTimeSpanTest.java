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
import java.time.Duration;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;

/**
 * {@code EE_KON_POPP_FF_011_waitTimeSpan.postman_collection.json} (konnektor-popp-testsuite
 * 9069cae): after the first scenario, the pre-request script of SecureSendApdu 2 waits for the
 * timeSpan of the scenario plus {@code timeoutTolerance}; the card session has then expired
 * (A_25860-01 a): SecureSendApdu 2 and StopCardSession return 4288, FindInLog finds
 * CARD/SESSION/TIMEOUT with {@code Timer=PoPP}. Instead of waiting, the test advances the clock.
 */
@QuarkusTest
@DisplayName("EE_KON_POPP_FF_011_waitTimeSpan TimeSpan abgelaufen → 4288, Timer=PoPP")
class EeKonPoppFf011WaitTimeSpanTest extends KmsPostmanCollection {

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
  @DisplayName("Bridge_websocket_stop")
  void bridgeWebsocketStopRequest() {
    bridgeWebsocketStop();
  }

  @Test
  @Order(9)
  @DisplayName(
      "A_25860-01 SecureSendApdu 2 nach timeSpan + timeoutTolerance: Statuscode ist 500, Fehler code ist 4288, Fehler errorText ist Unbekannte Session ID")
  void secureSendApdu2() {
    scenarioFromPoppService(signedScenario);
    waitFor(
        Duration.ofMillis(PoppServiceDouble.message(signedScenario).getLong("timeSpan"))
            .plus(TIMEOUT_TOLERANCE));
    assertFault(
        konnektor.secureSendApdu(endpoints, signedScenario), "4288", "Unbekannte Session ID");
  }

  @Test
  @Order(10)
  @DisplayName("A_25860-01 FindInLog: CARD/SESSION/TIMEOUT ist in Log vorhanden (Timer=PoPP)")
  void findInLogRequest() {
    findInLog("PoPP");
  }

  @Test
  @Order(11)
  @DisplayName(
      "A_26022 StopCardSession: Statuscode ist 500, Fehler code ist 4288, Fehler errorText ist Unbekannte Session ID")
  void stopCardSessionRequest() {
    stopCardSessionUnknown();
  }
}

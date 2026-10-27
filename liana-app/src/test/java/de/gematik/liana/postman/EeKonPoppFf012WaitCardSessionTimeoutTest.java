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

import io.quarkus.test.junit.QuarkusTest;
import java.time.Duration;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;

/**
 * {@code EE_KON_POPP_FF_012_waitCardSessionTimeout.postman_collection.json}
 * (konnektor-popp-testsuite 9069cae): the collection reads CARD_SESSION_TIMEOUT via the KMS, starts
 * a card session and sends the first scenario only after CARD_SESSION_TIMEOUT plus {@code
 * timeoutTolerance}; the session has then expired (A_25860-01 b): SecureSendApdu 1 and
 * StopCardSession return 4288, FindInLog finds CARD/SESSION/TIMEOUT with {@code Timer=Konnektor}.
 * Instead of waiting, the test advances the clock.
 */
@QuarkusTest
@DisplayName(
    "EE_KON_POPP_FF_012_waitCardSessionTimeout CARD_SESSION_TIMEOUT abgelaufen → 4288, Timer=Konnektor")
class EeKonPoppFf012WaitCardSessionTimeoutTest extends KmsPostmanCollection {

  /** {@code cardSessionTimeout} of the environment in seconds. */
  long cardSessionTimeout;

  @Test
  @Order(1)
  @DisplayName("GetConnector.sds: EndPoint für Services erfolgreich extrahiert")
  void getConnectorSdsRequest() {
    getConnectorSds();
  }

  @Test
  @Order(2)
  @DisplayName(
      "TAB_KON_554 getCardSessionTimeout: CARD_SESSION_TIMEOUT über das KMS (cardSessionTimeout)")
  void getCardSessionTimeoutRequest() {
    cardSessionTimeout = Long.parseLong(kms.getCardSessionTimeout());
    assertEquals(settings.sessionTimeout().toSeconds(), cardSessionTimeout);
  }

  @Test
  @Order(3)
  @DisplayName("GetCards: Statuscode ist 200, EGK CardHandle erfolgreich extrahiert")
  void getCardsRequest() {
    getCards();
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
  @DisplayName("Bridge_websocket_stop")
  void bridgeWebsocketStopRequest() {
    bridgeWebsocketStop();
  }

  @Test
  @Order(8)
  @DisplayName(
      "A_25860-01 SecureSendApdu 1 nach CARD_SESSION_TIMEOUT + timeoutTolerance: Statuscode ist 500, Fehler code ist 4288, Fehler errorText ist Unbekannte Session ID")
  void secureSendApdu1() {
    scenarioFromPoppService(signedScenario);
    waitFor(Duration.ofSeconds(cardSessionTimeout).plus(TIMEOUT_TOLERANCE));
    assertFault(
        konnektor.secureSendApdu(endpoints, signedScenario), "4288", "Unbekannte Session ID");
  }

  @Test
  @Order(9)
  @DisplayName("A_25860-01 FindInLog: CARD/SESSION/TIMEOUT ist in Log vorhanden (Timer=Konnektor)")
  void findInLogRequest() {
    findInLog("Konnektor");
  }

  @Test
  @Order(10)
  @DisplayName(
      "A_26022 StopCardSession: Statuscode ist 500, Fehler code ist 4288, Fehler errorText ist Unbekannte Session ID")
  void stopCardSessionRequest() {
    stopCardSessionUnknown();
  }
}

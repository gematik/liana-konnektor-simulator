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
 * {@code EE_KON_POPP_FF_006.postman_collection.json} (konnektor-popp-testsuite 9069cae): a second
 * StartCardSession on the eGK with a running card session → 4093 „Karte wird in einer anderen
 * Kartensitzung exklusiv verwendet“ (A_25970-01, TIP1-A_4571 TUC_KON_023).
 */
@QuarkusTest
@DisplayName("EE_KON_POPP_FF_006 zweite StartCardSession auf dieselbe eGK → 4093")
class EeKonPoppFf006Test extends PostmanCollection {

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
  @DisplayName(
      "A_25970-01 StartCardSession: Statuscode ist 500, Fehler code ist 4093, errorText Karte wird in einer anderen Kartensitzung exklusiv verwendet")
  void startCardSessionAgain() {
    assertFault(
        konnektor.startCardSession(endpoints, cardHandle),
        "4093",
        "Karte wird in einer anderen Kartensitzung exklusiv verwendet");
  }

  @Test
  @Order(5)
  @DisplayName("A_26022 StopCardSession: Statuscode ist 200, Result ist OK")
  void stopCardSessionRequest() {
    stopCardSession();
  }
}

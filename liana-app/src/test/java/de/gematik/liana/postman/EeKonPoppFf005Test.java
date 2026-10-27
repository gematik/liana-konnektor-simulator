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

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;

/**
 * {@code EE_KON_POPP_FF_005.postman_collection.json} (konnektor-popp-testsuite 9069cae):
 * StartCardSession on an inserted HBA → 4209 „Kartentyp HBA wird durch diese Operation nicht
 * unterstützt.“ (A_25970-01).
 *
 * <p>The HBA is hba-valid, in KT-01/3 in the test profile (LIANA-56).
 */
@QuarkusTest
@DisplayName("EE_KON_POPP_FF_005 StartCardSession auf HBA → 4209")
class EeKonPoppFf005Test extends PostmanCollection {

  @Test
  @Order(1)
  @DisplayName("GetConnector.sds: EndPoint für Services erfolgreich extrahiert")
  void getConnectorSdsRequest() {
    getConnectorSds();
  }

  @Test
  @Order(2)
  @DisplayName("GetCards: Statuscode ist 200, HBA CardHandle erfolgreich extrahiert")
  void getCardsRequest() {
    var answer = konnektor.getCards(endpoints);
    cardHandle = Konnektor.cardHandle(answer, "HBA");
    assertAll(
        "GetCards",
        () -> assertEquals(200, answer.status(), "Statuscode ist 200"),
        () -> assertNotNull(cardHandle, "HBA CardHandle erfolgreich extrahiert"));
  }

  @Test
  @Order(3)
  @DisplayName(
      "A_25970-01 StartCardSession: Statuscode ist 500, Fehler code ist 4209, errorText Kartentyp HBA wird durch diese Operation nicht unterstützt.")
  void startCardSessionRequest() {
    assertFault(
        konnektor.startCardSession(endpoints, cardHandle),
        "4209",
        "Kartentyp HBA wird durch diese Operation nicht unterstützt.");
  }
}

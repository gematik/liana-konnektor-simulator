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

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;

import de.gematik.liana.admin.AdminServer;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import java.time.Clock;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;

/**
 * LIANA-54 AC3: the PoPP good case as in {@code EE_KON_POPP_GF_001} up to the last scenario
 * (timeSpan 0); afterwards CARD/SESSION/TIMEOUT with {@code Timer=PoPP} is in the Systemprotokoll,
 * the way findInLog searches for it via the KMS (LIANA-55). Retrieved via the Admin API with the
 * time filter from the start of the card session.
 */
@QuarkusTest
@DisplayName("Systemprotokoll: CARD/SESSION/TIMEOUT nach dem letzten Szenario (TimeSpan 0)")
class SystemLogTimeoutTest extends PostmanCollection {

  @Inject AdminServer admin;

  /** LIANA's clock; it may be ahead of the system time (ShiftableClock, LIANA-55). */
  @Inject Clock clock;

  Instant started;

  @Test
  @Order(1)
  @DisplayName("GetConnector.sds, GetCards, StartCardSession, Bridge_websocket_start, Bridge_start")
  void start() {
    getConnectorSds();
    getCards();
    started = clock.instant();
    startCardSession();
    bridge.connect();
    bridgeStart();
  }

  @Test
  @Order(2)
  @DisplayName("SecureSendApdu 1–4 mit den Szenarien 0–3, das letzte hat timeSpan 0")
  void scenarios() {
    for (int i = 0; i < 3; i++) {
      secureSendApdu(signedScenario);
      bridgeResponses();
    }
    secureSendApdu(signedScenario);
  }

  @Test
  @Order(3)
  @DisplayName(
      "A_25860-01/TIP1-A_4715: Systemprotokoll enthält CARD/SESSION/TIMEOUT Op/Info CardType=EGK, SessionID, Timer=PoPP")
  void systemLog() {
    given()
        .port(admin.port())
        .queryParam("from", started.toString())
        .get("/admin/log")
        .then()
        .statusCode(200)
        .body("findAll { it.topic == 'CARD/SESSION/TIMEOUT' }", hasSize(1))
        .body("find { it.topic == 'CARD/SESSION/TIMEOUT' }.type", equalTo("Op"))
        .body("find { it.topic == 'CARD/SESSION/TIMEOUT' }.severity", equalTo("Info"))
        .body("find { it.topic == 'CARD/SESSION/TIMEOUT' }.parameters.CardType", equalTo("EGK"))
        .body(
            "find { it.topic == 'CARD/SESSION/TIMEOUT' }.parameters.SessionID", equalTo(sessionId))
        .body("find { it.topic == 'CARD/SESSION/TIMEOUT' }.parameters.Timer", equalTo("PoPP"));
    stopCardSessionUnknown();
  }
}

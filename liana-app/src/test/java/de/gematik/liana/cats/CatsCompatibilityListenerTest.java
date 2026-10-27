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
package de.gematik.liana.cats;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.TestPorts;
import de.gematik.liana.admin.AdminServer;
import de.gematik.liana.kern.card.CardList;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * CATS compatibility listener (LIANA-147): with {@code liana.cats.terminals[].port}, an additional
 * own HTTP port as up to 0.6 (Konnektor-QES: 9998), paths without prefix; {@code /cats/KT-01} on
 * the management port remains.
 */
@QuarkusTest
@TestProfile(CatsCompatibilityListenerTest.Profile.class)
class CatsCompatibilityListenerTest {

  public static class Profile implements QuarkusTestProfile {
    @Override
    public Map<String, String> getConfigOverrides() {
      return Map.of("liana.cats.terminals[0].port", String.valueOf(TestPorts.CATS));
    }
  }

  @Inject CatsServer cats;

  @Inject AdminServer admin;

  @Inject CardList cards;

  @AfterEach
  void reset() {
    given().port(admin.port()).post("/admin/reset").then().statusCode(200);
  }

  @Test
  @DisplayName(
      "LIANA-67 / LIANA-147: POST /config/card/insert auf dem eigenen Port zieht wie unter /cats/KT-01")
  void beidePfade() {
    assertEquals(TestPorts.CATS, cats.compatibilityPort("KT-01").orElseThrow());
    given()
        .port(TestPorts.CATS)
        .contentType("application/json")
        .body("{\"slotNumber\":3,\"inserted\":false}")
        .post("/config/card/insert")
        .then()
        .statusCode(200);
    assertTrue(cards.card("KT-01", 3).isEmpty());
    given()
        .port(admin.port())
        .contentType("application/json")
        .body("{\"slotNumber\":2,\"inserted\":false}")
        .post("/cats/KT-01/config/card/insert")
        .then()
        .statusCode(200);
    assertTrue(cards.card("KT-01", 2).isEmpty());
  }
}

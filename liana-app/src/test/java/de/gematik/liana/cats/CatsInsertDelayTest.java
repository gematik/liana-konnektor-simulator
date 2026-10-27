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
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.admin.AdminServer;
import de.gematik.liana.kern.card.CardList;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.specification.RequestSpecification;
import jakarta.inject.Inject;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * {@code liana.cats.terminals[].insert-delay}: CATS confirms {@code POST /config/card/insert}
 * immediately, the card is inserted after the delay, as with the real Konnektor via KT and SICCT
 * (Konnektor-QES KUC_1601_010, LIANA-112.02).
 */
@QuarkusTest
@TestProfile(CatsInsertDelayTest.Delayed.class)
class CatsInsertDelayTest {

  /** Long enough that the requests of a slow CI agent stay well inside it (LIANA-203). */
  static final Duration DELAY = Duration.ofSeconds(2);

  public static class Delayed implements QuarkusTestProfile {
    @Override
    public Map<String, String> getConfigOverrides() {
      return Map.of(
          "liana.cats.terminals[0].terminal",
          "KT-01",
          "liana.cats.terminals[0].insert-delay",
          DELAY.toMillis() + "ms");
    }
  }

  @Inject AdminServer admin;

  @Inject CardList cards;

  private RequestSpecification cats() {
    return given().port(admin.port()).basePath("/cats/KT-01");
  }

  @AfterEach
  void reset() {
    given().port(admin.port()).post("/admin/reset").then().statusCode(200);
  }

  private void loadAndInsert() throws Exception {
    loadAndInsert(3, "support/images/egk-valid.xml");
  }

  private void loadAndInsert(int slot, String image) throws Exception {
    cats()
        .contentType("application/json")
        .body(Files.readAllBytes(Path.of(image)))
        .put("/config/card/slot/" + slot + "/cardImage")
        .then()
        .statusCode(200);
    cats()
        .contentType("application/json")
        .body("{\"slotNumber\":" + slot + ",\"inserted\":true}")
        .post("/config/card/insert")
        .then()
        .statusCode(200);
  }

  @Test
  @DisplayName("insert antwortet sofort, CARD/INSERTED erst nach insert-delay")
  void verzoegert() throws Exception {
    loadAndInsert();
    assertTrue(cards.card("KT-01", 3).isEmpty(), "noch nicht gesteckt");
    long end = System.nanoTime() + 5_000_000_000L;
    while (cards.card("KT-01", 3).isEmpty() && System.nanoTime() < end) {
      Thread.sleep(20);
    }
    assertTrue(cards.card("KT-01", 3).isPresent(), "nach der Frist gesteckt");
  }

  @Test
  @DisplayName(
      "zwei Stecken am selben KT innerhalb der Frist: beide Karten kommen gemeinsam nach dem zweiten "
          + "(KUC_1602_072: gSMC-KT und HBA, ein CARD/INSERTED, dann GetCards)")
  void gemeinsam() throws Exception {
    loadAndInsert(1, "support/images/egk-valid.xml");
    // pending once the request returns: the deadline of the first insert is at most now + DELAY
    long firstDeadline = System.nanoTime() + DELAY.toNanos();
    Thread.sleep(500);
    // the deadline of the second insert is at least now + DELAY, so at least 250 ms after the
    // checkpoint (first deadline + 250 ms); the second request may take up to 1.5 s
    loadAndInsert(3, "support/images/egk-valid.xml");
    long checkpoint = firstDeadline + Duration.ofMillis(250).toNanos();
    assertTrue(System.nanoTime() < firstDeadline, "zweites Stecken innerhalb der Frist des ersten");
    while (System.nanoTime() < checkpoint) {
      Thread.sleep(20);
    }
    assertTrue(cards.card("KT-01", 1).isEmpty(), "das erste wartet auf das zweite");
    long end = System.nanoTime() + 5_000_000_000L;
    while ((cards.card("KT-01", 1).isEmpty() || cards.card("KT-01", 3).isEmpty())
        && System.nanoTime() < end) {
      Thread.sleep(20);
    }
    assertTrue(
        cards.card("KT-01", 1).isPresent() && cards.card("KT-01", 3).isPresent(), "beide gesteckt");
  }

  @Test
  @DisplayName("slots/reset vor Ablauf der Frist verwirft das ausstehende Stecken")
  void resetVerwirft() throws Exception {
    loadAndInsert();
    cats().contentType("application/json").post("/config/card/slots/reset").then().statusCode(200);
    Thread.sleep(DELAY.toMillis() + 300);
    assertTrue(cards.card("KT-01", 3).isEmpty());
  }
}

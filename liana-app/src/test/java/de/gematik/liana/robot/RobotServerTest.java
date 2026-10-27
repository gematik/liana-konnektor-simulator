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
package de.gematik.liana.robot;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.admin.AdminServer;
import de.gematik.liana.kern.card.CardList;
import de.gematik.liana.kern.card.CardType;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.response.ValidatableResponse;
import jakarta.inject.Inject;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Robot interface (LIANA-106) with the requests from {@code AutomationRobotGlueCode} of
 * tiger-ehealth-kt-e2e (Development_1.x): robot terminal 1 is KT-01 (boot: egk-valid in slot 1,
 * smcb-valid in 2, hba-valid in 3), compartments from application.yaml (Berechtigte SC2 HBA,
 * otherwise SMC-B; eGK egk-valid everywhere).
 */
@QuarkusTest
@TestProfile(RobotServerTest.RobotOn.class)
class RobotServerTest {

  /** The robot interface is off without a port; here on a free port. */
  public static class RobotOn implements QuarkusTestProfile {
    @Override
    public Map<String, String> getConfigOverrides() {
      return Map.of("liana.robot.port", "0", "liana.robot.await-pin", "true");
    }
  }

  @Inject RobotServer server;

  @Inject AdminServer admin;

  @Inject CardList cards;

  private final List<String> events = new ArrayList<>();

  @BeforeEach
  void listen() {
    cards.addListener(
        e -> events.add(e.topic().topic() + " " + e.card().ctId() + "/" + e.card().slotNo()));
  }

  @AfterEach
  void reset() {
    given().port(admin.port()).post("/admin/reset").then().statusCode(200);
  }

  /** {@code AutomationRobotGlueCode.performStartAction("robotCommand", command, input)}. */
  private ValidatableResponse robot(String command, String input) {
    return given()
        .port(server.port())
        .header("accept", "application/json")
        .contentType("application/json")
        .body(Map.of("command", command, "input", input))
        .post("/api/robot/robotCommand")
        .then();
  }

  @Test
  @DisplayName(
      "„ROBOT wählt eine Berechtigtenkarte SC2“ und „ROBOT steckt Berechtigtenkarte in Terminal“ (Ingenico: "
          + "IHO, IHP): die Boot-SMC-B geht (CARD/REMOVED), der HBA kommt (CARD/INSERTED); „ROBOT zieht "
          + "Berechtigtenkarte aus Terminal“ (IHO) zieht ihn")
  void berechtigtenkarteSteckenUndZiehen() {
    robot("selTerminal1", "").statusCode(200);
    robot("sendToRemovinator", "SC2").statusCode(200);
    robot("IHO", "").statusCode(200);
    robot("IHP", "").statusCode(200);
    assertEquals(CardType.HBA, cards.card("KT-01", 2).orElseThrow().data().type());
    assertEquals(List.of("CARD/REMOVED KT-01/2", "CARD/INSERTED KT-01/2"), events);

    robot("IHO", "").statusCode(200);
    assertTrue(cards.card("KT-01", 2).isEmpty());
    assertEquals(
        CardType.EGK, cards.card("KT-01", 1).orElseThrow().data().type(), "die eGK bleibt stecken");
  }

  @Test
  @DisplayName(
      "GET_CARDS: „ROBOT wählt eine eGk SC3“, „… Berechtigtenkarte SC3“, „ROBOT steckt beide gewählte "
          + "Karten“ (pressPatientenkarte, pressBerechtigtenkarte) bringt zwei CARD/INSERTED; „ROBOT zieht Karten aus "
          + "dem aktuellen Terminal“ (removeCards) leert Slot 1 und 2")
  void beideKartenSteckenUndZiehen() {
    robot("selTerminal1", "").statusCode(200);
    robot("sendToRemovinatorMaster", "SC3").statusCode(200);
    robot("sendToRemovinator", "SC3").statusCode(200);
    robot("pressPatientenkarte", "").statusCode(200);
    robot("pressBerechtigtenkarte", "").statusCode(200);
    assertEquals(CardType.EGK, cards.card("KT-01", 1).orElseThrow().data().type());
    assertEquals(CardType.SMC_B, cards.card("KT-01", 2).orElseThrow().data().type());
    assertEquals(
        2, events.stream().filter(e -> e.startsWith("CARD/INSERTED")).count(), events.toString());

    robot("removeCards", "").statusCode(200);
    assertTrue(cards.card("KT-01", 1).isEmpty());
    assertTrue(cards.card("KT-01", 2).isEmpty());
    assertEquals(
        CardType.HBA,
        cards.card("KT-01", 3).orElseThrow().data().type(),
        "Slot 3 fasst der Robot nicht an");
  }

  @Test
  @DisplayName(
      "LIANA-68: die PIN-Kommandos der Suite hängen ihre Eingabe an das PIN-Script von Robot-Terminal 1 "
          + "(KT-01, ohne Slot), das PIN-Pad wartet auf sie (Modus await); customPin mit Ziffern, sonst 400; Admin-PIN "
          + "und Virtual Card Kit antworten 501 (decision-12)")
  void pinEingabe() {
    robot("verifyPin", "").statusCode(200);
    robot("enterWrongPin", "").statusCode(200);
    robot("enterPUK", "").statusCode(200);
    robot("enterTransportPin", "").statusCode(200);
    robot("customPin", "4711").statusCode(200);
    robot("enterPinWithStop", "").statusCode(200);
    robot("enterIncompletePin", "").statusCode(200);
    assertEquals(
        List.of("correct", "wrong", "puk", "transport", "digits", "cancel", "incomplete"),
        given()
            .port(admin.port())
            .get("/admin/terminals/KT-01")
            .then()
            .extract()
            .jsonPath()
            .getList("pinScript.outcome"));
    robot("customPin", "12a4").statusCode(400);
    robot("enterAdminPin", "").statusCode(501);
    robot("startSimOnSlot2", "HBA_80276883110000129137_gema5_PUK.xml").statusCode(501);
    robot("R2OFF", "").statusCode(501);
    given()
        .port(server.port())
        .contentType("application/json")
        .body("{}")
        .post("/api/robot/other")
        .then()
        .statusCode(501);
  }

  @Test
  @DisplayName(
      "Unbelegtes Fach und unbekanntes Robot-Terminal liefern 400, Stecken ohne gewählte Karte 409; "
          + "POST /admin/reset vergisst die Auswahl (decision-4)")
  void fehler() {
    robot("sendToRemovinator", "SC9").statusCode(400).body("error", containsString("SC9"));
    robot("selTerminal2", "").statusCode(400);
    robot("sendToRemovinatorEgkT2", "SC1").statusCode(400);
    robot("pressPatientenkarte", "").statusCode(409);

    robot("sendToRemovinatorMaster", "SC1").statusCode(200);
    given().port(admin.port()).post("/admin/reset").then().statusCode(200);
    robot("pressPatientenkarte", "").statusCode(409);
  }
}

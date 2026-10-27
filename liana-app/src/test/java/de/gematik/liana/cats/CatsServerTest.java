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
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.admin.AdminServer;
import de.gematik.liana.kern.card.CardList;
import de.gematik.liana.kern.card.CardType;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.specification.RequestSpecification;
import jakarta.inject.Inject;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * CATS REST interface (LIANA-67) with the requests from {@code CardAction} of tiger-cats-extensions
 * 1.4.0: the CATS terminal of the test profile acts on KT-01 (slots 1–3, boot: egk-valid,
 * smcb-valid, hba-valid), base URL {@code /cats/KT-01} on the management port (LIANA-147).
 */
@QuarkusTest
class CatsServerTest {

  @Inject CatsServer server;

  @Inject AdminServer admin;

  @Inject CardList cards;

  private RequestSpecification cats() {
    return given().port(admin.port()).basePath("/cats/KT-01");
  }

  private RequestSpecification admin() {
    return given().port(admin.port());
  }

  @AfterEach
  void reset() {
    admin().post("/admin/reset").then().statusCode(200);
  }

  /** {@code CardAction.loadAndStartCardByCardImage}: image bytes with content type JSON. */
  private void loadImage(int slot, byte[] image, int status) {
    cats()
        .contentType("application/json")
        .body(image)
        .put("/config/card/slot/" + slot + "/cardImage")
        .then()
        .statusCode(status);
  }

  /** {@code CardAction.changeCardInsertedStatus}. */
  private void insert(int slot, boolean inserted, int status) {
    cats()
        .contentType("application/json")
        .body("{\"slotNumber\":" + slot + ",\"inserted\":" + inserted + "}")
        .post("/config/card/insert")
        .then()
        .statusCode(status);
  }

  @Test
  @DisplayName(
      "„CATS steckt die Karte … in Slot 3“: PUT cardImage legt das Image fest und zieht die alte Karte "
          + "(CARD/REMOVED), erst POST insert steckt das Image (CARD/INSERTED, neues CardHandle); inserted false zieht")
  void imageSteckenUndZiehen() throws Exception {
    String hba = cards.card("KT-01", 3).orElseThrow().cardHandle();
    List<String> events = new ArrayList<>();
    cards.addListener(
        e -> events.add(e.topic().topic() + " " + e.card().ctId() + "/" + e.card().slotNo()));

    loadImage(3, Files.readAllBytes(Path.of("support/images/egk-valid.xml")), 200);
    assertTrue(cards.card("KT-01", 3).isEmpty(), "CARD/INSERTED erst nach dem Stecken (LIANA-91)");
    assertEquals(List.of("CARD/REMOVED KT-01/3"), events);
    insert(3, true, 200);

    var egk = cards.card("KT-01", 3).orElseThrow();
    assertEquals(CardType.EGK, egk.data().type());
    assertNotEquals(hba, egk.cardHandle());
    assertTrue(cards.card(hba).isEmpty());
    admin()
        .get("/admin/terminals/KT-01")
        .then()
        .body("slots[2].path", containsString("liana-cats-"));

    insert(3, false, 200);
    assertTrue(cards.card("KT-01", 3).isEmpty());
    assertEquals(
        List.of("CARD/REMOVED KT-01/3", "CARD/INSERTED KT-01/3", "CARD/REMOVED KT-01/3"), events);

    insert(3, true, 200);
    assertEquals(
        CardType.EGK,
        cards.card("KT-01", 3).orElseThrow().data().type(),
        "das geladene Image bleibt");
  }

  @Test
  @DisplayName(
      "„CATS startet die Karte aus Slot n mit der Konfiguration …“: cardConfigPath auf eine CATS-"
          + "Kartenkonfiguration (cardImageFile) oder direkt auf ein Image")
  void kartenkonfiguration(@TempDir Path dir) throws Exception {
    Path config = dir.resolve("configuration_SMC_B.xml");
    Files.writeString(
        config,
        """
                <?xml version="1.0" encoding="UTF-8"?>
                <configuration><general>
                <attribute id="cardImageFile">%s</attribute>
                <attribute id="maxNoChannels">4</attribute>
                </general></configuration>"""
            .formatted(Path.of("support/images/smcb-valid.xml").toAbsolutePath()));
    cats()
        .contentType("application/json")
        .body("{\"cardConfigPath\":\"" + config + "\"}")
        .put("/config/card/slot/1")
        .then()
        .statusCode(200);
    insert(1, true, 200);
    assertEquals(CardType.SMC_B, cards.card("KT-01", 1).orElseThrow().data().type());

    cats()
        .contentType("application/json")
        .body(
            "{\"cardConfigPath\":\""
                + Path.of("support/images/hba-valid.xml").toAbsolutePath()
                + "\"}")
        .put("/config/card/slot/1")
        .then()
        .statusCode(200);
    assertEquals(
        CardType.HBA,
        cards.card("KT-01", 1).orElseThrow().data().type(),
        "neues Image für einen belegten Slot wechselt die Karte");
  }

  @Test
  @DisplayName(
      "LIANA-98: cardConfigPath, der keine Datei ist, wählt per Dateiname oder ICCSN aus liana.card-images")
  void kartePerNameOderIccsn() {
    cats()
        .contentType("application/json")
        .body("{\"cardConfigPath\":\"80276883110000168650\"}")
        .put("/config/card/slot/1")
        .then()
        .statusCode(200);
    insert(1, true, 200);
    assertEquals(CardType.SMC_B, cards.card("KT-01", 1).orElseThrow().data().type());
    cats()
        .contentType("application/json")
        .body("{\"cardConfigPath\":\"hba-valid\"}")
        .put("/config/card/slot/1")
        .then()
        .statusCode(200);
    assertEquals(CardType.HBA, cards.card("KT-01", 1).orElseThrow().data().type());
  }

  @Test
  @DisplayName(
      "@RemoveAllCardsAfterTest: POST /config/card/slots/reset zieht alle Karten des KT und vergisst die "
          + "Images; POST /admin/reset stellt den YAML-Stand her (decision-4)")
  void slotsReset() throws Exception {
    loadImage(2, Files.readAllBytes(Path.of("support/images/egk-valid.xml")), 200);
    cats().post("/config/card/slots/reset").then().statusCode(200);
    for (int slot = 1; slot <= 3; slot++) {
      assertTrue(cards.card("KT-01", slot).isEmpty(), "Slot " + slot);
    }
    insert(2, true, 409);

    admin().post("/admin/reset").then().statusCode(200);
    admin()
        .get("/admin/terminals/KT-01")
        .then()
        .body("slots[0].image", equalTo("egk-valid"))
        .body("slots[1].image", equalTo("smcb-valid"))
        .body("slots[2].image", equalTo("hba-valid"));
  }

  @Test
  @DisplayName(
      "Ungültiges Image → 400 (kein XML, kein card-Element, ohne ATR, leer), unbekannte Konfiguration → 400, "
          + "Stecken ohne Image → 409, Slot außerhalb → 404; der Slot bleibt unverändert")
  void fehler() {
    String hba = cards.card("KT-01", 3).orElseThrow().cardHandle();
    loadImage(3, "kein xml".getBytes(), 400);
    loadImage(3, "<cardImage><hpc/></cardImage>".getBytes(), 400);
    loadImage(3, "<card version=\"3\"><objectSystem/></card>".getBytes(), 400);
    loadImage(3, new byte[0], 400);
    cats()
        .contentType("application/json")
        .body("{\"cardConfigPath\":\"/gibt/es/nicht.xml\"}")
        .put("/config/card/slot/3")
        .then()
        .statusCode(400)
        .body("error", containsString("nicht gefunden"));
    insert(3, true, 409);
    loadImage(4, "<card/>".getBytes(), 404);
    insert(4, true, 404);
    cats()
        .contentType("application/json")
        .body("{\"slot\":3}")
        .post("/config/card/insert")
        .then()
        .statusCode(400);
    assertEquals(hba, cards.card("KT-01", 3).orElseThrow().cardHandle());
  }

  @Test
  @DisplayName(
      "Response Delay: GET /cardsim/slot/2/delay/3000 setzt die Störung delay (LIANA-41), 0 hebt sie auf")
  void delay() {
    cats().get("/cardsim/slot/2/delay/3000").then().statusCode(200);
    admin()
        .get("/admin/terminals/KT-01")
        .then()
        .body("slots[1].fault.type", equalTo("delay"))
        .body("slots[1].fault.delayMs", equalTo(3000));
    cats().get("/cardsim/slot/2/delay/0").then().statusCode(200);
    admin().get("/admin/terminals/KT-01").then().body("slots[1].fault", nullValue());
  }

  @Test
  @DisplayName(
      "ComputeSignature-Response: manipulateSignatureResponse setzt die Störung response für PSO COMPUTE "
          + "DIGITAL SIGNATURE (commandPrefix 002A9E9A); ohne responseReplacement → 400")
  void signaturAntwort() {
    String replacement =
        "5BF94E873DB24297AECB972564517B6606FBCB63D133652AEB9BD88F551E9A8CA3FBE1B8B4FAF7FE390BBA9C"
            + "B92E10EC0BF33C14F6BC96B5E2F649D26DE16F2D9000";
    cats()
        .contentType("application/json")
        .body("{\"responseReplacement\":\"" + replacement + "\"}")
        .post("/cardsim/slot/2/manipulateSignatureResponse")
        .then()
        .statusCode(200);
    admin()
        .get("/admin/terminals/KT-01")
        .then()
        .body("slots[1].fault.type", equalTo("response"))
        .body("slots[1].fault.response", equalTo(replacement))
        .body("slots[1].fault.commandPrefix", equalTo("002A9E9A"));
    cats()
        .contentType("application/json")
        .body("{}")
        .post("/cardsim/slot/2/manipulateSignatureResponse")
        .then()
        .statusCode(400);
  }

  @Test
  @DisplayName(
      "decision-12: nicht umgesetzte CATS-Endpunkte (userDefinedStatusWord, PIN, GetPinStatus) → 501 mit Pfad")
  void nichtUmgesetzt() {
    cats()
        .contentType("application/json")
        .body("{\"command\":\"x\",\"statusWord\":\"6982\"}")
        .post("/sicct/userDefinedStatusWord")
        .then()
        .statusCode(501)
        .body("error", containsString("POST /cats/KT-01/sicct/userDefinedStatusWord"));
    cats()
        .contentType("application/json")
        .body("{\"responseReplacement\":\"9000\"}")
        .post("/cardsim/slot/2/manipulateGetPinStatusResponse")
        .then()
        .statusCode(501);
    cats()
        .get("/config/pin/autoPin")
        .then()
        .statusCode(501)
        .body("error", containsString("/config/pin/autoPin"));
  }

  @Test
  @DisplayName("LIANA-147: CATS über HTTPS auf dem Management-Port wie über HTTP (decision-017)")
  void https() {
    given()
        .relaxedHTTPSValidation()
        .baseUri("https://localhost")
        .port(admin.port())
        .basePath("/cats/KT-01")
        .contentType("application/json")
        .body("{\"slotNumber\":3,\"inserted\":false}")
        .post("/config/card/insert")
        .then()
        .statusCode(200);
    assertTrue(cards.card("KT-01", 3).isEmpty());
  }

  @Test
  @DisplayName(
      "LIANA-147: unbekanntes CATS-Terminal unter /cats → 404 mit den konfigurierten, nicht 501")
  void unbekanntesTerminal() {
    admin()
        .contentType("application/json")
        .body("{\"slotNumber\":1,\"inserted\":false}")
        .post("/cats/KT-99/config/card/insert")
        .then()
        .statusCode(404)
        .body("error", containsString("[KT-01]"));
    admin().get("/cats").then().statusCode(404);
  }

  @Test
  @DisplayName("LIANA-147: ohne liana.cats.terminals[].port kein eigener Listener (9998 zu)")
  void keinKompatibilitaetsListener() {
    assertTrue(server.compatibilityPort("KT-01").isEmpty());
  }
}

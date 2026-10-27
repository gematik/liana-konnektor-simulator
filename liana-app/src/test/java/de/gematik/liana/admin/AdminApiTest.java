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
package de.gematik.liana.admin;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.kern.card.CardList;
import de.gematik.liana.kern.terminal.TerminalRegistry;
import de.gematik.liana.kern.vendor.Deviation;
import de.gematik.liana.kern.vendor.PeerDeviations;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.specification.RequestSpecification;
import jakarta.inject.Inject;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Admin API (decision-4) against the YAML state from application.yaml: KT-01 with egk-valid in slot
 * 1, KT-02 empty.
 */
@QuarkusTest
class AdminApiTest {

  @Inject AdminServer server;

  @Inject TerminalRegistry registry;

  @Inject CardList cards;

  @Inject PeerDeviations deviations;

  private RequestSpecification admin() {
    return given().port(server.port());
  }

  @AfterEach
  void reset() {
    admin().post("/admin/reset").then().statusCode(200);
  }

  @Test
  @DisplayName(
      "GET /admin/ready: nach dem Start bereit (LIANA-107), auf der Konnektor-Schnittstelle unbekannt")
  void ready() {
    admin()
        .get("/admin/ready")
        .then()
        .statusCode(200)
        .contentType("application/json")
        .body("ready", equalTo(true));
    given().get("/admin/ready").then().statusCode(404);
  }

  @Test
  @DisplayName("Admin-API hat einen eigenen Port, die Konnektor-Schnittstelle kennt /admin nicht")
  void eigenerPort() {
    admin()
        .get("/admin/info")
        .then()
        .statusCode(200)
        .contentType("application/json")
        .body("product", equalTo("LIANA"))
        .body("env", equalTo("ru"))
        .body("vendor", equalTo("neutral"))
        .body("terminalMode", equalTo("fake"))
        .body("adminPort", equalTo(server.port()))
        .body("adminPort", not(equalTo(8081)));
    given().get("/admin/info").then().statusCode(404);
  }

  @Test
  @DisplayName(
      "decision-017: HTTP und HTTPS auf dem Management-Port liefern dasselbe (ID.AK.AUT, ohne Client-Auth)")
  void httpUndHttps() {
    String http = admin().get("/admin/info").then().statusCode(200).extract().asString();
    String https =
        given()
            .relaxedHTTPSValidation()
            .baseUri("https://localhost")
            .port(server.port())
            .get("/admin/info")
            .then()
            .statusCode(200)
            .extract()
            .asString();
    assertEquals(http, https);
  }

  @Test
  @DisplayName("GET terminals, terminals/{id}, infomodel und tls liefern den Boot-Stand als JSON")
  void lesendeEndpunkte() {
    admin()
        .get("/admin/terminals")
        .then()
        .statusCode(200)
        .body("id", hasItems("KT-01", "KT-02"))
        .body("find { it.id == 'KT-01' }.slots[0].image", equalTo("egk-valid"))
        .body("find { it.id == 'KT-01' }.slots.size()", equalTo(3));
    admin()
        .get("/admin/terminals/KT-02")
        .then()
        .statusCode(200)
        .body("slots.size()", equalTo(2))
        .body("slots[0].image", nullValue());
    admin()
        .get("/admin/infomodel")
        .then()
        .statusCode(200)
        .body("mandants", hasItems("M1"))
        .body("workplaces[0].id", equalTo("WP1"))
        .body("workplaces[0].terminals", hasItems("KT-01", "KT-02"));
    admin()
        .get("/admin/tls")
        .then()
        .statusCode(200)
        .body("tlsMandatory", equalTo(false))
        .body("clientAuthMandatory", equalTo(false))
        .body("serverTls", equalTo(true))
        .body("certificate", containsString("ID.AK.AUT p256"))
        .body(
            "fingerprint",
            equalTo(
                "5E:2B:4B:3E:80:5E:62:13:8E:37:3B:A7:80:70:DF:8E:93:41:23:29:27:D2:C1:67:B7:BA:8C:D5:5C:2E:4D:50"));
  }

  @Test
  @DisplayName(
      "PUT steckt egk-valid in KT-02/1, das Terminal-Register sieht die Karte, reset stellt den YAML-Stand her")
  void steckenUndReset() {
    var kt02 = registry.terminal("KT-02").orElseThrow();
    assertFalse(kt02.cardPresent(1));

    admin()
        .contentType("application/json")
        .body("{\"image\":\"egk-valid\"}")
        .put("/admin/terminals/KT-02/slots/1")
        .then()
        .statusCode(200)
        .body("slots[0].image", equalTo("egk-valid"));
    assertTrue(kt02.cardPresent(1));

    admin()
        .delete("/admin/terminals/KT-01/slots/1")
        .then()
        .statusCode(200)
        .body("slots[0].image", nullValue());

    admin().post("/admin/reset").then().statusCode(200);
    assertFalse(kt02.cardPresent(1));
    assertTrue(registry.terminal("KT-01").orElseThrow().cardPresent(1));
  }

  @Test
  @DisplayName(
      "LIANA-121 TUC_KON_001: GET terminals zeigt je Slot CARD.TYPE aus CM_CARD_LIST, bei UNKNOWN mit Grund "
          + "(hier io-error beim Stecken)")
  void kartentypUndGrund() {
    admin()
        .get("/admin/terminals/KT-01")
        .then()
        .statusCode(200)
        .body("slots[0].cardType", equalTo("EGK"))
        .body("slots[0].unknownReason", nullValue())
        .body("slots[1].cardType", equalTo("SMC-B"));
    admin()
        .contentType("application/json")
        .body("{\"type\":\"io-error\"}")
        .put("/admin/terminals/KT-02/slots/1/fault")
        .then()
        .statusCode(200);
    admin()
        .contentType("application/json")
        .body("{\"image\":\"egk-valid\"}")
        .put("/admin/terminals/KT-02/slots/1")
        .then()
        .statusCode(200);
    admin()
        .get("/admin/terminals/KT-02")
        .then()
        .statusCode(200)
        .body("slots[0].image", equalTo("egk-valid"))
        .body("slots[0].cardType", equalTo("UNKNOWN"))
        .body("slots[0].unknownReason", equalTo("KT-02/1: Störung io-error"))
        .body("slots[1].cardType", nullValue());
    admin().post("/admin/reset").then().statusCode(200);
  }

  @Test
  @DisplayName("LIANA-98: PUT steckt per ICCSN und per Dateiname mit .xml aus liana.card-images")
  void steckenPerIccsn() {
    admin()
        .contentType("application/json")
        .body("{\"image\":\"80276883110000168650\"}")
        .put("/admin/terminals/KT-02/slots/1")
        .then()
        .statusCode(200)
        .body("slots[0].image", equalTo("smcb-valid"));
    admin()
        .contentType("application/json")
        .body("{\"image\":\"egk-valid.xml\"}")
        .put("/admin/terminals/KT-02/slots/2")
        .then()
        .statusCode(200)
        .body("slots[1].image", equalTo("egk-valid"));
    admin().post("/admin/reset").then().statusCode(200);
  }

  @Test
  @DisplayName(
      "TUC_KON_025: egk-valid, smcb-valid und hba-valid aus der YAML (Testprofil) haben nach dem Start ein "
          + "CardHandle, PUT, DELETE und reset vergeben neue")
  void cardHandles() {
    String boot = cards.card("KT-01", 1).orElseThrow().cardHandle();
    assertEquals(3, cards.cards().size());
    List<String> events = new ArrayList<>();
    cards.addListener(
        e -> events.add(e.topic().topic() + " " + e.card().ctId() + "/" + e.card().slotNo()));

    admin()
        .contentType("application/json")
        .body("{\"image\":\"egk-valid\"}")
        .put("/admin/terminals/KT-02/slots/1")
        .then()
        .statusCode(200);
    String kt02 = cards.card("KT-02", 1).orElseThrow().cardHandle();
    admin().delete("/admin/terminals/KT-02/slots/1").then().statusCode(200);
    assertTrue(cards.card(kt02).isEmpty());

    admin().post("/admin/reset").then().statusCode(200);
    String nachReset = cards.card("KT-01", 1).orElseThrow().cardHandle();
    assertNotEquals(boot, nachReset);
    assertTrue(cards.card(boot).isEmpty());
    assertEquals(3, cards.cards().size());
    assertEquals(
        List.of(
            "CARD/INSERTED KT-02/1",
            "CARD/REMOVED KT-02/1",
            "CARD/REMOVED KT-01/1",
            "CARD/REMOVED KT-01/2",
            "CARD/REMOVED KT-01/3",
            "CARD/INSERTED KT-01/1",
            "CARD/INSERTED KT-01/2",
            "CARD/INSERTED KT-01/3"),
        events);
  }

  @Test
  @DisplayName(
      "Unbekanntes Image → 404 mit Suchpfad, unbekannter KT oder Slot → 404, fehlender Body → 400")
  void fehler() {
    admin()
        .contentType("application/json")
        .body("{\"image\":\"egk-expired\"}")
        .put("/admin/terminals/KT-02/slots/1")
        .then()
        .statusCode(404)
        .body(
            "error",
            containsString(
                "Image 'egk-expired' nicht gefunden in [./support/images, "
                    + "./support/images/gsmc-kt, ./support/images/g20, ./support/images/gsmc-k, ./support/images/kvk, "
                    + "/opt/liana/images, /opt/liana/images/gsmc-kt, /opt/liana/images/g20, /opt/liana/images/gsmc-k, "
                    + "/opt/liana/images/kvk]"));
    admin()
        .get("/admin/terminals/KT-99")
        .then()
        .statusCode(404)
        .body("error", containsString("unbekanntes KT 'KT-99'"));
    admin()
        .contentType("application/json")
        .body("{\"image\":\"egk-valid\"}")
        .put("/admin/terminals/KT-02/slots/3")
        .then()
        .statusCode(404)
        .body("error", containsString("Slot 3 außerhalb 1..2"));
    admin().delete("/admin/terminals/KT-02/slots/x").then().statusCode(404);
    admin().put("/admin/terminals/KT-02/slots/1").then().statusCode(400);
  }

  @Test
  @DisplayName(
      "LIANA-41: PUT setzt die Störung eines Slots, GET terminals zeigt sie, DELETE und reset löschen sie; "
          + "ungültige Störung → 400")
  void stoerung() {
    admin()
        .contentType("application/json")
        .body(
            "{\"type\":\"status-word\",\"statusWord\":\"6a82\",\"commandPrefix\":\"00b0\",\"count\":2}")
        .put("/admin/terminals/KT-01/slots/1/fault")
        .then()
        .statusCode(200)
        .body("slots[0].image", equalTo("egk-valid"))
        .body("slots[0].fault.type", equalTo("status-word"))
        .body("slots[0].fault.statusWord", equalTo("6A82"))
        .body("slots[0].fault.commandPrefix", equalTo("00B0"))
        .body("slots[0].fault.count", equalTo(2))
        .body("slots[1].fault", nullValue());
    admin()
        .delete("/admin/terminals/KT-01/slots/1/fault")
        .then()
        .statusCode(200)
        .body("slots[0].fault", nullValue());

    admin()
        .contentType("application/json")
        .body("{\"type\":\"delay\",\"delayMs\":1500}")
        .put("/admin/terminals/KT-02/slots/2/fault")
        .then()
        .statusCode(200)
        .body("slots[1].fault.type", equalTo("delay"))
        .body("slots[1].fault.delayMs", equalTo(1500));
    admin()
        .contentType("application/json")
        .body("{\"type\":\"io-error\"}")
        .put("/admin/terminals/KT-01/slots/2/fault")
        .then()
        .statusCode(200)
        .body("slots[1].fault.type", equalTo("io-error"));
    admin()
        .post("/admin/reset")
        .then()
        .statusCode(200)
        .body("find { it.id == 'KT-01' }.slots[1].fault", nullValue())
        .body("find { it.id == 'KT-02' }.slots[1].fault", nullValue());

    admin()
        .contentType("application/json")
        .body("{\"type\":\"status-word\"}")
        .put("/admin/terminals/KT-01/slots/1/fault")
        .then()
        .statusCode(400)
        .body("error", containsString("statusWord"));
    admin()
        .contentType("application/json")
        .body("{\"type\":\"kaputt\"}")
        .put("/admin/terminals/KT-01/slots/1/fault")
        .then()
        .statusCode(400)
        .body("error", containsString("status-word, response, io-error oder delay"));
    admin()
        .contentType("application/json")
        .body("{\"type\":\"io-error\"}")
        .put("/admin/terminals/KT-01/slots/4/fault")
        .then()
        .statusCode(404);
  }

  @Test
  @DisplayName(
      "decision-10/decision-4: PUT /admin/vendor schaltet das Herstellerprofil flüchtig um, reset stellt den YAML-Stand her")
  void vendor() {
    admin()
        .get("/admin/vendor")
        .then()
        .statusCode(200)
        .body("vendor", equalTo("neutral"))
        .body("boot", equalTo("neutral"));
    admin()
        .contentType("application/json")
        .body("{\"vendor\":\"ehex\"}")
        .put("/admin/vendor")
        .then()
        .statusCode(200)
        .body("vendor", equalTo("EHEX"))
        .body("boot", equalTo("neutral"));
    admin().get("/admin/info").then().statusCode(200).body("vendor", equalTo("EHEX"));
    admin()
        .contentType("application/json")
        .body("{\"vendor\":\"ACME\"}")
        .put("/admin/vendor")
        .then()
        .statusCode(400)
        .body("error", containsString("erlaubt: neutral, KOCO, RISE, SECUNET, EHEX, CGM"));
    admin().get("/admin/vendor").then().body("vendor", equalTo("EHEX"));
    admin().post("/admin/reset").then().statusCode(200);
    admin().get("/admin/vendor").then().body("vendor", equalTo("neutral"));
  }

  @Test
  @DisplayName(
      "LIANA-126/decision-4: PUT /admin/vendor schaltet strict flüchtig um, Hersteller bleibt; reset stellt liana.strict her")
  void strict() {
    admin()
        .get("/admin/vendor")
        .then()
        .statusCode(200)
        .body("strict", equalTo(false))
        .body("strictBoot", equalTo(false));
    admin()
        .contentType("application/json")
        .body("{\"strict\":true}")
        .put("/admin/vendor")
        .then()
        .statusCode(200)
        .body("vendor", equalTo("neutral"))
        .body("strict", equalTo(true))
        .body("strictBoot", equalTo(false));
    admin().get("/admin/info").then().statusCode(200).body("strict", equalTo(true));
    admin()
        .contentType("application/json")
        .body("{}")
        .put("/admin/vendor")
        .then()
        .statusCode(400)
        .body("error", containsString("vendor oder strict erwartet"));
    admin()
        .contentType("application/json")
        .body("{\"vendor\":\"ACME\",\"strict\":false}")
        .put("/admin/vendor")
        .then()
        .statusCode(400);
    admin().get("/admin/vendor").then().body("strict", equalTo(true));
    admin().post("/admin/reset").then().statusCode(200);
    admin().get("/admin/vendor").then().body("strict", equalTo(false));
  }

  @Test
  @DisplayName(
      "LIANA-126: tolerierte Abweichung der Gegenstelle steht in GET /admin/log als LIANA/DEVIATION (Op, Warning), mit strict als Error")
  void deviationInLog() {
    admin().post("/admin/reset").then().statusCode(200);
    deviations.tolerate(Deviation.KARTOS_MODIFY_VERIFICATION_DATA, "KT-03", java.util.Map.of());
    admin()
        .contentType("application/json")
        .body("{\"strict\":true}")
        .put("/admin/vendor")
        .then()
        .statusCode(200);
    deviations.tolerate(Deviation.KARTOS_MODIFY_VERIFICATION_DATA, "KT-03", java.util.Map.of());
    admin()
        .get("/admin/log")
        .then()
        .statusCode(200)
        .body(
            "findAll { it.topic == 'LIANA/DEVIATION' }.severity",
            equalTo(List.of("Warning", "Error")))
        .body("find { it.topic == 'LIANA/DEVIATION' }.type", equalTo("Op"))
        .body("find { it.topic == 'LIANA/DEVIATION' }.parameters.Peer", equalTo("KT-03"))
        .body(
            "find { it.topic == 'LIANA/DEVIATION' }.parameters.Spec",
            equalTo("SICCT 1.2.3 §5.20 MODIFY VERIFICATION DATA"));
    admin().post("/admin/reset").then().statusCode(200);
  }

  @Test
  @DisplayName(
      "TIP1-A_4715: GET /admin/log liefert CARD/INSERTED und CARD/REMOVED ohne Personenbezug (TIP1-A_4710-02), Zeitfilter, reset leert")
  void systemLog() {
    String before = java.time.Instant.now().minusMillis(1).toString();
    admin()
        .contentType("application/json")
        .body("{\"image\":\"egk-valid\"}")
        .put("/admin/terminals/KT-02/slots/1")
        .then()
        .statusCode(200);
    admin().delete("/admin/terminals/KT-02/slots/1").then().statusCode(200);
    admin()
        .queryParam("from", before)
        .get("/admin/log")
        .then()
        .statusCode(200)
        .body("topic", hasItems("CARD/INSERTED", "CARD/REMOVED"))
        .body(
            "find { it.topic == 'CARD/INSERTED' && it.parameters.CtID == 'KT-02' }.type",
            equalTo("Op"))
        .body(
            "find { it.topic == 'CARD/INSERTED' && it.parameters.CtID == 'KT-02' }.severity",
            equalTo("Info"))
        .body(
            "find { it.topic == 'CARD/INSERTED' && it.parameters.CtID == 'KT-02' }.parameters.CardType",
            equalTo("EGK"))
        .body(
            "find { it.topic == 'CARD/INSERTED' && it.parameters.CtID == 'KT-02' }.parameters.SlotID",
            equalTo("1"))
        .body("find { it.topic == 'CARD/INSERTED' }.parameters.ICCSN", nullValue())
        .body("find { it.topic == 'CARD/INSERTED' }.parameters.KVNR", nullValue())
        .body("find { it.topic == 'CARD/INSERTED' }.parameters.CardHolderName", nullValue());
    admin()
        .queryParam("to", "2000-01-01T00:00:00Z")
        .get("/admin/log")
        .then()
        .statusCode(200)
        .body("size()", equalTo(0));
    admin()
        .queryParam("from", "gestern")
        .get("/admin/log")
        .then()
        .statusCode(400)
        .body("error", containsString("ISO-8601"));
    admin().post("/admin/reset").then().statusCode(200);
    admin().get("/admin/log").then().statusCode(200).body("size()", equalTo(0));
  }
}

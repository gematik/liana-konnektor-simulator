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
package de.gematik.liana.soap;

import static de.gematik.liana.soap.EventServiceTest.bodyElement;
import static de.gematik.liana.soap.EventServiceTest.serialize;
import static de.gematik.liana.soap.EventServiceTest.xpath;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import de.gematik.liana.admin.AdminServer;
import de.gematik.liana.kern.card.CardList;
import de.gematik.liana.robot.RobotServer;
import de.gematik.liana.sds.XsdValidator;
import de.gematik.liana.wiring.RecordedCardEngine;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.response.ValidatableResponse;
import jakarta.inject.Inject;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Element;

/**
 * LIANA-68: PIN bad cases at the PIN pad of the fake KT against cards in kartos (the card keeps the
 * retry counters and the transport PIN). KT-01 is robot terminal 1 and, with {@code await-pin},
 * waits for every PIN entry (mode await); each VerifyPin gets it from the PIN script of the Admin
 * API or from the robot as in tiger-ehealth-kt-e2e. YAML state: smcb-valid in KT-01/2, after each
 * test {@code POST /admin/reset}.
 */
@QuarkusTest
@TestProfile(PinPadKartosIT.KartosCards.class)
class PinPadKartosIT {

  private static final String NS = "http://ws.gematik.de/conn/CardService/v8.2";
  private static final String SCHEMA = "conn/CardService_v8_2_1.xsd";

  /** Cards in kartos instead of the recording, robot interface on. */
  public static class KartosCards implements QuarkusTestProfile {
    @Override
    public Map<String, String> getConfigOverrides() {
      return Map.of(
          RecordedCardEngine.KARTOS,
          "kartos",
          "liana.robot.port",
          "0",
          "liana.robot.await-pin",
          "true");
    }
  }

  @Inject AdminServer admin;

  @Inject RobotServer robot;

  @Inject CardList cards;

  @TempDir Path images;

  @AfterEach
  void reset() {
    given().port(admin.port()).post("/admin/reset").then().statusCode(200);
  }

  private String smcb() {
    return cards.card("KT-01", 2).orElseThrow().cardHandle();
  }

  private static ValidatableResponse post(String operation, String cardHandle) {
    String body =
        """
                <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body>\
                <ns2:%1$s xmlns:ns2="%2$s" xmlns:ns3="http://ws.gematik.de/conn/ConnectorCommon/v5.0" \
                xmlns:ns6="http://ws.gematik.de/conn/ConnectorContext/v2.0">\
                <ns6:Context><ns3:MandantId>M1</ns3:MandantId><ns3:ClientSystemId>CS1</ns3:ClientSystemId>\
                <ns3:WorkplaceId>WP1</ns3:WorkplaceId></ns6:Context><ns3:CardHandle>%3$s</ns3:CardHandle>\
                <ns4:PinTyp xmlns:ns4="http://ws.gematik.de/conn/CardServiceCommon/v2.0">PIN.SMC</ns4:PinTyp>\
                </ns2:%1$s></SOAP-ENV:Body></SOAP-ENV:Envelope>"""
            .formatted(operation, NS, cardHandle);
    return given()
        .contentType("text/xml; charset=utf-8")
        .header("SOAPAction", "\"" + NS + "#" + operation + "\"")
        .body(body)
        .post("/ws/CardService")
        .then();
  }

  /**
   * VerifyPin with status OK, response against the schema: PinResult and LeftTries (empty if
   * absent).
   */
  private static String verifyPin(String cardHandle) throws Exception {
    Element response =
        bodyElement(post("VerifyPin", cardHandle).statusCode(200).extract().asString());
    XsdValidator.validate(SCHEMA, serialize(response));
    String leftTries = xpath(response, "//*[local-name()='LeftTries']");
    return xpath(response, "//*[local-name()='PinResult']")
        + (leftTries.isEmpty() ? "" : " " + leftTries);
  }

  /** VerifyPin as SOAP fault: code and severity from the GERROR. */
  private static String verifyPinFault(String cardHandle) throws Exception {
    Element fault = bodyElement(post("VerifyPin", cardHandle).statusCode(500).extract().asString());
    return xpath(fault, "//*[local-name()='Code']")
        + " "
        + xpath(fault, "//*[local-name()='Severity']");
  }

  private static String pinStatus(String cardHandle) throws Exception {
    Element response =
        bodyElement(post("GetPinStatus", cardHandle).statusCode(200).extract().asString());
    XsdValidator.validate(SCHEMA, serialize(response));
    String leftTries = xpath(response, "//*[local-name()='LeftTries']");
    return xpath(response, "//*[local-name()='PinStatus']")
        + (leftTries.isEmpty() ? "" : " " + leftTries);
  }

  private void script(String json) {
    given()
        .port(admin.port())
        .contentType("application/json")
        .body(json)
        .post("/admin/terminals/KT-01/pin-script")
        .then()
        .statusCode(200);
  }

  private void robot(String command) {
    given()
        .port(robot.port())
        .contentType("application/json")
        .body("{\"command\":\"" + command + "\",\"input\":\"\"}")
        .post("/api/robot/robotCommand")
        .then()
        .statusCode(200);
  }

  /**
   * VerifyPin in the background, like the suite ({@code new Thread(…)}); returns when the PIN pad
   * is waiting.
   */
  private CompletableFuture<ValidatableResponse> verifyPinWaiting(String cardHandle)
      throws InterruptedException {
    CompletableFuture<ValidatableResponse> verify =
        CompletableFuture.supplyAsync(() -> post("VerifyPin", cardHandle));
    long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
    while (given()
            .port(admin.port())
            .get("/admin/terminals/KT-01")
            .then()
            .extract()
            .jsonPath()
            .getString("display")
        == null) {
      if (System.nanoTime() > deadline) {
        throw new AssertionError("PIN-Pad von KT-01 wartet nicht auf eine Eingabe");
      }
      Thread.sleep(20);
    }
    return verify;
  }

  @Test
  @DisplayName(
      "TIP1-A_4567 / TUC_KON_012 7c: falsche PIN aus dem PIN-Script → REJECTED mit dem LeftTries der Karte "
          + "(2, 1), nach der letzten Fehleingabe NOWBLOCKED, die richtige danach WASBLOCKED (TAB_KON_738 Schritt 5); "
          + "GetPinStatus VERIFIABLE 2, dann BLOCKED 0; decision-4: POST /admin/reset steckt die Karte frisch aus dem "
          + "Image, VERIFIABLE 3")
  void falschePin() throws Exception {
    String smcb = smcb();
    script(
        """
                [{"outcome":"wrong","slotNo":2},{"outcome":"wrong","slotNo":2},{"outcome":"wrong"},\
                {"outcome":"correct","slotNo":2}]""");
    assertEquals(
        4,
        given()
            .port(admin.port())
            .get("/admin/terminals/KT-01")
            .then()
            .extract()
            .jsonPath()
            .getList("pinScript")
            .size());
    assertEquals("REJECTED 2", verifyPin(smcb));
    assertEquals("VERIFIABLE 2", pinStatus(smcb));
    assertEquals("REJECTED 1", verifyPin(smcb));
    assertEquals("NOWBLOCKED", verifyPin(smcb));
    assertEquals("BLOCKED 0", pinStatus(smcb));
    assertEquals("WASBLOCKED", verifyPin(smcb));

    reset();
    String fresh = smcb();
    assertNotEquals(smcb, fresh);
    assertEquals("VERIFIABLE 3", pinStatus(fresh));
    script("[{\"outcome\":\"correct\"}]");
    assertEquals("OK", verifyPin(fresh));
  }

  @Test
  @DisplayName(
      "TUC_KON_012 (7), TAB_KON_089: keine Eingabe in der Zeit → 4043 (Warning), Abbruchtaste → 4049 (Error)")
  void timeoutUndAbbruch() throws Exception {
    script("[{\"outcome\":\"timeout\"},{\"outcome\":\"cancel\"}]");
    assertEquals("4043 Warning", verifyPinFault(smcb()));
    assertEquals("4049 Error", verifyPinFault(smcb()));
    script("[{\"outcome\":\"digits\",\"pin\":\"123456\"}]");
    assertEquals("OK", verifyPin(smcb()), "digits mit der PIN der Testkarte");
  }

  @Test
  @DisplayName(
      "TUC_KON_022 und TAB_KON_738 Schritt 5: SMC-B mit Transport-PIN → GetPinStatus TRANSPORT_PIN, VerifyPin "
          + "(Transport-PIN eingegeben) → PinResult TRANSPORT_PIN (TUC_KON_012 4065 abgefangen); mit Leer-PIN → EMPTY_PIN, "
          + "VerifyPin → TRANSPORT_PIN")
  void transportUndLeerPin() throws Exception {
    for (var c : Map.of("transportPIN", "TRANSPORT_PIN", "leerPIN", "EMPTY_PIN").entrySet()) {
      String image = smcbWithPinSmc(c.getKey());
      given().port(admin.port()).delete("/admin/terminals/KT-01/slots/2").then().statusCode(200);
      given()
          .port(admin.port())
          .contentType("application/json")
          .body(Map.of("image", image))
          .put("/admin/terminals/KT-01/slots/2")
          .then()
          .statusCode(200);
      assertEquals(c.getValue(), pinStatus(smcb()), c.getKey());
      script("[{\"outcome\":\"transport\"}]");
      assertEquals("TRANSPORT_PIN", verifyPin(smcb()), c.getKey());
    }
  }

  /** smcb-valid with {@code transportStatus} of PIN.SMC, outside the search paths (same ICCSN). */
  private String smcbWithPinSmc(String transportStatus) throws Exception {
    String xml = Files.readString(Path.of("support/images/smcb-valid.xml"), StandardCharsets.UTF_8);
    int pin = xml.indexOf("<child id=\"PIN.SMC\"");
    String regular = "<attribute id=\"transportStatus\">regularPassword</attribute>";
    int status = xml.indexOf(regular, pin);
    Path image = images.resolve("smcb-" + transportStatus + ".xml");
    Files.writeString(
        image,
        xml.substring(0, status)
            + regular.replace("regularPassword", transportStatus)
            + xml.substring(status + regular.length()),
        StandardCharsets.UTF_8);
    return image.toAbsolutePath().toString();
  }

  @Test
  @DisplayName(
      "tiger-ehealth-kt-e2e: VerifyPin wartet am Robot-Terminal auf den Stift; enterWrongPin → REJECTED 2 "
          + "(EE_EHKT_VERIFYPIN_SMB_WRONG_PIN), verifyPin → OK, enterPinWithStop → 4049 (EE_EHKT_ABBRUCH), "
          + "enterIncompletePin und Karte ziehen → 4008 mit Severity Error (EE_EHKT_KARTE_ZIEHEN)")
  void robot() throws Exception {
    String smcb = smcb();
    robot("selTerminal1");
    CompletableFuture<ValidatableResponse> wrong = verifyPinWaiting(smcb);
    robot("enterWrongPin");
    Element rejected =
        bodyElement(wrong.get(20, TimeUnit.SECONDS).statusCode(200).extract().asString());
    assertEquals("REJECTED", xpath(rejected, "//*[local-name()='PinResult']"));
    assertEquals("2", xpath(rejected, "//*[local-name()='LeftTries']"));

    CompletableFuture<ValidatableResponse> correct = verifyPinWaiting(smcb);
    robot("verifyPin");
    assertEquals(
        "OK",
        xpath(
            bodyElement(correct.get(20, TimeUnit.SECONDS).statusCode(200).extract().asString()),
            "//*[local-name()='PinResult']"));

    CompletableFuture<ValidatableResponse> cancel = verifyPinWaiting(smcb);
    robot("enterPinWithStop");
    assertEquals(
        "4049",
        xpath(
            bodyElement(cancel.get(20, TimeUnit.SECONDS).statusCode(500).extract().asString()),
            "//*[local-name()='Code']"));

    CompletableFuture<ValidatableResponse> pulled = verifyPinWaiting(smcb);
    robot("enterIncompletePin");
    robot("removeBerechtigtenkarte");
    Element error =
        bodyElement(pulled.get(20, TimeUnit.SECONDS).statusCode(500).extract().asString());
    assertEquals("4008", xpath(error, "//*[local-name()='Code']"));
    assertEquals("Error", xpath(error, "//*[local-name()='Severity']"));
  }

  @Test
  @DisplayName(
      "Admin-API PIN-Script: unbekanntes outcome, digits ohne pin und kein Array → 400, unbekannter Slot → 404, "
          + "dann ist nichts angehängt; gelesen ohne pin; DELETE leert das Script")
  void pinScriptFehler() {
    for (String body :
        new String[] {
          "[{\"outcome\":\"falsch\"}]",
          "[{\"outcome\":\"digits\"}]",
          "{\"outcome\":\"wrong\"}",
          "[{}]"
        }) {
      given()
          .port(admin.port())
          .contentType("application/json")
          .body(body)
          .post("/admin/terminals/KT-01/pin-script")
          .then()
          .statusCode(400);
    }
    given()
        .port(admin.port())
        .contentType("application/json")
        .body("[{\"outcome\":\"wrong\",\"slotNo\":9}]")
        .post("/admin/terminals/KT-01/pin-script")
        .then()
        .statusCode(404);
    script("[{\"outcome\":\"digits\",\"pin\":\"4711\",\"slotNo\":2}]");
    var terminal =
        given().port(admin.port()).get("/admin/terminals/KT-01").then().extract().jsonPath();
    assertEquals(Map.of("outcome", "digits", "slotNo", 2), terminal.getMap("pinScript[0]"));
    given().port(admin.port()).delete("/admin/terminals/KT-01/pin-script").then().statusCode(200);
    assertEquals(
        0,
        given()
            .port(admin.port())
            .get("/admin/terminals/KT-01")
            .then()
            .extract()
            .jsonPath()
            .getList("pinScript")
            .size());
  }
}

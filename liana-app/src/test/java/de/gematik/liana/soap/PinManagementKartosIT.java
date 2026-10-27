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

import de.gematik.liana.admin.AdminServer;
import de.gematik.liana.kern.card.CardList;
import de.gematik.liana.robot.RobotServer;
import de.gematik.liana.sds.XsdValidator;
import io.quarkus.test.junit.QuarkusTest;
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
 * LIANA-109: ChangePin, UnblockPin, EnablePin, DisablePin and GetPinStatus of the eGK PINs against
 * cards in kartos (the card keeps the retry counters, PIN protection and new PINs). YAML state:
 * egk-valid in KT-01/1, smcb-valid in KT-01/2; KT-01 is robot terminal 1 and waits for every PIN
 * entry (PIN script of the Admin API or robot). After each test {@code POST /admin/reset}; the
 * cards come fresh from the image.
 */
@QuarkusTest
@TestProfile(PinPadKartosIT.KartosCards.class)
class PinManagementKartosIT {

  private static final String NS = "http://ws.gematik.de/conn/CardService/v8.2";
  private static final String NS_V81 = "http://ws.gematik.de/conn/CardService/v8.1";

  @Inject AdminServer admin;

  @Inject RobotServer robot;

  @Inject CardList cards;

  @TempDir Path images;

  @AfterEach
  void reset() {
    given().port(admin.port()).post("/admin/reset").then().statusCode(200);
  }

  private String egk() {
    return cards.card("KT-01", 1).orElseThrow().cardHandle();
  }

  private String smcb() {
    return cards.card("KT-01", 2).orElseThrow().cardHandle();
  }

  private static ValidatableResponse post(
      String namespace, String operation, String cardHandle, String pinTyp, String extra) {
    String body =
        """
                <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body>\
                <ns2:%1$s xmlns:ns2="%2$s" xmlns:ns3="http://ws.gematik.de/conn/ConnectorCommon/v5.0" \
                xmlns:ns6="http://ws.gematik.de/conn/ConnectorContext/v2.0">\
                <ns6:Context><ns3:MandantId>M1</ns3:MandantId><ns3:ClientSystemId>CS1</ns3:ClientSystemId>\
                <ns3:WorkplaceId>WP1</ns3:WorkplaceId></ns6:Context><ns3:CardHandle>%3$s</ns3:CardHandle>\
                <ns4:PinTyp xmlns:ns4="http://ws.gematik.de/conn/CardServiceCommon/v2.0">%4$s</ns4:PinTyp>%5$s\
                </ns2:%1$s></SOAP-ENV:Body></SOAP-ENV:Envelope>"""
            .formatted(operation, namespace, cardHandle, pinTyp, extra);
    return given()
        .contentType("text/xml; charset=utf-8")
        .header("SOAPAction", "\"" + namespace + "#" + operation + "\"")
        .body(body)
        .post("/ws/CardService")
        .then();
  }

  /**
   * Operation with status OK, response against the schema of the namespace: PinResult and LeftTries
   * (empty if absent).
   */
  private static String pin(
      String namespace, String operation, String cardHandle, String pinTyp, String extra)
      throws Exception {
    Element response =
        bodyElement(
            post(namespace, operation, cardHandle, pinTyp, extra)
                .statusCode(200)
                .extract()
                .asString());
    XsdValidator.validate(
        NS.equals(namespace) ? "conn/CardService_v8_2_1.xsd" : "conn/CardService_v8_1_3.xsd",
        serialize(response));
    assertEquals(operation + "Response", response.getLocalName());
    String leftTries = xpath(response, "//*[local-name()='LeftTries']");
    return xpath(response, "//*[local-name()='PinResult']")
        + (leftTries.isEmpty() ? "" : " " + leftTries);
  }

  private static String pin(String operation, String cardHandle, String pinTyp) throws Exception {
    return pin(NS, operation, cardHandle, pinTyp, "");
  }

  private static String fault(String operation, String cardHandle, String pinTyp) throws Exception {
    Element fault =
        bodyElement(
            post(NS, operation, cardHandle, pinTyp, "").statusCode(500).extract().asString());
    return xpath(fault, "//*[local-name()='Code']");
  }

  private static String pinStatus(String cardHandle, String pinTyp) throws Exception {
    Element response =
        bodyElement(
            post(NS, "GetPinStatus", cardHandle, pinTyp, "").statusCode(200).extract().asString());
    XsdValidator.validate("conn/CardService_v8_2_1.xsd", serialize(response));
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

  private void robot(String command, String input) {
    given()
        .port(robot.port())
        .contentType("application/json")
        .body(Map.of("command", command, "input", input))
        .post("/api/robot/robotCommand")
        .then()
        .statusCode(200);
  }

  @Test
  @DisplayName(
      "TIP1-A_5487 / TUC_KON_027 (EE_KT_T_DISABLE, EE_KT_T_PIN_ENABLE): DisablePin MRPIN.GDD mit PIN.CH → OK, "
          + "GetPinStatus DISABLED (62D0); EnablePin → OK, VERIFIABLE 3; MRPIN.AMTS ebenso; Antworten gegen "
          + "CardService_v8_2_1.xsd und im Namensraum v8.1 gegen v8_1_3.xsd")
  void pinSchutz() throws Exception {
    String egk = egk();
    assertEquals("VERIFIABLE 3", pinStatus(egk, "MRPIN.GDD"));
    script(
        "[{\"outcome\":\"correct\"},{\"outcome\":\"correct\"},{\"outcome\":\"correct\"},{\"outcome\":\"correct\"}]");
    assertEquals("OK", pin("DisablePin", egk, "MRPIN.GDD"));
    assertEquals("DISABLED", pinStatus(egk, "MRPIN.GDD"));
    assertEquals("OK", pin(NS_V81, "EnablePin", egk, "MRPIN.GDD", ""));
    assertEquals("VERIFIABLE 3", pinStatus(egk, "MRPIN.GDD"));
    assertEquals("OK", pin("DisablePin", egk, "MRPIN.AMTS"));
    assertEquals("DISABLED", pinStatus(egk, "MRPIN.AMTS"));
    assertEquals("OK", pin(NS_V81, "EnablePin", egk, "MRPIN.AMTS", ""));
  }

  @Test
  @DisplayName(
      "EE_KT_T_PIN_DISABLE_FALSCHE_EINGABE: DisablePin mit falscher PIN.CH → REJECTED 2, PIN-Schutz bleibt; "
          + "TAB_KON_245: SM-B → 4209, MRPIN.OSE → 4000")
  void pinSchutzFalsch() throws Exception {
    String egk = egk();
    script("[{\"outcome\":\"wrong\"}]");
    assertEquals("REJECTED 2", pin("DisablePin", egk, "MRPIN.GDD"));
    assertEquals("VERIFIABLE 2", pinStatus(egk, "MRPIN.GDD"));
    assertEquals("4209", fault("DisablePin", smcb(), "PIN.SMC"));
    assertEquals("4000", fault("EnablePin", egk, "MRPIN.OSE"));
  }

  @Test
  @DisplayName(
      "TIP1-A_4588 / TUC_KON_019 (EE_KT_T_PIN_CHANGE_AMTS_REP): ChangePin PIN.AMTS_REP – PIN.CH, neue "
          + "Vertreter-PIN, Wiederholung (drei Stiftbefehle des Robot) → OK; GetPinStatus VERIFIABLE")
  void vertreterPinAendern() throws Exception {
    String egk = egk();
    robot("selTerminal1", "");
    CompletableFuture<ValidatableResponse> change =
        CompletableFuture.supplyAsync(() -> post(NS, "ChangePin", egk, "PIN.AMTS_REP", ""));
    robot("verifyPin", "");
    robot("verifyPin", "");
    robot("verifyPin", "");
    Element response =
        bodyElement(change.get(20, TimeUnit.SECONDS).statusCode(200).extract().asString());
    XsdValidator.validate("conn/CardService_v8_2_1.xsd", serialize(response));
    assertEquals("OK", xpath(response, "//*[local-name()='PinResult']"));
    assertEquals("VERIFIABLE 3", pinStatus(egk, "PIN.AMTS_REP"));
  }

  @Test
  @DisplayName(
      "TUC_KON_019: ChangePin PIN.SMC auf 654321, danach gilt nur die neue PIN; falsche alte PIN → REJECTED 2; "
          + "ungleiche Wiederholung → 4067 (TAB_KON_093), die PIN bleibt")
  void smcbPinAendern() throws Exception {
    String smcb = smcb();
    script(
        """
                [{"outcome":"correct"},{"outcome":"digits","pin":"654321"},{"outcome":"digits","pin":"654321"},\
                {"outcome":"correct"},{"outcome":"digits","pin":"654321"}]""");
    assertEquals("OK", pin("ChangePin", smcb, "PIN.SMC"));
    assertEquals("REJECTED 2", pin("VerifyPin", smcb, "PIN.SMC"));
    assertEquals("OK", pin("VerifyPin", smcb, "PIN.SMC"));

    script("[{\"outcome\":\"wrong\"},{\"outcome\":\"correct\"},{\"outcome\":\"correct\"}]");
    assertEquals("REJECTED 2", pin("ChangePin", smcb, "PIN.SMC"));
    script(
        """
                [{"outcome":"digits","pin":"654321"},{"outcome":"correct"},{"outcome":"digits","pin":"111111"}]""");
    assertEquals("4067", fault("ChangePin", smcb, "PIN.SMC"));
    assertEquals("VERIFIABLE 2", pinStatus(smcb, "PIN.SMC"));
  }

  @Test
  @DisplayName(
      "TIP1-A_4590 / TUC_KON_021: UnblockPin PIN.SMC – nicht gesperrt → OK ohne PIN-Eingabe; nach drei "
          + "Fehleingaben (BLOCKED 0) mit PUK → OK, VERIFIABLE 3; SetNewPin true mit PUK und neuer PIN → OK, die neue "
          + "PIN gilt; falsche PUK → REJECTED mit den verbleibenden PUK-Verwendungen")
  void entsperren() throws Exception {
    String smcb = smcb();
    assertEquals("OK", pin("UnblockPin", smcb, "PIN.SMC"));
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

    script(
        "[{\"outcome\":\"wrong\"},{\"outcome\":\"wrong\"},{\"outcome\":\"wrong\"},{\"outcome\":\"puk\"}]");
    pin("VerifyPin", smcb, "PIN.SMC");
    pin("VerifyPin", smcb, "PIN.SMC");
    assertEquals("NOWBLOCKED", pin("VerifyPin", smcb, "PIN.SMC"));
    assertEquals("OK", pin("UnblockPin", smcb, "PIN.SMC"));
    assertEquals("VERIFIABLE 3", pinStatus(smcb, "PIN.SMC"));

    script(
        """
                [{"outcome":"wrong"},{"outcome":"wrong"},{"outcome":"wrong"},\
                {"outcome":"digits","pin":"11111111"},{"outcome":"digits","pin":"777777"},{"outcome":"digits","pin":"777777"},\
                {"outcome":"puk"},{"outcome":"digits","pin":"777777"},{"outcome":"digits","pin":"777777"},\
                {"outcome":"digits","pin":"777777"}]""");
    pin("VerifyPin", smcb, "PIN.SMC");
    pin("VerifyPin", smcb, "PIN.SMC");
    pin("VerifyPin", smcb, "PIN.SMC");
    // pukUsage of the image '0a': every unblock consumes one; after the first one and a wrong PUK,
    // 8
    // remain
    assertEquals(
        "REJECTED 8",
        pin(NS, "UnblockPin", smcb, "PIN.SMC", "<ns2:SetNewPin>true</ns2:SetNewPin>"));
    assertEquals(
        "OK", pin(NS, "UnblockPin", smcb, "PIN.SMC", "<ns2:SetNewPin>true</ns2:SetNewPin>"));
    assertEquals("OK", pin("VerifyPin", smcb, "PIN.SMC"));
  }

  @Test
  @DisplayName(
      "TAB_KON_049/053 für HBAx und eGK: ChangePin PIN.CH des HBA (KT-01/3) auf 654321, danach gilt die neue "
          + "PIN; eGK PIN.CH nach drei Fehleingaben (ChangePin REJECTED 2, 1, NOWBLOCKED) mit PUK entsperrt, "
          + "VERIFIABLE 3; Antworten im Namensraum v8.1 gegen CardService_v8_1_3.xsd")
  void hbaUndEgk() throws Exception {
    String hba = cards.card("KT-01", 3).orElseThrow().cardHandle();
    script(
        """
                [{"outcome":"correct","slotNo":3},{"outcome":"digits","pin":"654321","slotNo":3},\
                {"outcome":"digits","pin":"654321","slotNo":3},{"outcome":"digits","pin":"654321","slotNo":3}]""");
    assertEquals("OK", pin(NS_V81, "ChangePin", hba, "PIN.CH", ""));
    assertEquals("OK", pin(NS_V81, "VerifyPin", hba, "PIN.CH", ""));

    String egk = egk();
    script(
        """
                [{"outcome":"wrong","slotNo":1},{"outcome":"correct","slotNo":1},{"outcome":"correct","slotNo":1},\
                {"outcome":"wrong","slotNo":1},{"outcome":"correct","slotNo":1},{"outcome":"correct","slotNo":1},\
                {"outcome":"wrong","slotNo":1},{"outcome":"correct","slotNo":1},{"outcome":"correct","slotNo":1},\
                {"outcome":"puk","slotNo":1}]""");
    assertEquals("REJECTED 2", pin(NS_V81, "ChangePin", egk, "PIN.CH", ""));
    assertEquals("REJECTED 1", pin(NS_V81, "ChangePin", egk, "PIN.CH", ""));
    assertEquals("NOWBLOCKED", pin(NS_V81, "ChangePin", egk, "PIN.CH", ""));
    assertEquals("BLOCKED 0", pinStatus(egk, "PIN.CH"));
    assertEquals("OK", pin(NS_V81, "UnblockPin", egk, "PIN.CH", ""));
    assertEquals("VERIFIABLE 3", pinStatus(egk, "PIN.CH"));
  }

  @Test
  @DisplayName(
      "TUC_KON_019 7b Transportschutz: SMC-B mit Transport-PIN (Image mit transportStatus transportPIN) – "
          + "ChangePin mit Transport-PIN, neuer PIN und Wiederholung → OK, danach VERIFIABLE")
  void transportPinAendern() throws Exception {
    String xml = Files.readString(Path.of("support/images/smcb-valid.xml"), StandardCharsets.UTF_8);
    String regular = "<attribute id=\"transportStatus\">regularPassword</attribute>";
    int status = xml.indexOf(regular, xml.indexOf("<child id=\"PIN.SMC\""));
    Path image = images.resolve("smcb-transport.xml");
    Files.writeString(
        image,
        xml.substring(0, status)
            + regular.replace("regularPassword", "transportPIN")
            + xml.substring(status + regular.length()),
        StandardCharsets.UTF_8);
    given().port(admin.port()).delete("/admin/terminals/KT-01/slots/2").then().statusCode(200);
    given()
        .port(admin.port())
        .contentType("application/json")
        .body(Map.of("image", image.toString()))
        .put("/admin/terminals/KT-01/slots/2")
        .then()
        .statusCode(200);
    String smcb = smcb();
    assertEquals("TRANSPORT_PIN", pinStatus(smcb, "PIN.SMC"));
    // the transport PIN is the image's secret (123456, "correct")
    script(
        """
                [{"outcome":"correct"},{"outcome":"digits","pin":"654321"},{"outcome":"digits","pin":"654321"}]""");
    assertEquals("OK", pin("ChangePin", smcb, "PIN.SMC"));
    assertEquals("VERIFIABLE 3", pinStatus(smcb, "PIN.SMC"));
  }

  @Test
  @DisplayName(
      "EE_KT_T_PIN_ABBRUCH / EE_KT_T_PIN_KARTE_ZIEHEN: DisablePin am Robot-Terminal – enterPinWithStop → 4049; "
          + "enterIncompletePin und Karte ziehen → 4008 mit Severity Error")
  void abbruch() throws Exception {
    String egk = egk();
    robot("selTerminal1", "");
    CompletableFuture<ValidatableResponse> cancel =
        CompletableFuture.supplyAsync(() -> post(NS, "DisablePin", egk, "MRPIN.GDD", ""));
    robot("enterPinWithStop", "");
    assertEquals(
        "4049",
        xpath(
            bodyElement(cancel.get(20, TimeUnit.SECONDS).statusCode(500).extract().asString()),
            "//*[local-name()='Code']"));

    CompletableFuture<ValidatableResponse> pulled =
        CompletableFuture.supplyAsync(() -> post(NS, "DisablePin", egk, "MRPIN.GDD", ""));
    robot("enterIncompletePin", "");
    awaitDisplay();
    robot("removePatientenkarte", "");
    Element error =
        bodyElement(pulled.get(20, TimeUnit.SECONDS).statusCode(500).extract().asString());
    assertEquals("4008", xpath(error, "//*[local-name()='Code']"));
    assertEquals("Error", xpath(error, "//*[local-name()='Severity']"));
  }

  /** Waits until the PIN pad of KT-01 shows a prompt. */
  private void awaitDisplay() throws InterruptedException {
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
        throw new AssertionError("PIN-Pad von KT-01 zeigt keine Aufforderung");
      }
      Thread.sleep(20);
    }
  }
}

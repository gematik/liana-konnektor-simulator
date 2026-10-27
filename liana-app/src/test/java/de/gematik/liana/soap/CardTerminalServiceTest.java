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
import static org.junit.jupiter.api.Assertions.assertNull;

import de.gematik.liana.admin.AdminServer;
import de.gematik.liana.sds.XsdValidator;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;

/**
 * LIANA-110: CardTerminalService RequestCard and EjectCard at the fake KT (YAML state: KT-01 with
 * eGK, SMC-B and HBA, KT-02 empty, both at WP1). Inserting and removing while waiting via the Admin
 * API, as a robot or user would.
 */
@QuarkusTest
class CardTerminalServiceTest {

  private static final String NS = "http://ws.gematik.de/conn/CardTerminalService/v1.1";
  private static final String CONTEXT =
      "<CCTX:Context><CONN:MandantId>M1</CONN:MandantId>"
          + "<CONN:ClientSystemId>CS1</CONN:ClientSystemId><CONN:WorkplaceId>WP1</CONN:WorkplaceId></CCTX:Context>";

  @Inject AdminServer admin;

  @AfterEach
  void reset() {
    given().port(admin.port()).post("/admin/reset").then().statusCode(200);
  }

  private static String envelope(String operation, String content) {
    return """
                <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body>\
                <CT:%1$s xmlns:CT="%2$s" xmlns:CONN="http://ws.gematik.de/conn/ConnectorCommon/v5.0" \
                xmlns:CARDCMN="http://ws.gematik.de/conn/CardServiceCommon/v2.0" \
                xmlns:CCTX="http://ws.gematik.de/conn/ConnectorContext/v2.0">%3$s%4$s</CT:%1$s>\
                </SOAP-ENV:Body></SOAP-ENV:Envelope>"""
        .formatted(operation, NS, CONTEXT, content);
  }

  private static String slot(String ctId, int slot) {
    return "<CT:Slot><CARDCMN:CtId>"
        + ctId
        + "</CARDCMN:CtId><CARDCMN:SlotId>"
        + slot
        + "</CARDCMN:SlotId></CT:Slot>";
  }

  private static Element post(String operation, String content, int status) throws Exception {
    return bodyElement(
        given()
            .contentType("text/xml; charset=utf-8")
            .header("SOAPAction", "\"" + NS + "#" + operation + "\"")
            .body(envelope(operation, content))
            .post("/ws/CardTerminalService")
            .then()
            .statusCode(status)
            .extract()
            .asString());
  }

  private static CompletableFuture<Element> postAsync(String operation, String content) {
    return CompletableFuture.supplyAsync(
        () -> {
          try {
            return post(operation, content, 200);
          } catch (Exception e) {
            throw new IllegalStateException(e);
          }
        });
  }

  /** Waits until the fake KT shows {@code message} (Admin API {@code display}). */
  private void awaitDisplay(String ctId, String message) throws InterruptedException {
    long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
    while (!message.equals(display(ctId))) {
      if (System.nanoTime() > deadline) {
        throw new AssertionError(ctId + " zeigt nicht „" + message + "“, sondern " + display(ctId));
      }
      Thread.sleep(20);
    }
  }

  private String display(String ctId) {
    return given()
        .port(admin.port())
        .get("/admin/terminals/" + ctId)
        .then()
        .statusCode(200)
        .extract()
        .jsonPath()
        .getString("display");
  }

  private void put(String ctId, int slot, String image) {
    given()
        .port(admin.port())
        .contentType("application/json")
        .body(Map.of("image", image))
        .put("/admin/terminals/" + ctId + "/slots/" + slot)
        .then()
        .statusCode(200);
  }

  private void pull(String ctId, int slot) {
    given()
        .port(admin.port())
        .delete("/admin/terminals/" + ctId + "/slots/" + slot)
        .then()
        .statusCode(200);
  }

  @Test
  @DisplayName(
      "TIP1-A_5412 / TUC_KON_056 4a: RequestCard für die gesteckte eGK in KT-01/1 liefert sie sofort mit "
          + "AlreadyInserted true; Antwort gegen CardTerminalService.xsd")
  void schonGesteckt() throws Exception {
    Element response =
        post("RequestCard", slot("KT-01", 1) + "<CARDCMN:CardType>EGK</CARDCMN:CardType>", 200);
    XsdValidator.validate("conn/CardTerminalService.xsd", serialize(response));
    assertEquals("OK", xpath(response, "//*[local-name()='Result']"));
    assertEquals("true", xpath(response, "//*[local-name()='AlreadyInserted']"));
    assertEquals("EGK", xpath(response, "//*[local-name()='Card']/*[local-name()='CardType']"));
    assertEquals("KT-01", xpath(response, "//*[local-name()='Card']/*[local-name()='CtId']"));
  }

  @Test
  @DisplayName(
      "TUC_KON_056 Schritt 2–6: das Fake-KT zeigt die DisplayMsg, bis die eGK gesteckt ist (Admin-API); "
          + "RequestCard liefert sie mit AlreadyInserted false, danach ist das Display leer")
  void gestecktNachAufforderung() throws Exception {
    CompletableFuture<Element> request =
        postAsync(
            "RequestCard",
            slot("KT-02", 1)
                + "<CT:DisplayMsg>Tiger: Bitte Karten stecken</CT:DisplayMsg><CT:TimeOut>20</CT:TimeOut>");
    awaitDisplay("KT-02", "Tiger: Bitte Karten stecken");
    put("KT-02", 1, "egk-valid");
    Element response = request.get(20, TimeUnit.SECONDS);
    XsdValidator.validate("conn/CardTerminalService.xsd", serialize(response));
    assertEquals("false", xpath(response, "//*[local-name()='AlreadyInserted']"));
    assertEquals("1", xpath(response, "//*[local-name()='Card']/*[local-name()='SlotId']"));
    assertNull(display("KT-02"));
  }

  @Test
  @DisplayName(
      "TIP1-A_5408: ohne DisplayMsg zeigt das KT die Standardanzeige; ohne Karte innerhalb des TimeOut "
          + "(Sekunden) 4202")
  void timeout() throws Exception {
    CompletableFuture<Element> request =
        CompletableFuture.supplyAsync(
            () -> {
              try {
                return post(
                    "RequestCard",
                    slot("KT-02", 2)
                        + "<CARDCMN:CardType>EGK</CARDCMN:CardType>"
                        + "<CT:TimeOut>2</CT:TimeOut>",
                    500);
              } catch (Exception e) {
                throw new IllegalStateException(e);
              }
            });
    awaitDisplay("KT-02", "Bitte \u000BeGK \u000Bin \u000BSLOT 2 \u000Bstecken");
    assertEquals("4202", xpath(request.get(10, TimeUnit.SECONDS), "//*[local-name()='Code']"));
  }

  @Test
  @DisplayName(
      "TIP1-A_5413 / TUC_KON_057: EjectCard per Slot zeigt die DisplayMsg, bis die Karte gezogen ist "
          + "(TimeOut in Millisekunden); Antwort gegen CardTerminalService.xsd, die Karte ist aus GetCards")
  void auswerfen() throws Exception {
    CompletableFuture<Element> eject =
        postAsync(
            "EjectCard",
            slot("KT-01", 1)
                + "<CT:DisplayMsg>Tiger-Test ist fertig</CT:DisplayMsg><CT:TimeOut>50000</CT:TimeOut>");
    awaitDisplay("KT-01", "Tiger-Test ist fertig");
    pull("KT-01", 1);
    Element response = eject.get(20, TimeUnit.SECONDS);
    XsdValidator.validate("conn/CardTerminalService.xsd", serialize(response));
    assertEquals("OK", xpath(response, "//*[local-name()='Result']"));
    assertEquals(
        null,
        given()
            .port(admin.port())
            .get("/admin/terminals/KT-01")
            .then()
            .extract()
            .jsonPath()
            .getString("slots[0].cardType"));
  }

  @Test
  @DisplayName(
      "TAB_KON_721: bleibt die Karte stecken, 4203 nach dem TimeOut; unbekanntes CardHandle 4101; "
          + "TAB_KON_717 CardType SMC-B 4058")
  void fehler() throws Exception {
    Element notRemoved = post("EjectCard", slot("KT-01", 3) + "<CT:TimeOut>200</CT:TimeOut>", 500);
    assertEquals("4203", xpath(notRemoved, "//*[local-name()='Code']"));
    Element handle = post("EjectCard", "<CONN:CardHandle>unbekannt</CONN:CardHandle>", 500);
    assertEquals("4101", xpath(handle, "//*[local-name()='Code']"));
    Element type =
        post("RequestCard", slot("KT-01", 2) + "<CARDCMN:CardType>SMC-B</CARDCMN:CardType>", 500);
    assertEquals("4058", xpath(type, "//*[local-name()='Code']"));
  }
}

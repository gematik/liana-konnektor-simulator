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
import static de.gematik.liana.soap.EventServiceTest.xpath;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import de.gematik.liana.adapter.fake.CardImages;
import de.gematik.liana.kern.card.CardList;
import de.gematik.liana.kern.card.CardType;
import de.gematik.liana.robot.RobotServer;
import de.gematik.liana.sicct.KartosTerminal;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.common.QuarkusTestResourceLifecycleManager;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.ValidatableResponse;
import jakarta.inject.Inject;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.w3c.dom.Element;

/**
 * LIANA-112.15: robot interface with KT-01 as {@code kartos terminal} over SICCT, like {@code
 * ehkt.sh} in SICCT mode. Boot: egk-valid in slot 1, smcb-valid in 2, gSMC-KT in 3. The robot
 * inserts and removes via the kartos control interface; with {@code await-pin}, the PIN entry
 * arrives only after the call, as in tiger-ehealth-kt-e2e; LIANA holds PERFORM VERIFICATION until
 * then and puts the entry into the kartos PIN script. The tests run in order.
 */
@QuarkusTest
@QuarkusTestResource(value = RobotKartosIT.Kartos.class, restrictToAnnotatedClass = true)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class RobotKartosIT {

  static final String SECRET = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf";
  static final String NS = "http://ws.gematik.de/conn/CardService/v8.2";
  static final Duration WAIT = Duration.ofSeconds(20);

  public static class Kartos implements QuarkusTestResourceLifecycleManager {
    static KartosTerminal kt;

    @Override
    public Map<String, String> start() {
      kt =
          KartosTerminal.start(
              "02:00:00:4C:49:46",
              "kartos-kt-robot",
              0,
              Map.of("TERMINAL_TRACE", "true"),
              SECRET,
              List.of("egk-valid", "smcb-valid", "gsmckt-valid"));
      int announcements;
      try {
        announcements = KartosTerminal.freeUdpPort();
      } catch (IOException e) {
        throw new UncheckedIOException(e);
      }
      return Map.ofEntries(
          Map.entry("liana.infrastructure.terminals.KT-01.type", "sicct"),
          Map.entry("liana.infrastructure.terminals.KT-01.host", "127.0.0.1"),
          Map.entry("liana.infrastructure.terminals.KT-01.shared-secret", SECRET),
          Map.entry(
              "liana.infrastructure.terminals.KT-01.control",
              "http://127.0.0.1:" + kt.controlPort()),
          Map.entry("liana.ctm.service-discovery-port", String.valueOf(kt.port())),
          Map.entry("liana.ctm.service-announcement-port", String.valueOf(announcements)),
          Map.entry("liana.ctm.service-discovery-timeout", "2s"),
          Map.entry("liana.infomodel.workplaces[0].terminals", "KT-01"),
          Map.entry("liana.robot.port", "0"),
          Map.entry("liana.robot.await-pin", "true"));
    }

    @Override
    public void stop() {
      if (kt != null) {
        kt.close();
      }
    }
  }

  @Inject RobotServer server;

  @Inject CardList cards;

  @Test
  @Order(1)
  @DisplayName(
      "Removinator SC2 und IHP stecken hba-valid über kartos in KT-01/2: kartos zieht die SMC-B (85) und "
          + "steckt den HBA (84), LIANA meldet den HBA nach TUC_KON_001")
  void stecken() throws InterruptedException {
    awaitType(2, CardType.SMC_B);
    robot("selTerminal1", "").statusCode(200);
    robot("sendToRemovinator", "SC2").statusCode(200);
    robot("IHP", "").statusCode(200);
    awaitType(2, CardType.HBA);
    assertEquals(
        CardImages.iccsn(Path.of("support/images/hba-valid.xml")).orElseThrow(),
        Kartos.kt.iccsn(2),
        "Slot 2 von kartos: hba-valid, hochgeladen in die Bibliothek");
  }

  @Test
  @Order(2)
  @DisplayName(
      "TUC_KON_012 über SICCT mit await-pin: VerifyPin PIN.CH wartet auf den Robot, erst „verifyPin“ "
          + "schickt PERFORM VERIFICATION mit der richtigen PIN → PinResult OK")
  void pinNachDemAufruf() throws Exception {
    String hba = cardHandle(2);
    int before = performVerifications();
    CompletableFuture<String> response =
        CompletableFuture.supplyAsync(() -> verifyPin(hba).extract().asString());
    TimeUnit.SECONDS.sleep(2);
    assertFalse(response.isDone(), "VerifyPin wartet auf die PIN-Eingabe");
    assertEquals(
        before, performVerifications(), "ohne Eingabe kein PERFORM VERIFICATION an kartos");
    robot("verifyPin", "").statusCode(200);
    Element body = bodyElement(response.get(WAIT.toSeconds(), TimeUnit.SECONDS));
    assertEquals("OK", xpath(body, "//*[local-name()='PinResult']"), Kartos.kt.log());
    assertEquals(before + 1, performVerifications());
  }

  @Test
  @Order(3)
  @DisplayName(
      "TIP1-A_4567: „enterWrongPin“ nach dem Aufruf → kartos tippt die falsche PIN, REJECTED mit LeftTries 2; "
          + "danach „verifyPin“ → OK")
  void falschePin() throws Exception {
    String hba = cardHandle(2);
    CompletableFuture<String> wrong =
        CompletableFuture.supplyAsync(() -> verifyPin(hba).extract().asString());
    TimeUnit.MILLISECONDS.sleep(500);
    robot("enterWrongPin", "").statusCode(200);
    Element body = bodyElement(wrong.get(WAIT.toSeconds(), TimeUnit.SECONDS));
    assertEquals("REJECTED", xpath(body, "//*[local-name()='PinResult']"), Kartos.kt.log());
    assertEquals("2", xpath(body, "//*[local-name()='LeftTries']"));
    CompletableFuture<String> right =
        CompletableFuture.supplyAsync(() -> verifyPin(hba).extract().asString());
    TimeUnit.MILLISECONDS.sleep(500);
    robot("verifyPin", "").statusCode(200);
    assertEquals(
        "OK",
        xpath(
            bodyElement(right.get(WAIT.toSeconds(), TimeUnit.SECONDS)),
            "//*[local-name()='PinResult']"));
  }

  @Test
  @Order(4)
  @DisplayName(
      "TUC_KON_012 7b: „enterPinWithStop“ → kartos beantwortet PERFORM VERIFICATION mit 6401, LIANA meldet den "
          + "Abbruch durch den Nutzer (4049)")
  void abbruch() throws Exception {
    String hba = cardHandle(2);
    CompletableFuture<ValidatableResponse> cancel =
        CompletableFuture.supplyAsync(() -> verifyPin(hba));
    TimeUnit.MILLISECONDS.sleep(500);
    robot("enterPinWithStop", "").statusCode(200);
    String fault =
        cancel.get(WAIT.toSeconds(), TimeUnit.SECONDS).statusCode(500).extract().asString();
    assertEquals("4049", xpath(bodyElement(fault), "//*[local-name()='Code']"), fault);
  }

  @Test
  @Order(5)
  @DisplayName(
      "IHO zieht den HBA über kartos (85): LIANA meldet Slot 2 leer; pressBerechtigtenkarte steckt ihn wieder")
  void ziehen() throws InterruptedException {
    robot("IHO", "").statusCode(200);
    await(() -> cards.card("KT-01", 2).isEmpty(), "KT-01/2 leer");
    assertFalse(
        Kartos.kt.control().get("/slots/2").then().extract().jsonPath().getBoolean("occupied"));
    robot("pressBerechtigtenkarte", "").statusCode(200);
    awaitType(2, CardType.HBA);
  }

  private ValidatableResponse robot(String command, String input) {
    return given()
        .port(server.port())
        .contentType("application/json")
        .body(Map.of("command", command, "input", input))
        .post("/api/robot/robotCommand")
        .then();
  }

  private int performVerifications() {
    return (int)
        Kartos.kt.wire().stream()
            .filter(l -> l.contains("\"dir\":\"in\"") && l.contains("801802d0"))
            .count();
  }

  private String cardHandle(int slot) throws InterruptedException {
    await(() -> cards.card("KT-01", slot).isPresent(), "Karte in KT-01/" + slot);
    return cards.card("KT-01", slot).orElseThrow().cardHandle();
  }

  private void awaitType(int slot, CardType type) throws InterruptedException {
    await(
        () -> cards.card("KT-01", slot).filter(card -> card.data().type() == type).isPresent(),
        type + " in KT-01/" + slot);
  }

  private static void await(BooleanSupplier condition, String what) throws InterruptedException {
    long deadline = System.nanoTime() + WAIT.toNanos();
    while (!condition.getAsBoolean()) {
      if (System.nanoTime() > deadline) {
        throw new AssertionError(what + "\nkartos: " + Kartos.kt.log());
      }
      Thread.sleep(100);
    }
  }

  private static ValidatableResponse verifyPin(String cardHandle) {
    String body =
        """
                <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body>\
                <ns2:VerifyPin xmlns:ns2="%1$s" xmlns:ns3="http://ws.gematik.de/conn/ConnectorCommon/v5.0" \
                xmlns:ns6="http://ws.gematik.de/conn/ConnectorContext/v2.0">\
                <ns6:Context><ns3:MandantId>M1</ns3:MandantId><ns3:ClientSystemId>CS1</ns3:ClientSystemId>\
                <ns3:WorkplaceId>WP1</ns3:WorkplaceId></ns6:Context><ns3:CardHandle>%2$s</ns3:CardHandle>\
                <ns4:PinTyp xmlns:ns4="http://ws.gematik.de/conn/CardServiceCommon/v2.0">PIN.CH</ns4:PinTyp>\
                </ns2:VerifyPin></SOAP-ENV:Body></SOAP-ENV:Envelope>"""
            .formatted(NS, cardHandle);
    return given()
        .contentType("text/xml; charset=utf-8")
        .header("SOAPAction", "\"" + NS + "#VerifyPin\"")
        .body(body)
        .post("/ws/CardService")
        .then();
  }
}

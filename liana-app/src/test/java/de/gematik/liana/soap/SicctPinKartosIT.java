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
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.kern.card.CardList;
import de.gematik.liana.kern.event.SystemLog;
import de.gematik.liana.kern.vendor.PeerDeviations;
import de.gematik.liana.sds.XsdValidator;
import de.gematik.liana.sicct.KartosTerminal;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.common.QuarkusTestResourceLifecycleManager;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.ValidatableResponse;
import jakarta.inject.Inject;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.w3c.dom.Element;

/**
 * LIANA-80: VerifyPin PIN.SMC via SICCT PERFORM VERIFICATION against {@code kartos terminal} (SMC-B
 * in slot 2 as with the fake terminal), LIANA-61: PIN.CH of the HBA in slot 4. The kartos control
 * interface drives the PIN entry at the keypad (PIN script {@code POST /api/v1/tui/script} in input
 * mode {@code script}, LIANA-73, LIANA-118); the kartos wire trace shows the command on the line.
 * LIANA-63: GetPinStatus reads the retry counter of the card (GET PIN STATUS). LIANA-127:
 * UnblockPin and ChangePin via SICCT MODIFY VERIFICATION DATA with the kartos deviation
 * (LIANA-126). The tests run in order; at the end PIN.CH is blocked and PIN.SMC is 654321.
 */
@QuarkusTest
@QuarkusTestResource(value = SicctPinKartosIT.Kartos.class, restrictToAnnotatedClass = true)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class SicctPinKartosIT {

  static final String SECRET = "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf";
  static final String NS = "http://ws.gematik.de/conn/CardService/v8.2";
  static final Duration WAIT = Duration.ofSeconds(20);

  public static class Kartos implements QuarkusTestResourceLifecycleManager {
    static KartosTerminal kt;

    @Override
    public Map<String, String> start() {
      kt =
          KartosTerminal.start(
              "02:00:00:4C:49:45",
              "kartos-kt-pin",
              0,
              Map.of("TERMINAL_TRACE", "true", "TERMINAL_INPUT_MODE", "script"),
              SECRET,
              List.of("egk-valid", "smcb-valid", "gsmckt-valid", "hba-valid"));
      int announcements;
      try {
        announcements = KartosTerminal.freeUdpPort();
      } catch (IOException e) {
        throw new UncheckedIOException(e);
      }
      return Map.of(
          "liana.infrastructure.terminals.KT-01.type", "sicct",
          "liana.infrastructure.terminals.KT-01.host", "127.0.0.1",
          "liana.infrastructure.terminals.KT-01.shared-secret", SECRET,
          "liana.ctm.service-discovery-port", String.valueOf(kt.port()),
          "liana.ctm.service-announcement-port", String.valueOf(announcements),
          "liana.ctm.service-discovery-timeout", "2s",
          "liana.infomodel.workplaces[0].terminals", "KT-01");
    }

    @Override
    public void stop() {
      if (Kartos.kt != null) {
        Kartos.kt.close();
      }
    }
  }

  @Inject CardList cards;

  @Inject de.gematik.liana.admin.AdminServer admin;

  private String smcb() throws InterruptedException {
    return card(2);
  }

  private String hba() throws InterruptedException {
    return card(4);
  }

  private String card(int slot) throws InterruptedException {
    long deadline = System.nanoTime() + WAIT.toNanos();
    while (cards.card("KT-01", slot).isEmpty()) {
      if (System.nanoTime() > deadline) {
        throw new AssertionError("Karte in KT-01/" + slot + "\nkartos: " + Kartos.kt.log());
      }
      Thread.sleep(100);
    }
    return cards.card("KT-01", slot).orElseThrow().cardHandle();
  }

  private static ValidatableResponse verifyPin(String cardHandle) {
    return verifyPin(cardHandle, "PIN.SMC");
  }

  private static ValidatableResponse verifyPin(String cardHandle, String pinTyp) {
    String body =
        """
                <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body>\
                <ns2:VerifyPin xmlns:ns2="%1$s" xmlns:ns3="http://ws.gematik.de/conn/ConnectorCommon/v5.0" \
                xmlns:ns6="http://ws.gematik.de/conn/ConnectorContext/v2.0">\
                <ns6:Context><ns3:MandantId>M1</ns3:MandantId><ns3:ClientSystemId>CS1</ns3:ClientSystemId>\
                <ns3:WorkplaceId>WP1</ns3:WorkplaceId></ns6:Context><ns3:CardHandle>%2$s</ns3:CardHandle>\
                <ns4:PinTyp xmlns:ns4="http://ws.gematik.de/conn/CardServiceCommon/v2.0">%3$s</ns4:PinTyp>\
                </ns2:VerifyPin></SOAP-ENV:Body></SOAP-ENV:Envelope>"""
            .formatted(NS, cardHandle, pinTyp);
    return given()
        .contentType("text/xml; charset=utf-8")
        .header("SOAPAction", "\"" + NS + "#VerifyPin\"")
        .body(body)
        .post("/ws/CardService")
        .then();
  }

  private static ValidatableResponse getPinStatus(String cardHandle, String pinTyp) {
    String body =
        """
                <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body>\
                <ns2:GetPinStatus xmlns:ns2="%1$s" xmlns:ns3="http://ws.gematik.de/conn/ConnectorCommon/v5.0" \
                xmlns:ns6="http://ws.gematik.de/conn/ConnectorContext/v2.0">\
                <ns6:Context><ns3:MandantId>M1</ns3:MandantId><ns3:ClientSystemId>CS1</ns3:ClientSystemId>\
                <ns3:WorkplaceId>WP1</ns3:WorkplaceId></ns6:Context><ns3:CardHandle>%2$s</ns3:CardHandle>\
                <ns4:PinTyp xmlns:ns4="http://ws.gematik.de/conn/CardServiceCommon/v2.0">%3$s</ns4:PinTyp>\
                </ns2:GetPinStatus></SOAP-ENV:Body></SOAP-ENV:Envelope>"""
            .formatted(NS, cardHandle, pinTyp);
    return given()
        .contentType("text/xml; charset=utf-8")
        .header("SOAPAction", "\"" + NS + "#GetPinStatus\"")
        .body(body)
        .post("/ws/CardService")
        .then();
  }

  /**
   * PinStatus and LeftTries (empty if not delivered) from GetPinStatus, response against the
   * schema.
   */
  private static String pinStatus(String cardHandle, String pinTyp) throws Exception {
    Element response = ok(getPinStatus(cardHandle, pinTyp));
    String leftTries = xpath(response, "//*[local-name()='LeftTries']");
    return xpath(response, "//*[local-name()='PinStatus']")
        + (leftTries.isEmpty() ? "" : " " + leftTries);
  }

  private static Element ok(ValidatableResponse response) throws Exception {
    Element element = bodyElement(response.statusCode(200).extract().asString());
    XsdValidator.validate("conn/CardService_v8_2_1.xsd", serialize(element));
    return element;
  }

  private static String faultCode(ValidatableResponse response) throws Exception {
    return xpath(
        bodyElement(response.statusCode(500).extract().asString()), "//*[local-name()='Code']");
  }

  /** Next PIN entry at the keypad of slot 2 (kartos LIANA-73). */
  private static void keypad(String outcome) {
    keypad(2, outcome, 1);
  }

  /**
   * The next {@code times} PIN entries at the keypad of {@code slot}: {@code correct}, {@code
   * wrong}, {@code cancel} …
   */
  private static void keypad(int slot, String outcome, int times) {
    Kartos.kt.pinScript(
        java.util.stream.Stream.generate(
                () -> "{\"outcome\":\"" + outcome + "\",\"slotNo\":" + slot + "}")
            .limit(times)
            .collect(java.util.stream.Collectors.joining(",", "[", "]")));
  }

  /** APPL DO (tag 50) with {@code text}, hex as in the wire trace. */
  private static String appl(String text) {
    byte[] bytes = text.getBytes(StandardCharsets.US_ASCII);
    return "50" + "%02x".formatted(bytes.length) + HexFormat.of().formatHex(bytes);
  }

  @Test
  @Order(1)
  @DisplayName(
      "TIP1-A_4587 / TUC_KON_012 über SICCT: VerifyPin PIN.SMC liefert wie am Fake-Terminal Status OK, "
          + "PinResult OK, kein LeftTries; LIANA-63 TIP1-A_4589: GetPinStatus davor VERIFIABLE mit LeftTries 3, danach "
          + "VERIFIED; Antworten gegen CardService_v8_2_1.xsd")
  void ok() throws Exception {
    assertEquals(
        "VERIFIABLE 3",
        pinStatus(smcb(), "PIN.SMC"),
        "TIP1-A_4589 / TUC_KON_022 3b: GET PIN STATUS an die frische SMC-B, Fehlbedienungszähler 3");
    Element response = ok(verifyPin(smcb()));
    assertEquals("OK", xpath(response, "//*[local-name()='Result']"));
    assertEquals("OK", xpath(response, "//*[local-name()='PinResult']"));
    assertEquals("0", xpath(response, "count(//*[local-name()='LeftTries'])"));
    assertEquals("VERIFIED", pinStatus(smcb(), "PIN.SMC"), "TUC_KON_022 3a: PIN.SMC in AUTHSTATE");
  }

  @Test
  @Order(2)
  @DisplayName(
      "TIP1-A_3083 / TIP1-A_4561-02 im Wire-Trace: PERFORM VERIFICATION an FU 0 mit P1 = Slot 2, P2 = D0 und "
          + "den Anzeigen aus TAB_KON_090 (Aufforderung mit PIN-Prompt, Erfolg, Fehler) vor dem CMD DO")
  void wireTrace() {
    String dialog =
        appl("Eingabe \u000BPIN SMC-B \u000BSLOT:2\u000FPIN.SMC:")
            + appl("PIN \u000Berfolgreich \u000Bverifiziert!")
            + appl("PIN \u000Bfalsch \u000Boder \u000Bgesperrt!");
    String cmd = "520f" + "0206" + "0020000108ffffffffffffffff";
    List<String> commands =
        Kartos.kt.wire().stream()
            .filter(
                l ->
                    l.contains("\"dir\":\"in\"")
                        && l.contains("\"fu\":\"0x0000\"")
                        && l.contains("801802d0"))
            .toList();
    assertTrue(
        !commands.isEmpty(),
        "PERFORM VERIFICATION im Wire-Trace:\n" + String.join("\n", Kartos.kt.wire()));
    String apdu = commands.getFirst().substring(commands.getFirst().indexOf("801802d0"));
    assertTrue(
        apdu.startsWith("801802d0" + "%02x".formatted((dialog + cmd).length() / 2) + dialog + cmd),
        apdu);
  }

  @Test
  @Order(3)
  @DisplayName(
      "TUC_KON_012 Fehlerfälle (7), TAB_KON_089: Abbruchtaste am KT (6401) → 4049, keine Eingabe in der Zeit "
          + "(6400) → 4043; die Karte sieht kein VERIFY, ihr Fehlbedienungszähler bleibt")
  void abbruchUndTimeout() throws Exception {
    String smcb = smcb();
    keypad("cancel");
    assertEquals("4049", faultCode(verifyPin(smcb)));
    keypad("timeout");
    assertEquals("4043", faultCode(verifyPin(smcb)));
    assertEquals("OK", xpath(ok(verifyPin(smcb)), "//*[local-name()='PinResult']"));
  }

  @Test
  @Order(4)
  @DisplayName(
      "TIP1-A_4567 / TUC_KON_012 7c: falsche PIN am KT → REJECTED mit dem LeftTries der Karte, nach der letzten "
          + "Fehleingabe NOWBLOCKED; jede weitere Eingabe, auch die richtige, → WASBLOCKED (TAB_KON_738 Schritt 5); "
          + "GetPinStatus zeigt den "
          + "Fehlbedienungszähler (VERIFIABLE 2, dann BLOCKED 0)")
  void falschePin() throws Exception {
    String smcb = smcb();
    keypad(2, "wrong", 3);
    Element first = ok(verifyPin(smcb));
    assertEquals("OK", xpath(first, "//*[local-name()='Result']"));
    assertEquals("REJECTED", xpath(first, "//*[local-name()='PinResult']"));
    assertEquals("2", xpath(first, "//*[local-name()='LeftTries']"));
    assertEquals(
        "VERIFIABLE 2", pinStatus(smcb, "PIN.SMC"), "LIANA-63: Fehlbedienungszähler der Karte");
    assertEquals("1", xpath(ok(verifyPin(smcb)), "//*[local-name()='LeftTries']"));
    Element blocked = ok(verifyPin(smcb));
    assertEquals("NOWBLOCKED", xpath(blocked, "//*[local-name()='PinResult']"));
    assertEquals("0", xpath(blocked, "count(//*[local-name()='LeftTries'])"));
    assertEquals("BLOCKED 0", pinStatus(smcb, "PIN.SMC"), "LIANA-63 TUC_KON_022 3b e");
    assertEquals("WASBLOCKED", xpath(ok(verifyPin(smcb)), "//*[local-name()='PinResult']"));
  }

  @Test
  @Order(5)
  @DisplayName(
      "LIANA-61 TIP1-A_4587 / TUC_KON_012 am HBA: VerifyPin PIN.CH mit der PIN am Keypad → PinResult OK; im "
          + "Wire-Trace PERFORM VERIFICATION an Slot 4 mit den Anzeigen aus TAB_KON_090 HBAx/PIN.CH und VERIFY P2 01")
  void hbaPinCh() throws Exception {
    Element response = ok(verifyPin(hba(), "PIN.CH"));
    assertEquals("OK", xpath(response, "//*[local-name()='PinResult']"));
    String dialog = appl("Eingabe \u000BFreigabe-PIN \u000BHBA\u000FPIN.HBA:");
    List<String> commands =
        Kartos.kt.wire().stream()
            .filter(l -> l.contains("\"dir\":\"in\"") && l.contains("801804d0"))
            .toList();
    assertTrue(
        !commands.isEmpty(),
        "PERFORM VERIFICATION an Slot 4:\n" + String.join("\n", Kartos.kt.wire()));
    String apdu = commands.getLast().substring(commands.getLast().indexOf("801804d0"));
    assertTrue(apdu.contains(dialog) && apdu.contains("0020000108ffffffffffffffff"), apdu);
  }

  @Test
  @Order(6)
  @DisplayName(
      "LIANA-61 TIP1-A_4567 / TUC_KON_012 7c am HBA: falsche PIN.CH am Keypad → REJECTED mit dem "
          + "Fehlbedienungszähler der Karte (LeftTries 2, 1), dann NOWBLOCKED; danach → WASBLOCKED; LIANA-63 GetPinStatus "
          + "PIN.CH: VERIFIABLE 2, dann BLOCKED 0")
  void hbaFalschePin() throws Exception {
    String hba = hba();
    keypad(4, "wrong", 3);
    assertEquals("2", xpath(ok(verifyPin(hba, "PIN.CH")), "//*[local-name()='LeftTries']"));
    assertEquals(
        "VERIFIABLE 2", pinStatus(hba, "PIN.CH"), "LIANA-63: Fehlbedienungszähler von PIN.CH");
    assertEquals("1", xpath(ok(verifyPin(hba, "PIN.CH")), "//*[local-name()='LeftTries']"));
    assertEquals(
        "NOWBLOCKED", xpath(ok(verifyPin(hba, "PIN.CH")), "//*[local-name()='PinResult']"));
    assertEquals("BLOCKED 0", pinStatus(hba, "PIN.CH"));
    assertEquals(
        "WASBLOCKED", xpath(ok(verifyPin(hba, "PIN.CH")), "//*[local-name()='PinResult']"));
  }

  private static ValidatableResponse post(
      String operation, String cardHandle, String pinTyp, String extra) {
    String body =
        """
                <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body>\
                <ns2:%1$s xmlns:ns2="%2$s" xmlns:ns3="http://ws.gematik.de/conn/ConnectorCommon/v5.0" \
                xmlns:ns6="http://ws.gematik.de/conn/ConnectorContext/v2.0">\
                <ns6:Context><ns3:MandantId>M1</ns3:MandantId><ns3:ClientSystemId>CS1</ns3:ClientSystemId>\
                <ns3:WorkplaceId>WP1</ns3:WorkplaceId></ns6:Context><ns3:CardHandle>%3$s</ns3:CardHandle>\
                <ns4:PinTyp xmlns:ns4="http://ws.gematik.de/conn/CardServiceCommon/v2.0">%4$s</ns4:PinTyp>%5$s\
                </ns2:%1$s></SOAP-ENV:Body></SOAP-ENV:Envelope>"""
            .formatted(operation, NS, cardHandle, pinTyp, extra);
    return given()
        .contentType("text/xml; charset=utf-8")
        .header("SOAPAction", "\"" + NS + "#" + operation + "\"")
        .body(body)
        .post("/ws/CardService")
        .then();
  }

  /** The next {@code times} entries at the keypad of slot 2: {@code pin} (outcome digits). */
  private static void digits(String pin, int times) {
    Kartos.kt.pinScript(
        java.util.stream.Stream.generate(
                () -> "{\"outcome\":\"digits\",\"pin\":\"" + pin + "\",\"slotNo\":2}")
            .limit(times)
            .collect(java.util.stream.Collectors.joining(",", "[", "]")));
  }

  /**
   * Hex of the SICCT commands to FU 0 that begin with {@code prefix}, from the kartos wire trace.
   */
  private static List<String> terminalCommands(String prefix) {
    return Kartos.kt.wire().stream()
        .filter(
            l ->
                l.contains("\"dir\":\"in\"")
                    && l.contains("\"fu\":\"0x0000\"")
                    && l.contains(prefix))
        .map(l -> l.substring(l.indexOf(prefix)))
        .toList();
  }

  /** LIANA/DEVIATION entries in the Systemprotokoll (LIANA-126). */
  private List<SystemLog.Entry> deviationLog() {
    return systemLog.entries(null, null).stream()
        .filter(e -> e.topic().equals(PeerDeviations.TOPIC))
        .toList();
  }

  @Inject SystemLog systemLog;

  @Inject PeerDeviations deviations;

  @Test
  @Order(7)
  @DisplayName(
      "LIANA-127 TUC_KON_021 7b gegen kartos terminal 0.8.0, strict=false: UnblockPin PIN.SMC (gesperrt) mit "
          + "SetNewPin – LIANA sendet zuerst 80 19 nach SICCT §5.20 (CMD DO 02 06 0E, RESET RETRY COUNTER), kartos "
          + "antwortet 6700; Deviation KARTOS_MODIFY_VERIFICATION_DATA im Systemprotokoll als Warning, dann 80 1A mit "
          + "PinFormat-DO 5F2F → OK, die neue PIN gilt")
  void unblockKartos() throws Exception {
    String smcb = smcb();
    assertEquals("BLOCKED 0", pinStatus(smcb, "PIN.SMC"));
    digits("12345678", 2);
    Element response =
        ok(post("UnblockPin", smcb, "PIN.SMC", "<ns2:SetNewPin>true</ns2:SetNewPin>"));
    assertEquals("OK", xpath(response, "//*[local-name()='PinResult']"), Kartos.kt.log());
    assertEquals("VERIFIABLE 3", pinStatus(smcb, "PIN.SMC"));
    digits("654321", 1);
    assertEquals(
        "OK", xpath(ok(verifyPin(smcb)), "//*[local-name()='PinResult']"), "neue PIN 654321");

    assertTrue(
        terminalCommands("801902d0").getLast().contains("5218" + "02060e" + "002c000110"),
        "nach Spec:\n" + String.join("\n", Kartos.kt.wire()));
    assertTrue(
        terminalCommands("801a02d0")
            .getLast()
            .contains("5f2f0602080102040c" + "5215" + "002c000110"),
        "kartos-Format:\n" + String.join("\n", Kartos.kt.wire()));
    SystemLog.Entry entry = deviationLog().getLast();
    assertEquals(SystemLog.Type.OP, entry.type());
    assertEquals(SystemLog.Severity.WARN, entry.severity());
    assertEquals("KARTOS_MODIFY_VERIFICATION_DATA", entry.parameters().get("Deviation"));
    assertEquals("KT-01", entry.parameters().get("Peer"));
    assertEquals("6700", entry.parameters().get("StatusWord"));
  }

  @Test
  @Order(8)
  @DisplayName(
      "LIANA-127 TUC_KON_019 7b gegen kartos terminal 0.8.0, strict=false: ChangePin PIN.SMC – 80 19 nach Spec, "
          + "6700, Warning im Systemprotokoll, 80 19 mit 5F2F → OK")
  void changeKartos() throws Exception {
    String smcb = smcb();
    int before = deviationLog().size();
    digits("654321", 2);
    assertEquals(
        "OK", xpath(ok(post("ChangePin", smcb, "PIN.SMC", "")), "//*[local-name()='PinResult']"));
    List<String> modify = terminalCommands("801902d0");
    assertTrue(modify.get(modify.size() - 2).contains("02060e" + "0024000110"), modify.toString());
    assertTrue(
        modify.getLast().contains("5f2f06" + "02080102040c" + "5215" + "0024000110"),
        modify.toString());
    assertEquals(before + 1, deviationLog().size());
    assertEquals(SystemLog.Severity.WARN, deviationLog().getLast().severity());
  }

  @Test
  @Order(9)
  @DisplayName(
      "LIANA-127 gegen kartos terminal 0.8.0, strict=true: ChangePin PIN.SMC scheitert nach dem Kommando nach "
          + "Spec mit 4044 (Zugriff auf das Kartenterminal, TUC_KON_019); Systemprotokoll mit Error-Eintrag, kein "
          + "zweites Kommando")
  void changeKartosStrict() throws Exception {
    String smcb = smcb();
    int commands = terminalCommands("801902d0").size();
    deviations.setStrict(true);
    try {
      digits("654321", 1);
      assertEquals("4044", faultCode(post("ChangePin", smcb, "PIN.SMC", "")));
    } finally {
      deviations.reset();
    }
    assertEquals(commands + 1, terminalCommands("801902d0").size());
    SystemLog.Entry entry = deviationLog().getLast();
    assertEquals(SystemLog.Severity.ERR, entry.severity());
    assertEquals("abgewiesen (strict)", entry.parameters().get("Action"));
    digits("654321", 1);
    assertEquals(
        "OK",
        xpath(ok(verifyPin(smcb)), "//*[local-name()='PinResult']"),
        "die Karte hat kein Kommando gesehen, PIN 654321 gilt");
  }

  @Test
  @Order(10)
  @DisplayName(
      "LIANA-67 decision-12: ein CATS-Terminal auf einem eHealth-KT (KT-01 ist hier SICCT) antwortet 501 mit "
          + "Pfad, Weiterleitung an kartos ist LIANA-93")
  void catsAufSicctKt() throws Exception {
    String hba = hba();
    given()
        .port(admin.port())
        .contentType("application/json")
        .body("{\"slotNumber\":4,\"inserted\":false}")
        .post("/cats/KT-01/config/card/insert")
        .then()
        .statusCode(501)
        .body(org.hamcrest.Matchers.containsString("POST /cats/KT-01/config/card/insert"));
    given().port(admin.port()).post("/cats/KT-01/config/card/slots/reset").then().statusCode(501);
    assertEquals(
        hba, cards.card("KT-01", 4).orElseThrow().cardHandle(), "die Karte bleibt gesteckt");
  }
}

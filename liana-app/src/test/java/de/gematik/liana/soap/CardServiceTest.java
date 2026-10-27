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
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.adapter.fake.FakeTerminals;
import de.gematik.liana.adapter.fake.Fault;
import de.gematik.liana.admin.AdminServer;
import de.gematik.liana.crypto.ReplaySigner;
import de.gematik.liana.crypto.ReplaySigner.Profile;
import de.gematik.liana.kern.card.CardList;
import de.gematik.liana.sds.XsdValidator;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.path.xml.XmlPath;
import io.restassured.response.ValidatableResponse;
import jakarta.inject.Inject;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;

/**
 * CardService v8.2 (PoPP tunnel) against the YAML state with the recorded egk-valid
 * (RecordedCardEngine): after the reset of the card session it answers SELECT MF and READ BINARY
 * EF.Version2 as recorded, everything else with 6D00. Each test ends its session, the card is free
 * again afterwards.
 */
@QuarkusTest
class CardServiceTest {

  private static final String NS = "http://ws.gematik.de/conn/CardService/v8.2";
  private static final String SCHEMA = "conn/CardService_v8_2_1.xsd";

  @Inject CardList cards;

  @Inject FakeTerminals terminals;

  @Inject AdminServer admin;

  @AfterEach
  void stoerungenLoeschen() {
    terminals.terminal("KT-01").clearFault(1);
    terminals.terminal("KT-01").clearFault(2);
  }

  private void stoerung(int slot, Fault fault) {
    terminals.terminal("KT-01").fault(slot, fault);
  }

  private static void stop(String sessionId, String code) throws Exception {
    fault(post("StopCardSession", "<ns2:SessionId>" + sessionId + "</ns2:SessionId>"), code);
  }

  private static ValidatableResponse post(String operation, String inner) {
    return post(NS, operation, inner);
  }

  private static ValidatableResponse post(String namespace, String operation, String inner) {
    String body =
        """
                <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body>\
                <ns2:%1$s xmlns:ns2="%2$s" xmlns:ns3="http://ws.gematik.de/conn/ConnectorCommon/v5.0" \
                xmlns:ns6="http://ws.gematik.de/conn/ConnectorContext/v2.0">%3$s</ns2:%1$s></SOAP-ENV:Body></SOAP-ENV:Envelope>"""
            .formatted(operation, namespace, inner);
    return given()
        .contentType("text/xml; charset=utf-8")
        .header("SOAPAction", "\"" + namespace + "#" + operation + "\"")
        .body(body)
        .post("/ws/CardService")
        .then();
  }

  private String start() throws Exception {
    String xml =
        post(
                "StartCardSession",
                """
                <ns6:Context><ns3:MandantId>M1</ns3:MandantId><ns3:ClientSystemId>CS1</ns3:ClientSystemId>\
                <ns3:WorkplaceId>WP1</ns3:WorkplaceId></ns6:Context><ns3:CardHandle>%s</ns3:CardHandle>"""
                    .formatted(cards.card("KT-01", 1).orElseThrow().cardHandle()))
            .statusCode(200)
            .extract()
            .asString();
    Element response = bodyElement(xml);
    XsdValidator.validate(SCHEMA, serialize(response));
    assertEquals("OK", xpath(response, "//*[local-name()='Result']"));
    return xpath(response, "//*[local-name()='SessionId']");
  }

  private static ValidatableResponse secureSend(
      String sessionId, int counter, int timeSpan, String steps) throws Exception {
    String jws =
        ReplaySigner.sign(
            """
                {"type":"StandardScenario","version":"1.0.0","clientSessionId":"%s","sequenceCounter":%d,\
                "timeSpan":%d,"steps":[%s]}"""
                .formatted(sessionId, counter, timeSpan, steps));
    return post("SecureSendAPDU", "<ns2:SignedScenario>" + jws + "</ns2:SignedScenario>");
  }

  private static Element fault(ValidatableResponse response, String code) throws Exception {
    Element fault = bodyElement(response.statusCode(500).extract().asString());
    assertEquals(code, xpath(fault, "//*[local-name()='Code']"));
    return fault;
  }

  @Test
  @DisplayName(
      "A_25970-01 / A_25822-02 / A_26022: Start, SecureSendAPDU (Szenario 0), Stop; Antworten gegen CardService_v8_2_1.xsd")
  void tunnel() throws Exception {
    String sessionId = start();
    assertEquals(sessionId, UUID.fromString(sessionId).toString());

    String xml =
        secureSend(
                sessionId,
                0,
                10000,
                """
                {"commandApdu":"00A4040C07d2760001448000","expectedStatusWords":["9000"]},\
                {"commandApdu":"00B0910000","expectedStatusWords":["9000","6281"]}""")
            .statusCode(200)
            .extract()
            .asString();
    Element response = bodyElement(xml);
    XsdValidator.validate(SCHEMA, serialize(response));
    assertEquals("OK", xpath(response, "//*[local-name()='Result']"));
    assertEquals("2", xpath(response, "count(//*[local-name()='ResponseApdu'])"));
    assertEquals("9000", xpath(response, "//*[local-name()='ResponseApdu'][1]"));
    assertTrue(
        xpath(response, "//*[local-name()='ResponseApdu'][2]").startsWith("EF2BC003020000C10304"));
    assertEquals("10000", xpath(response, "//*[local-name()='TimeSpan']"));

    String stop =
        post("StopCardSession", "<ns2:SessionId>" + sessionId + "</ns2:SessionId>")
            .statusCode(200)
            .extract()
            .asString();
    XsdValidator.validate(SCHEMA, serialize(bodyElement(stop)));
  }

  @Test
  @DisplayName(
      "TUC_KON_208: unerwartetes Statuswort → Status Warning mit GERROR 4284; TimeSpan 0 beendet die Sitzung → Stop 4288")
  void warnungUndLetztesSzenario() throws Exception {
    String sessionId = start();
    String xml =
        secureSend(
                sessionId,
                0,
                0,
                """
                {"commandApdu":"00B0870000","expectedStatusWords":["9000","6281"]},\
                {"commandApdu":"00B0860000","expectedStatusWords":["9000","6281"]}""")
            .statusCode(200)
            .extract()
            .asString();
    Element response = bodyElement(xml);
    XsdValidator.validate(SCHEMA, serialize(response));
    assertEquals("Warning", xpath(response, "//*[local-name()='Result']"));
    assertEquals("4284", xpath(response, "//*[local-name()='Status']//*[local-name()='Code']"));
    assertEquals(
        "Warning", xpath(response, "//*[local-name()='Status']//*[local-name()='Severity']"));
    assertEquals("6D00", xpath(response, "//*[local-name()='ResponseApdu']"));
    assertEquals("1", xpath(response, "count(//*[local-name()='ResponseApdu'])"));
    assertEquals("0", xpath(response, "//*[local-name()='TimeSpan']"));

    Element fault =
        fault(post("StopCardSession", "<ns2:SessionId>" + sessionId + "</ns2:SessionId>"), "4288");
    assertEquals("Unbekannte Session ID", xpath(fault, "faultstring"));
  }

  @Test
  @DisplayName(
      "A_26069-01 TUC_KON_208 Schritt 2: expectedStatusWords umbenannt in expectedStatus (wie "
          + "EE_KON_POPP_FF_014) → SOAP-Fault 4286; die Sitzung bleibt, derselbe sequenceCounter wird danach angenommen")
  void szenarioUngueltig() throws Exception {
    String sessionId = start();
    Element fault =
        fault(
            secureSend(
                sessionId,
                0,
                10000,
                "{\"commandApdu\":\"00B0910000\",\"expectedStatus\":[\"9000\"]}"),
            "4286");
    XsdValidator.validate(
        "tel/error/TelematikError.xsd",
        serialize(
            (Element)
                XPathFactory.newInstance()
                    .newXPath()
                    .evaluate("detail/*", fault, XPathConstants.NODE)));
    String xml =
        secureSend(
                sessionId,
                0,
                10000,
                "{\"commandApdu\":\"00B0910000\",\"expectedStatusWords\":[\"9000\"]}")
            .statusCode(200)
            .extract()
            .asString();
    assertEquals("OK", xpath(bodyElement(xml), "//*[local-name()='Result']"));
    fault(secureSend(sessionId, 1, 0, "{\"commandApdu\":\"00B0910000\"}"), "4286");
    post("StopCardSession", "<ns2:SessionId>" + sessionId + "</ns2:SessionId>").statusCode(200);
  }

  @Test
  @DisplayName(
      "TUC_KON_208: Szenario ohne Schritte (steps: []) → Status OK, leere ResponseApduList gegen "
          + "CardService_v8_2_1.xsd, nächster sequenceCounter; TimeSpan 0 beendet die Sitzung")
  void ohneSchritte() throws Exception {
    String sessionId = start();
    Element response =
        bodyElement(secureSend(sessionId, 0, 10000, "").statusCode(200).extract().asString());
    XsdValidator.validate(SCHEMA, serialize(response));
    assertEquals("OK", xpath(response, "//*[local-name()='Result']"));
    assertEquals("0", xpath(response, "count(//*[local-name()='ResponseApdu'])"));
    secureSend(sessionId, 1, 0, "").statusCode(200);
    fault(post("StopCardSession", "<ns2:SessionId>" + sessionId + "</ns2:SessionId>"), "4288");
  }

  @Test
  @DisplayName(
      "A_25895: zweite StartCardSession auf dieselbe eGK während laufender Sitzung → SOAP-Fault 4093")
  void exklusiv() throws Exception {
    String sessionId = start();
    try {
      fault(
          post(
              "StartCardSession",
              """
                    <ns6:Context><ns3:MandantId>M1</ns3:MandantId><ns3:ClientSystemId>CS1</ns3:ClientSystemId>\
                    <ns3:WorkplaceId>WP1</ns3:WorkplaceId></ns6:Context><ns3:CardHandle>%s</ns3:CardHandle>"""
                  .formatted(cards.card("KT-01", 1).orElseThrow().cardHandle())),
          "4093");
    } finally {
      post("StopCardSession", "<ns2:SessionId>" + sessionId + "</ns2:SessionId>").statusCode(200);
    }
  }

  @Test
  @DisplayName(
      "TAB_KON_272 4700: Signer mit Rolle oid_popp-token (wie EE_KON_POPP_FF_013) → SOAP-Fault mit Text "
          + "laut Spec, GERROR gegen TelematikError.xsd; die Sitzung bleibt, StopCardSession → OK")
  void signerOhneOidPopp() throws Exception {
    String sessionId = start();
    var poppToken = ReplaySigner.issue(Profile.poppService().withRole(ReplaySigner.OID_POPP_TOKEN));
    String jws =
        ReplaySigner.sign(
            poppToken,
            """
                {"type":"StandardScenario","version":"1.0.0","clientSessionId":"%s","sequenceCounter":0,\
                "timeSpan":0,"steps":[{"commandApdu":"00B0910000","expectedStatusWords":["9000"]}]}"""
                .formatted(sessionId));
    Element fault =
        fault(
            post("SecureSendAPDU", "<ns2:SignedScenario>" + jws + "</ns2:SignedScenario>"), "4700");
    assertEquals("Zertifikat enthält nicht die erwartete Rolle", xpath(fault, "faultstring"));
    assertEquals("Security", xpath(fault, "//*[local-name()='ErrorType']"));
    XsdValidator.validate(
        "tel/error/TelematikError.xsd",
        serialize(
            (Element)
                XPathFactory.newInstance()
                    .newXPath()
                    .evaluate("detail/*", fault, XPathConstants.NODE)));
    post("StopCardSession", "<ns2:SessionId>" + sessionId + "</ns2:SessionId>").statusCode(200);
  }

  @Test
  @DisplayName(
      "TAB_KON_272 / TUC_KON_208: Signatur ungültig → 4701, falscher sequenceCounter → 4285, unbekanntes Handle → 4008")
  void fehler() throws Exception {
    String sessionId = start();
    String jws =
        ReplaySigner.sign(
            """
                {"type":"StandardScenario","version":"1.0.0","clientSessionId":"%s","sequenceCounter":0,\
                "timeSpan":0,"steps":[{"commandApdu":"00B0910000","expectedStatusWords":["9000"]}]}"""
                .formatted(sessionId));
    String forged = jws.substring(0, jws.length() - 4) + (jws.endsWith("AAAA") ? "BBBB" : "AAAA");
    fault(
        post("SecureSendAPDU", "<ns2:SignedScenario>" + forged + "</ns2:SignedScenario>"), "4701");
    fault(
        secureSend(
            sessionId, 1, 0, "{\"commandApdu\":\"00B0910000\",\"expectedStatusWords\":[\"9000\"]}"),
        "4285");
    fault(post("StopCardSession", "<ns2:SessionId>" + sessionId + "</ns2:SessionId>"), "4288");
    fault(
        post(
            "StartCardSession",
            """
                <ns6:Context><ns3:MandantId>M1</ns3:MandantId><ns3:ClientSystemId>CS1</ns3:ClientSystemId>\
                <ns3:WorkplaceId>WP1</ns3:WorkplaceId></ns6:Context><ns3:CardHandle>EGK-24</ns3:CardHandle>"""),
        "4008");
    post("GetCards", "")
        .statusCode(500)
        .body(containsString("GetCards wird von LIANA nicht unterstützt"));
  }

  private static ValidatableResponse verifyPin(String cardHandle, String pinTyp) {
    return post(
        "VerifyPin",
        """
                <ns6:Context><ns3:MandantId>M1</ns3:MandantId><ns3:ClientSystemId>CS1</ns3:ClientSystemId>\
                <ns3:WorkplaceId>WP1</ns3:WorkplaceId></ns6:Context><ns3:CardHandle>%s</ns3:CardHandle>\
                <ns4:PinTyp xmlns:ns4="http://ws.gematik.de/conn/CardServiceCommon/v2.0">%s</ns4:PinTyp>"""
            .formatted(cardHandle, pinTyp));
  }

  @Test
  @DisplayName(
      "TIP1-A_4587 VerifyPin PIN.SMC der SMC-B (wie der popp-client für ZETA): Status OK, PinResult OK; "
          + "Antwort gegen CardService_v8_2_1.xsd")
  void verifyPinSmcb() throws Exception {
    String smcb = cards.card("KT-01", 2).orElseThrow().cardHandle();
    Element response = bodyElement(verifyPin(smcb, "PIN.SMC").statusCode(200).extract().asString());
    XsdValidator.validate(SCHEMA, serialize(response));
    assertEquals("OK", xpath(response, "//*[local-name()='Result']"));
    assertEquals("OK", xpath(response, "//*[local-name()='PinResult']"));
    assertEquals("0", xpath(response, "count(//*[local-name()='LeftTries'])"));
  }

  @Test
  @DisplayName(
      "LIANA-61 TIP1-A_4587: VerifyPin PIN.CH des HBA (KT-01/3) → Status OK, PinResult OK; PIN.SMC auf dem "
          + "HBA → 4000; Antwort gegen CardService_v8_2_1.xsd")
  void verifyPinHba() throws Exception {
    String hba = cards.card("KT-01", 3).orElseThrow().cardHandle();
    Element response = bodyElement(verifyPin(hba, "PIN.CH").statusCode(200).extract().asString());
    XsdValidator.validate(SCHEMA, serialize(response));
    assertEquals("OK", xpath(response, "//*[local-name()='PinResult']"));
    fault(verifyPin(hba, "PIN.SMC"), "4000");
  }

  @Test
  @DisplayName(
      "TAB_KON_047: VerifyPin auf der eGK → 4209, PIN.CH auf SM-B → 4000, unbekanntes Handle → 4008")
  void verifyPinFehler() throws Exception {
    String egk = cards.card("KT-01", 1).orElseThrow().cardHandle();
    String smcb = cards.card("KT-01", 2).orElseThrow().cardHandle();
    fault(verifyPin(egk, "PIN.SMC"), "4209");
    fault(verifyPin(smcb, "PIN.CH"), "4000");
    fault(verifyPin("SMC-B-99", "PIN.SMC"), "4008");
  }

  @Test
  @DisplayName(
      "LIANA-106/LIANA-120 TIP1-A_4586-04: ein 8.1-Client (ti-CLI, konnektor-service-client der eHealth-KT-"
          + "Suite) findet CardService 8.1.2 in connector.sds (TIP1-A_4966) und ruft VerifyPin und GetPinStatus in "
          + "v8.1 → Antwort im Namensraum v8.1, gültig gegen CardService_v8_1_3.xsd; den PoPP-Tunnel gibt es erst "
          + "ab v8.2.0 → SOAP-Fault")
  void cardServiceV81() throws Exception {
    // Selection as in gemILF_PS 9.2.2: same major and minor version, highest revision
    XmlPath sds =
        new XmlPath(given().get("/connector.sds").then().statusCode(200).extract().asString());
    String card =
        "ConnectorServices.ServiceInformation.Service.find { it.@Name == 'CardService' }.Versions.Version";
    List<String> versions81 =
        sds.<String>getList(card + ".@Version").stream()
            .filter(v -> v.startsWith("8.1."))
            .sorted()
            .toList();
    String chosen = versions81.getLast();
    assertEquals("8.1.2", chosen);
    String v81 = sds.getString(card + ".find { it.@Version == '" + chosen + "' }.@TargetNamespace");
    assertEquals("http://ws.gematik.de/conn/CardService/v8.1", v81);
    assertTrue(
        sds.getString(card + ".find { it.@Version == '" + chosen + "' }.Endpoint.@Location")
            .endsWith("/ws/CardService"));
    String smcb = cards.card("KT-01", 2).orElseThrow().cardHandle();
    String pin =
        """
                <ns6:Context><ns3:MandantId>M1</ns3:MandantId><ns3:ClientSystemId>CS1</ns3:ClientSystemId>\
                <ns3:WorkplaceId>WP1</ns3:WorkplaceId></ns6:Context><ns3:CardHandle>%s</ns3:CardHandle>\
                <ns4:PinTyp xmlns:ns4="http://ws.gematik.de/conn/CardServiceCommon/v2.0">PIN.SMC</ns4:PinTyp>"""
            .formatted(smcb);
    Element verify = bodyElement(post(v81, "VerifyPin", pin).statusCode(200).extract().asString());
    XsdValidator.validate("conn/CardService_v8_1_3.xsd", serialize(verify));
    assertEquals(v81, verify.getNamespaceURI());
    assertEquals("OK", xpath(verify, "//*[local-name()='PinResult']"));
    Element status =
        bodyElement(post(v81, "GetPinStatus", pin).statusCode(200).extract().asString());
    XsdValidator.validate("conn/CardService_v8_1_3.xsd", serialize(status));
    assertEquals(v81, status.getNamespaceURI());

    post(v81, "StartCardSession", "").statusCode(500).body(containsString("passt nicht zu"));
  }

  private static ValidatableResponse getPinStatus(String cardHandle, String pinTyp) {
    return post(
        "GetPinStatus",
        """
                <ns6:Context><ns3:MandantId>M1</ns3:MandantId><ns3:ClientSystemId>CS1</ns3:ClientSystemId>\
                <ns3:WorkplaceId>WP1</ns3:WorkplaceId></ns6:Context><ns3:CardHandle>%s</ns3:CardHandle>\
                <ns4:PinTyp xmlns:ns4="http://ws.gematik.de/conn/CardServiceCommon/v2.0">%s</ns4:PinTyp>"""
            .formatted(cardHandle, pinTyp));
  }

  /**
   * After newly inserted cards: YAML state with the order of the card list for the remaining tests.
   */
  private void yamlStand() {
    given().port(admin.port()).post("/admin/reset").then().statusCode(200);
  }

  /**
   * Re-inserts {@code image} into KT-01/{@code slot}: new CardHandle, empty card session
   * (AUTHSTATE).
   */
  private String neuStecken(int slot, String image) throws InterruptedException {
    String before = cards.card("KT-01", slot).map(c -> c.cardHandle()).orElse(null);
    terminals.put("KT-01", slot, image);
    long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
    while (cards
        .card("KT-01", slot)
        .map(c -> c.cardHandle())
        .filter(h -> !h.equals(before))
        .isEmpty()) {
      assertTrue(System.nanoTime() < deadline, "neues CardHandle in KT-01/" + slot);
      Thread.sleep(20);
    }
    return cards.card("KT-01", slot).orElseThrow().cardHandle();
  }

  @Test
  @DisplayName(
      "TIP1-A_4589 / TUC_KON_022: GetPinStatus PIN.SMC der frisch gesteckten SMC-B → VERIFIABLE mit LeftTries "
          + "3 (GET PIN STATUS wie von kartos aufgezeichnet), nach VerifyPin → VERIFIED aus AUTHSTATE; Antworten gegen "
          + "CardService_v8_2_1.xsd")
  void getPinStatusSmcb() throws Exception {
    try {
      String smcb = neuStecken(2, "smcb-valid");
      Element response =
          bodyElement(getPinStatus(smcb, "PIN.SMC").statusCode(200).extract().asString());
      XsdValidator.validate(SCHEMA, serialize(response));
      assertEquals("OK", xpath(response, "//*[local-name()='Result']"));
      assertEquals("VERIFIABLE", xpath(response, "//*[local-name()='PinStatus']"));
      assertEquals("3", xpath(response, "//*[local-name()='LeftTries']"));

      verifyPin(smcb, "PIN.SMC").statusCode(200);
      Element verified =
          bodyElement(getPinStatus(smcb, "PIN.SMC").statusCode(200).extract().asString());
      XsdValidator.validate(SCHEMA, serialize(verified));
      assertEquals("VERIFIED", xpath(verified, "//*[local-name()='PinStatus']"));
      assertEquals("0", xpath(verified, "count(//*[local-name()='LeftTries'])"));
    } finally {
      yamlStand();
    }
  }

  @Test
  @DisplayName(
      "TIP1-A_4589 / TUC_KON_022: GetPinStatus PIN.CH des frisch gesteckten HBA → VERIFIABLE mit LeftTries 3")
  void getPinStatusHba() throws Exception {
    try {
      String hba = neuStecken(3, "hba-valid");
      Element response =
          bodyElement(getPinStatus(hba, "PIN.CH").statusCode(200).extract().asString());
      XsdValidator.validate(SCHEMA, serialize(response));
      assertEquals("VERIFIABLE", xpath(response, "//*[local-name()='PinStatus']"));
      assertEquals("3", xpath(response, "//*[local-name()='LeftTries']"));
    } finally {
      yamlStand();
    }
  }

  @Test
  @DisplayName(
      "TAB_KON_549: GetPinStatus PIN.SMC auf der eGK → 4000 (TAB_KON_051, LIANA-109), PIN.CH auf SM-B → 4000, "
          + "unbekanntes Handle → 4008, "
          + "IO-Fehler am KT (Störung io-error) → 4044")
  void getPinStatusFehler() throws Exception {
    try {
      String egk = cards.card("KT-01", 1).orElseThrow().cardHandle();
      String smcb = neuStecken(2, "smcb-valid");
      fault(getPinStatus(egk, "PIN.SMC"), "4000");
      fault(getPinStatus(smcb, "PIN.CH"), "4000");
      fault(getPinStatus("SMC-B-99", "PIN.SMC"), "4008");
      stoerung(2, Fault.ioError());
      fault(getPinStatus(smcb, "PIN.SMC"), "4044");
    } finally {
      yamlStand();
    }
  }

  @Test
  @DisplayName(
      "A_26069-01 TUC_KON_208 Schritt 6a: Karte antwortet auf READ BINARY mit 6A82 (Störung status-word, "
          + "LIANA-41) → Status Warning 4284, Antwortliste bis einschließlich der gestörten APDU")
  void stoerungStatuswort() throws Exception {
    String sessionId = start();
    stoerung(1, Fault.statusWord("6A82").onlyFor("00B0").times(1));
    Element response =
        bodyElement(
            secureSend(
                    sessionId,
                    0,
                    10000,
                    """
                {"commandApdu":"00A4040C07D2760001448000","expectedStatusWords":["9000"]},\
                {"commandApdu":"00B0910000","expectedStatusWords":["9000"]},\
                {"commandApdu":"00B0910000","expectedStatusWords":["9000"]}""")
                .statusCode(200)
                .extract()
                .asString());
    XsdValidator.validate(SCHEMA, serialize(response));
    assertEquals("Warning", xpath(response, "//*[local-name()='Result']"));
    assertEquals("4284", xpath(response, "//*[local-name()='Status']//*[local-name()='Code']"));
    assertEquals("2", xpath(response, "count(//*[local-name()='ResponseApdu'])"));
    assertEquals("9000", xpath(response, "//*[local-name()='ResponseApdu'][1]"));
    assertEquals("6A82", xpath(response, "//*[local-name()='ResponseApdu'][2]"));
    post("StopCardSession", "<ns2:SessionId>" + sessionId + "</ns2:SessionId>").statusCode(200);
  }

  @Test
  @DisplayName(
      "TUC_KON_223 / TUC_KON_200: IO-Fehler am KT (Störung io-error, LIANA-41) → StartCardSession 4044; "
          + "während der Sitzung → SecureSendAPDU 4044, die Sitzung ist beendet (Stop 4288)")
  void stoerungIoFehlerTunnel() throws Exception {
    stoerung(1, Fault.ioError().times(1));
    fault(
        post(
            "StartCardSession",
            """
                <ns6:Context><ns3:MandantId>M1</ns3:MandantId><ns3:ClientSystemId>CS1</ns3:ClientSystemId>\
                <ns3:WorkplaceId>WP1</ns3:WorkplaceId></ns6:Context><ns3:CardHandle>%s</ns3:CardHandle>"""
                .formatted(cards.card("KT-01", 1).orElseThrow().cardHandle())),
        "4044");

    String sessionId = start();
    stoerung(1, Fault.ioError().onlyFor("00B0"));
    fault(
        secureSend(
            sessionId,
            0,
            10000,
            """
                {"commandApdu":"00A4040C07D2760001448000","expectedStatusWords":["9000"]},\
                {"commandApdu":"00B0910000","expectedStatusWords":["9000"]}"""),
        "4044");
    stop(sessionId, "4288");
  }

  @Test
  @DisplayName(
      "TUC_KON_200 / TAB_KON_554: Karte antwortet nicht innerhalb von CARD_TIMEOUT_CARD (Test 1 s, Störung "
          + "delay 3 s, LIANA-41) → SecureSendAPDU 4094, die Sitzung ist beendet (Stop 4288)")
  void stoerungVerzoegerung() throws Exception {
    String sessionId = start();
    stoerung(1, Fault.delay(Duration.ofSeconds(3)));
    long begin = System.nanoTime();
    Element fault =
        fault(
            secureSend(
                sessionId,
                0,
                10000,
                "{\"commandApdu\":\"00B0910000\",\"expectedStatusWords\":[\"9000\"]}"),
            "4094");
    assertEquals("Timeout beim Kartenzugriff aufgetreten", xpath(fault, "faultstring"));
    long millis = Duration.ofNanos(System.nanoTime() - begin).toMillis();
    assertTrue(millis >= 1000 && millis < 3000, millis + " ms");
    stop(sessionId, "4288");
  }

  @Test
  @DisplayName(
      "TUC_KON_012 Schritt 7b: IO-Fehler am KT (Störung io-error, LIANA-41) → VerifyPin 4044")
  void stoerungVerifyPin() throws Exception {
    stoerung(2, Fault.ioError());
    fault(verifyPin(cards.card("KT-01", 2).orElseThrow().cardHandle(), "PIN.SMC"), "4044");
  }
}

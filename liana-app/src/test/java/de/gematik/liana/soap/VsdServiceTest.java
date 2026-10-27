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
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.admin.AdminServer;
import de.gematik.liana.kern.card.CardList;
import de.gematik.liana.sds.XsdValidator;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.ValidatableResponse;
import jakarta.inject.Inject;
import java.io.ByteArrayInputStream;
import java.nio.charset.Charset;
import java.util.Base64;
import java.util.zip.GZIPInputStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;

/**
 * VSDService v5.2, ReadVSD (LIANA-119), with Onlineprüfung via the empty default chain (LIANA-141),
 * against the YAML state: egk-valid in KT-01/1 (the Testhub image EGK_80276883110000168584_gema5),
 * smcb-valid in KT-01/2 (RecordedCardEngine).
 */
@QuarkusTest
class VsdServiceTest {

  private static final String NS = "http://ws.gematik.de/conn/vsds/VSDService/v5.2";

  /** SOAPAction according to VSDService.wsdl, with v6.0 instead of the schema namespace v5.2. */
  private static final String SOAP_ACTION =
      "\"http://ws.gematik.de/conn/vsds/VSDService/v6.0#ReadVSD\"";

  private static final String CONTEXT =
      """
            <ns11:Context xmlns:ns11="http://ws.gematik.de/conn/ConnectorContext/v2.0" \
            xmlns:ns6="http://ws.gematik.de/conn/ConnectorCommon/v5.0"><ns6:MandantId>M1</ns6:MandantId>\
            <ns6:ClientSystemId>CS1</ns6:ClientSystemId><ns6:WorkplaceId>WP1</ns6:WorkplaceId></ns11:Context>""";

  @Inject CardList cards;

  @Inject AdminServer admin;

  static ValidatableResponse readVsd(String egk, String smcb, boolean performOnlineCheck)
      throws Exception {
    return readVsd(egk, smcb, performOnlineCheck, false);
  }

  static ValidatableResponse readVsd(
      String egk, String smcb, boolean performOnlineCheck, boolean readOnlineReceipt)
      throws Exception {
    String operation =
        """
                <VSD:ReadVSD xmlns:VSD="%s"><VSD:EhcHandle>%s</VSD:EhcHandle><VSD:HpcHandle>%s</VSD:HpcHandle>\
                <VSD:PerformOnlineCheck>%s</VSD:PerformOnlineCheck><VSD:ReadOnlineReceipt>%s</VSD:ReadOnlineReceipt>\
                %s</VSD:ReadVSD>"""
            .formatted(NS, egk, smcb, performOnlineCheck, readOnlineReceipt, CONTEXT);
    XsdValidator.validate("conn/vsds/VSDService.xsd", operation);
    return given()
        .contentType("text/xml; charset=utf-8")
        .header("SOAPAction", SOAP_ACTION)
        .body(
            "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\"><SOAP-ENV:Body>"
                + operation
                + "</SOAP-ENV:Body></SOAP-ENV:Envelope>")
        .post("/ws/VSDService")
        .then();
  }

  static void verifyPin(String cardHandle) {
    String ns = "http://ws.gematik.de/conn/CardService/v8.2";
    given()
        .contentType("text/xml; charset=utf-8")
        .header("SOAPAction", "\"" + ns + "#VerifyPin\"")
        .body(
            """
                <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body>\
                <ns2:VerifyPin xmlns:ns2="%s" xmlns:ns6="http://ws.gematik.de/conn/ConnectorCommon/v5.0">%s\
                <ns6:CardHandle>%s</ns6:CardHandle><ns4:PinTyp xmlns:ns4="http://ws.gematik.de/conn/CardServiceCommon/v2.0">\
                PIN.SMC</ns4:PinTyp></ns2:VerifyPin></SOAP-ENV:Body></SOAP-ENV:Envelope>"""
                .formatted(ns, CONTEXT, cardHandle))
        .post("/ws/CardService")
        .then()
        .statusCode(200);
  }

  @Test
  @DisplayName(
      "VSDM-A_2567 / VSDM-A_2652: ReadVSD nach VerifyPin PIN.SMC liefert PD, VD und VSD_Status, Base64 "
          + "über gzip; Antwort gegen VSDService.xsd; KVNR, Vor- und Nachname, Kostenträgerkennung")
  void readVsd() throws Exception {
    String egk = cards.card("KT-01", 1).orElseThrow().cardHandle();
    String smcb = cards.card("KT-01", 2).orElseThrow().cardHandle();
    verifyPin(smcb);

    Element response = bodyElement(readVsd(egk, smcb, false).statusCode(200).extract().asString());
    XsdValidator.validate("conn/vsds/VSDService.xsd", serialize(response));
    String pd = gunzip(xpath(response, "//*[local-name()='PersoenlicheVersichertendaten']"));
    assertTrue(pd.contains("<Versicherten_ID>X110630769</Versicherten_ID>"), pd);
    assertTrue(pd.contains("<Vorname>Dörthe Abigail</Vorname>"), pd);
    assertTrue(pd.contains("<Nachname>Dåmmer-Ørsted</Nachname>"), pd);
    String vd = gunzip(xpath(response, "//*[local-name()='AllgemeineVersicherungsdaten']"));
    assertTrue(vd.contains("<Kostentraegerkennung>109500969</Kostentraegerkennung>"), vd);
    assertEquals("0", xpath(response, "//*[local-name()='VSD_Status']/*[local-name()='Status']"));
    assertEquals("2025-04-07T10:01:58", xpath(response, "//*[local-name()='Timestamp']"));
    assertEquals("5.2.0", xpath(response, "//*[local-name()='Version']"));
  }

  @Test
  @DisplayName(
      "VSDM-A_2575 / VSDM-A_2578 / Tab_FM_VSDM_05-01: leere Kette (Standard) → VSD von der Karte und "
          + "Prüfungsnachweis Ergebnis 3 ohne Prüfziffer, gegen VSDService.xsd und Pruefungsnachweis.xsd; Stufe spec "
          + "im Systemprotokoll und in der Admin-API")
  void onlinepruefungLeereKette() throws Exception {
    String egk = cards.card("KT-01", 1).orElseThrow().cardHandle();
    String smcb = cards.card("KT-01", 2).orElseThrow().cardHandle();
    verifyPin(smcb);

    Element response =
        bodyElement(readVsd(egk, smcb, true, true).statusCode(200).extract().asString());

    XsdValidator.validate("conn/vsds/VSDService.xsd", serialize(response));
    assertTrue(
        gunzip(xpath(response, "//*[local-name()='PersoenlicheVersichertendaten']"))
            .contains("<Versicherten_ID>X110630769</Versicherten_ID>"));
    String pn = pruefungsnachweis(response);
    assertTrue(pn.contains("<E>3</E>"), pn);
    assertFalse(pn.contains("<PZ>"), pn);
    given()
        .port(admin.port())
        .get("/admin/vsdm/online-checks")
        .then()
        .statusCode(200)
        .body("sources", empty())
        .body("checks.find { it.cardHandle == '" + egk + "' }.source", equalTo("spec"))
        .body("checks.find { it.cardHandle == '" + egk + "' }.ergebnis", equalTo(3));
    given()
        .port(admin.port())
        .get("/admin/log")
        .then()
        .statusCode(200)
        .body(
            "findAll { it.topic == 'LIANA/VSDM/ONLINE_CHECK' }.last().parameters.Source",
            equalTo("spec"));
  }

  @Test
  @DisplayName(
      "VSDM-A_2579: PerformOnlineCheck=true, ReadOnlineReceipt=false → kein Prüfungsnachweis in der Antwort")
  void onlinepruefungOhneRueckgabe() throws Exception {
    String egk = cards.card("KT-01", 1).orElseThrow().cardHandle();
    String smcb = cards.card("KT-01", 2).orElseThrow().cardHandle();
    verifyPin(smcb);

    String response = readVsd(egk, smcb, true, false).statusCode(200).extract().asString();

    assertFalse(response.contains("Pruefungsnachweis"), response);
  }

  @Test
  @DisplayName(
      "decision-12 / VSDM-A_2577: ReadOnlineReceipt=true ohne Onlineprüfung (Prüfungsnachweis von der eGK) → "
          + "SOAP-ENV:Client mit Verweis auf LIANA-103")
  void pruefungsnachweisVonDerKarte() throws Exception {
    String egk = cards.card("KT-01", 1).orElseThrow().cardHandle();
    String smcb = cards.card("KT-01", 2).orElseThrow().cardHandle();

    Element fault =
        bodyElement(readVsd(egk, smcb, false, true).statusCode(500).extract().asString());

    assertEquals("SOAP-ENV:Client", xpath(fault, "faultcode"));
    assertTrue(xpath(fault, "faultstring").contains("LIANA-103"), xpath(fault, "faultstring"));
  }

  /**
   * Pruefungsnachweis from the response: Base64, gzip, validated against Pruefungsnachweis.xsd
   * (VSDM-A_2652).
   */
  static String pruefungsnachweis(Element response) throws Exception {
    try (var in =
        new GZIPInputStream(
            new ByteArrayInputStream(
                Base64.getDecoder()
                    .decode(xpath(response, "//*[local-name()='Pruefungsnachweis']"))))) {
      String xml = new String(in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
      XsdValidator.validate("fa/vsds/Pruefungsnachweis.xsd", xml);
      return xml;
    }
  }

  static String gunzip(String base64) throws Exception {
    try (var in =
        new GZIPInputStream(new ByteArrayInputStream(Base64.getDecoder().decode(base64)))) {
      return new String(in.readAllBytes(), Charset.forName("ISO-8859-15"));
    }
  }
}

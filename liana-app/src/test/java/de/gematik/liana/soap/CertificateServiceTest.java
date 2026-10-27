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
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.adapter.fake.FakeTerminals;
import de.gematik.liana.adapter.fake.Fault;
import de.gematik.liana.kern.card.CardList;
import de.gematik.liana.sds.XsdValidator;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.ValidatableResponse;
import jakarta.inject.Inject;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;

/**
 * CertificateService v6.0 against the YAML state: egk-valid in KT-01/1, smcb-valid in KT-01/2
 * (RecordedCardEngine).
 */
@QuarkusTest
class CertificateServiceTest {

  private static final String NS = "http://ws.gematik.de/conn/CertificateService/v6.0";

  @Inject CardList cards;

  @Inject FakeTerminals terminals;

  /** ReadCardCertificate like the popp-client (popp-kon-tu, request 6). */
  private static ValidatableResponse read(String cardHandle, String certRefs) {
    return readWithAction(cardHandle, certRefs, "\"" + NS + "#ReadCardCertificate\"");
  }

  /** With Crypt ({@code ECC} or {@code RSA}). */
  private static ValidatableResponse read(String cardHandle, String certRefs, String crypt) {
    String body =
        """
                <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body>\
                <ns4:ReadCardCertificate xmlns:ns2="http://ws.gematik.de/conn/ConnectorCommon/v5.0" xmlns:ns4="%s" \
                xmlns:ns5="http://ws.gematik.de/conn/ConnectorContext/v2.0"><ns2:CardHandle>%s</ns2:CardHandle>\
                <ns5:Context><ns2:MandantId>M1</ns2:MandantId><ns2:ClientSystemId>CS1</ns2:ClientSystemId>\
                <ns2:WorkplaceId>WP1</ns2:WorkplaceId></ns5:Context><ns4:CertRefList>%s</ns4:CertRefList>\
                <ns4:Crypt>%s</ns4:Crypt></ns4:ReadCardCertificate></SOAP-ENV:Body></SOAP-ENV:Envelope>"""
            .formatted(NS, cardHandle, certRefs, crypt);
    return given()
        .contentType("text/xml; charset=utf-8")
        .header("SOAPAction", "\"" + NS + "#ReadCardCertificate\"")
        .body(body)
        .post("/ws/CertificateService")
        .then();
  }

  private static ValidatableResponse readWithAction(
      String cardHandle, String certRefs, String soapAction) {
    String body =
        """
                <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body>\
                <ns4:ReadCardCertificate xmlns:ns2="http://ws.gematik.de/conn/ConnectorCommon/v5.0" xmlns:ns4="%s" \
                xmlns:ns5="http://ws.gematik.de/conn/ConnectorContext/v2.0"><ns2:CardHandle>%s</ns2:CardHandle>\
                <ns5:Context><ns2:MandantId>M1</ns2:MandantId><ns2:ClientSystemId>CS1</ns2:ClientSystemId>\
                <ns2:WorkplaceId>WP1</ns2:WorkplaceId></ns5:Context><ns4:CertRefList>%s</ns4:CertRefList>\
                </ns4:ReadCardCertificate></SOAP-ENV:Body></SOAP-ENV:Envelope>"""
            .formatted(NS, cardHandle, certRefs);
    return given()
        .contentType("text/xml; charset=utf-8")
        .header("SOAPAction", soapAction)
        .body(body)
        .post("/ws/CertificateService")
        .then();
  }

  @Test
  @DisplayName(
      "TIP1-A_4700-03 ReadCardCertificate C.AUT der SMC-B: X509DataInfo mit Issuer, Seriennummer, Subject und "
          + "Zertifikat (ECC) wie EF.C.HCI.AUT.E256; Antwort gegen CertificateService.xsd")
  void cAutDerSmcb() throws Exception {
    String smcb = cards.card("KT-01", 2).orElseThrow().cardHandle();
    Element response =
        bodyElement(
            read(smcb, "<ns4:CertRef>C.AUT</ns4:CertRef>").statusCode(200).extract().asString());
    XsdValidator.validate("conn/CertificateService.xsd", serialize(response));

    assertEquals("OK", xpath(response, "//*[local-name()='Result']"));
    assertEquals("C.AUT", xpath(response, "//*[local-name()='CertRef']"));
    var der = Base64.getDecoder().decode(xpath(response, "//*[local-name()='X509Certificate']"));
    var certificate =
        (X509Certificate)
            CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(der));
    assertEquals(
        certificate.getIssuerX500Principal().getName(),
        xpath(response, "//*[local-name()='X509IssuerName']"));
    assertEquals(
        certificate.getSerialNumber().toString(),
        xpath(response, "//*[local-name()='X509SerialNumber']"));
    assertEquals(
        certificate.getSubjectX500Principal().getName(),
        xpath(response, "//*[local-name()='X509SubjectName']"));
    assertInstanceOf(
        ECPublicKey.class, certificate.getPublicKey(), "ohne Crypt das ECC-Zertifikat");
    assertTrue(xpath(response, "//*[local-name()='X509IssuerName']").contains("CN=GEM.SMCB-CA"));
  }

  @Test
  @DisplayName(
      "LIANA-61 TIP1-A_4700-03 / TAB_KON_858: C.AUT, C.ENC und C.QES des HBA (KT-01/3) ohne Crypt als ECC, mit "
          + "Crypt RSA als R2048; C.QES aus DF.QES mit eigenem Zertifikat; Antwort gegen CertificateService.xsd")
  void hba() throws Exception {
    String hba = cards.card("KT-01", 3).orElseThrow().cardHandle();
    String refs =
        "<ns4:CertRef>C.AUT</ns4:CertRef><ns4:CertRef>C.ENC</ns4:CertRef><ns4:CertRef>C.QES</ns4:CertRef>";
    for (String crypt : new String[] {"ECC", "RSA"}) {
      Element response = bodyElement(read(hba, refs, crypt).statusCode(200).extract().asString());
      XsdValidator.validate("conn/CertificateService.xsd", serialize(response));
      assertEquals("3", xpath(response, "count(//*[local-name()='X509DataInfo'])"));
      java.util.Set<String> subjects = new java.util.HashSet<>();
      for (int i = 1; i <= 3; i++) {
        var der =
            Base64.getDecoder()
                .decode(xpath(response, "(//*[local-name()='X509Certificate'])[" + i + "]"));
        var certificate =
            (X509Certificate)
                CertificateFactory.getInstance("X.509", "BC")
                    .generateCertificate(new ByteArrayInputStream(der));
        // C.HP.QES.R2048 of the HBA …20 carries the key as id-RSASSA-PSS (like hba-g20, LIANA-197)
        String rsa = i == 3 ? "RSASSA-PSS" : "RSA";
        assertEquals(
            crypt.equals("ECC") ? "EC" : rsa,
            certificate.getPublicKey().getAlgorithm(),
            crypt + " " + i);
        assertTrue(
            certificate
                .getSubjectX500Principal()
                .getName()
                .contains("CN=Maximilian PopówitschTEST-ONLY"));
        subjects.add(
            certificate.getIssuerX500Principal().getName() + certificate.getSerialNumber());
      }
      assertEquals(3, subjects.size(), "drei verschiedene Zertifikate");
      assertEquals("C.QES", xpath(response, "(//*[local-name()='CertRef'])[3]"));
      assertTrue(
          xpath(response, "(//*[local-name()='X509IssuerName'])[3]").contains("HBA-qCA"),
          xpath(response, "(//*[local-name()='X509IssuerName'])[3]"));
    }
  }

  @Test
  @DisplayName(
      "Maßgeblich ist der Body: popp-client 2.9.0 schickt die SOAPAction CertificateService/v8.2#ReadCardCertificate "
          + "zu einem v6.0-Body, LIANA antwortet wie auf v6.0; eine andere Operation in der SOAPAction bleibt ein Client-Fault")
  void soapActionAusPoppClient() throws Exception {
    String smcb = cards.card("KT-01", 2).orElseThrow().cardHandle();
    readWithAction(
            smcb,
            "<ns4:CertRef>C.AUT</ns4:CertRef>",
            "\"http://ws.gematik.de/conn/CertificateService/v8.2#ReadCardCertificate\"")
        .statusCode(200);
    readWithAction(smcb, "<ns4:CertRef>C.AUT</ns4:CertRef>", "\"" + NS + "#VerifyCertificate\"")
        .statusCode(500)
        .body(containsString("SOAP-ENV:Client"));
  }

  @Test
  @DisplayName(
      "TAB_KON_604: eGK → 4090, C.QES auf SM-B → 4149, unbekanntes Handle → 4008; GERROR gegen TelematikError.xsd")
  void fehler() throws Exception {
    String egk = cards.card("KT-01", 1).orElseThrow().cardHandle();
    String smcb = cards.card("KT-01", 2).orElseThrow().cardHandle();
    fault(read(egk, "<ns4:CertRef>C.AUT</ns4:CertRef>"), "4090");
    fault(read(smcb, "<ns4:CertRef>C.QES</ns4:CertRef>"), "4149");
    fault(read("SMC-B-99", "<ns4:CertRef>C.AUT</ns4:CertRef>"), "4008");
  }

  private static void fault(ValidatableResponse response, String code) throws Exception {
    Element fault = bodyElement(response.statusCode(500).extract().asString());
    assertEquals(code, xpath(fault, "//*[local-name()='Code']"));
    XsdValidator.validate(
        "tel/error/TelematikError.xsd",
        serialize(
            (Element)
                XPathFactory.newInstance()
                    .newXPath()
                    .evaluate("detail/*", fault, XPathConstants.NODE)));
  }

  @Test
  @DisplayName(
      "TIP1-A_4700-03 / TUC_KON_200: IO-Fehler am KT (Störung io-error, LIANA-41) → ReadCardCertificate 4044")
  void stoerungIoFehler() throws Exception {
    String smcb = cards.card("KT-01", 2).orElseThrow().cardHandle();
    terminals.terminal("KT-01").fault(2, Fault.ioError());
    try {
      fault(read(smcb, "<ns4:CertRef>C.AUT</ns4:CertRef>"), "4044");
    } finally {
      terminals.terminal("KT-01").clearFault(2);
    }
  }
}

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

import de.gematik.liana.adapter.fake.FakeTerminals;
import de.gematik.liana.adapter.fake.Fault;
import de.gematik.liana.kern.card.CardList;
import de.gematik.liana.sds.XsdValidator;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.ValidatableResponse;
import jakarta.inject.Inject;
import java.io.ByteArrayInputStream;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;

/**
 * AuthSignatureService (SignatureService v7.4) against the YAML state: smcb-valid in KT-01/2
 * (RecordedCardEngine). Flow as in the popp-client for ZETA: ReadCardCertificate, VerifyPin,
 * ExternalAuthenticate.
 */
@QuarkusTest
class AuthSignatureServiceTest {

  private static final String NS = "http://ws.gematik.de/conn/SignatureService/v7.4";

  /** The hash that the popp-client has signed in the TU trace (request 12). */
  private static final String HASH = "8Tqb6qisC00ZtYRHyFIpVZwb5FnIBVqD4aY4EjVHF/4=";

  private static final String CONTEXT =
      """
            <ns11:Context xmlns:ns11="http://ws.gematik.de/conn/ConnectorContext/v2.0"><ns6:MandantId>M1</ns6:MandantId>\
            <ns6:ClientSystemId>CS1</ns6:ClientSystemId><ns6:WorkplaceId>WP1</ns6:WorkplaceId></ns11:Context>""";

  @Inject CardList cards;

  @Inject FakeTerminals terminals;

  private static ValidatableResponse externalAuthenticate(
      String cardHandle, String base64, String mimeType) throws Exception {
    return externalAuthenticate(cardHandle, "", base64, mimeType);
  }

  /**
   * {@code optionalInputs}: content of SIG:OptionalInputs (prefixes ns2 = dss, ns3 = SIG), empty →
   * without.
   */
  private static ValidatableResponse externalAuthenticate(
      String cardHandle, String optionalInputs, String base64, String mimeType) throws Exception {
    String optional =
        optionalInputs.isEmpty()
            ? ""
            : "<ns3:OptionalInputs>" + optionalInputs + "</ns3:OptionalInputs>";
    String body =
        """
                <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body>\
                <ns3:ExternalAuthenticate xmlns:ns2="urn:oasis:names:tc:dss:1.0:core:schema" xmlns:ns3="%s" \
                xmlns:ns6="http://ws.gematik.de/conn/ConnectorCommon/v5.0"><ns6:CardHandle>%s</ns6:CardHandle>%s%s\
                <ns3:BinaryString><ns2:Base64Data MimeType="%s">%s</ns2:Base64Data></ns3:BinaryString>\
                </ns3:ExternalAuthenticate></SOAP-ENV:Body></SOAP-ENV:Envelope>"""
            .formatted(NS, cardHandle, CONTEXT, optional, mimeType, base64);
    XsdValidator.validate(
        "conn/SignatureService.xsd",
        body.substring(
            body.indexOf("<ns3:ExternalAuthenticate"), body.indexOf("</SOAP-ENV:Body>")));
    return given()
        .contentType("text/xml; charset=utf-8")
        .header("SOAPAction", "\"" + NS + "#ExternalAuthenticate\"")
        .body(body)
        .post("/ws/AuthSignatureService")
        .then();
  }

  private static void verifyPin(String cardHandle) {
    verifyPin(cardHandle, "PIN.SMC");
  }

  private static void verifyPin(String cardHandle, String pinTyp) {
    String ns = "http://ws.gematik.de/conn/CardService/v8.2";
    given()
        .contentType("text/xml; charset=utf-8")
        .header("SOAPAction", "\"" + ns + "#VerifyPin\"")
        .body(
            """
                <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body>\
                <ns2:VerifyPin xmlns:ns2="%s" xmlns:ns6="http://ws.gematik.de/conn/ConnectorCommon/v5.0">%s\
                <ns6:CardHandle>%s</ns6:CardHandle><ns4:PinTyp xmlns:ns4="http://ws.gematik.de/conn/CardServiceCommon/v2.0">\
                %s</ns4:PinTyp></ns2:VerifyPin></SOAP-ENV:Body></SOAP-ENV:Envelope>"""
                .formatted(ns, CONTEXT, cardHandle, pinTyp))
        .post("/ws/CardService")
        .then()
        .statusCode(200);
  }

  /** C.AUT of the card (SMC-B, HBA) via ReadCardCertificate. */
  private static X509Certificate cAut(String cardHandle) throws Exception {
    String ns = "http://ws.gematik.de/conn/CertificateService/v6.0";
    String xml =
        given()
            .contentType("text/xml; charset=utf-8")
            .header("SOAPAction", "\"" + ns + "#ReadCardCertificate\"")
            .body(
                """
                        <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body>\
                        <ns4:ReadCardCertificate xmlns:ns4="%s" xmlns:ns6="http://ws.gematik.de/conn/ConnectorCommon/v5.0">\
                        <ns6:CardHandle>%s</ns6:CardHandle>%s<ns4:CertRefList><ns4:CertRef>C.AUT</ns4:CertRef>\
                        </ns4:CertRefList></ns4:ReadCardCertificate></SOAP-ENV:Body></SOAP-ENV:Envelope>"""
                    .formatted(ns, cardHandle, CONTEXT))
            .post("/ws/CertificateService")
            .then()
            .statusCode(200)
            .extract()
            .asString();
    byte[] der =
        Base64.getDecoder().decode(xpath(bodyElement(xml), "//*[local-name()='X509Certificate']"));
    return (X509Certificate)
        CertificateFactory.getInstance("X.509", "BC")
            .generateCertificate(new ByteArrayInputStream(der));
  }

  @Test
  @DisplayName(
      "TIP1-A_5439-02 ExternalAuthenticate nach VerifyPin: Base64Signature Type urn:bsi:tr:03111:ecdsa, "
          + "ECDSA-Sig-Value über den Hash, prüfbar mit C.AUT aus ReadCardCertificate; Antwort gegen SignatureService.xsd")
  void signaturMitCaut() throws Exception {
    String smcb = cards.card("KT-01", 2).orElseThrow().cardHandle();
    verifyPin(smcb);

    Element response =
        bodyElement(
            externalAuthenticate(smcb, HASH, "application/octet-stream")
                .statusCode(200)
                .extract()
                .asString());
    XsdValidator.validate("conn/SignatureService.xsd", serialize(response));
    assertEquals("OK", xpath(response, "//*[local-name()='Result']"));
    assertEquals(
        "urn:bsi:tr:03111:ecdsa", xpath(response, "//*[local-name()='Base64Signature']/@Type"));

    byte[] signature =
        Base64.getDecoder().decode(xpath(response, "//*[local-name()='Base64Signature']"));
    Signature verify = Signature.getInstance("NONEwithECDSA", "BC");
    verify.initVerify(cAut(smcb));
    verify.update(Base64.getDecoder().decode(HASH));
    assertTrue(verify.verify(signature), "Signatur passt zu C.HCI.AUT.E256 (brainpoolP256r1)");
  }

  @Test
  @DisplayName(
      "LIANA-61 TIP1-A_5439-02 / TAB_KON_784: ExternalAuthenticate mit dem HBA (KT-01/3) nach VerifyPin "
          + "PIN.CH: Signatur mit PrK.HP.AUT.E256, prüfbar mit C.HP.AUT.E256 aus ReadCardCertificate; ohne PIN.CH → 4085")
  void signaturHba() throws Exception {
    String hba = cards.card("KT-01", 3).orElseThrow().cardHandle();
    fault(externalAuthenticate(hba, HASH, "application/octet-stream"), "4085");
    verifyPin(hba, "PIN.CH");

    Element response =
        bodyElement(
            externalAuthenticate(hba, HASH, "application/octet-stream")
                .statusCode(200)
                .extract()
                .asString());
    XsdValidator.validate("conn/SignatureService.xsd", serialize(response));
    assertEquals(
        "urn:bsi:tr:03111:ecdsa", xpath(response, "//*[local-name()='Base64Signature']/@Type"));

    byte[] signature =
        Base64.getDecoder().decode(xpath(response, "//*[local-name()='Base64Signature']"));
    Signature verify = Signature.getInstance("NONEwithECDSA", "BC");
    X509Certificate cAut = cAut(hba);
    assertTrue(
        cAut.getIssuerX500Principal().getName().contains("HBA-CA"),
        cAut.getIssuerX500Principal().getName());
    verify.initVerify(cAut);
    verify.update(Base64.getDecoder().decode(HASH));
    assertTrue(verify.verify(signature), "Signatur passt zu C.HP.AUT.E256 (brainpoolP256r1)");
  }

  @Test
  @DisplayName(
      "LIANA-64 TAB_KON_781: dss:SignatureType (auch CMS urn:ietf:rfc:5652) und SIG:SignatureSchemes "
          + "(RSASSA-PSS, RSASSA-PKCS1-v1_5) werden für G2.1 nicht ausgewertet → ECDSA-Signatur, prüfbar mit C.AUT "
          + "(KUC/HSK_1606_001/002/004/011); SHA-512- und SHA-1-Hash → 4000 (HSK_1606_007 bis 010)")
  void optionalInputsIgnoriert() throws Exception {
    String smcb = cards.card("KT-01", 2).orElseThrow().cardHandle();
    String hba = cards.card("KT-01", 3).orElseThrow().cardHandle();
    verifyPin(smcb);
    verifyPin(hba, "PIN.CH");
    String cms = "<ns2:SignatureType>urn:ietf:rfc:5652</ns2:SignatureType>";
    String cmsUndPss = cms + "<ns3:SignatureSchemes>RSASSA-PSS</ns3:SignatureSchemes>";
    String pkcs1 = "<ns3:SignatureSchemes>RSASSA-PKCS1-v1_5</ns3:SignatureSchemes>";
    for (String[] fall :
        new String[][] {{smcb, cms}, {hba, cms}, {hba, cmsUndPss}, {smcb, pkcs1}}) {
      Element response =
          bodyElement(
              externalAuthenticate(fall[0], fall[1], HASH, "application/octet-stream")
                  .statusCode(200)
                  .extract()
                  .asString());
      assertEquals(
          "urn:bsi:tr:03111:ecdsa",
          xpath(response, "//*[local-name()='Base64Signature']/@Type"),
          fall[1]);
      Signature verify = Signature.getInstance("NONEwithECDSA", "BC");
      verify.initVerify(cAut(fall[0]));
      verify.update(Base64.getDecoder().decode(HASH));
      assertTrue(
          verify.verify(
              Base64.getDecoder().decode(xpath(response, "//*[local-name()='Base64Signature']"))),
          fall[1]);
    }
    for (String card : new String[] {smcb, hba}) {
      fault(
          externalAuthenticate(
              card, Base64.getEncoder().encodeToString(new byte[64]), "application/octet-stream"),
          "4000");
      fault(
          externalAuthenticate(
              card, Base64.getEncoder().encodeToString(new byte[20]), "application/octet-stream"),
          "4000");
    }
  }

  @Test
  @DisplayName(
      "TAB_KON_783 / TUC_KON_218: eGK → 4058, MimeType nicht application/octet-stream → 4000, "
          + "Hash mit 20 Byte → 4000; GERROR gegen TelematikError.xsd")
  void fehler() throws Exception {
    String egk = cards.card("KT-01", 1).orElseThrow().cardHandle();
    String smcb = cards.card("KT-01", 2).orElseThrow().cardHandle();
    fault(externalAuthenticate(egk, HASH, "application/octet-stream"), "4058");
    fault(externalAuthenticate(smcb, HASH, "text/plain"), "4000");
    fault(
        externalAuthenticate(
            smcb, Base64.getEncoder().encodeToString(new byte[20]), "application/octet-stream"),
        "4000");
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
      "TUC_KON_218 / TUC_KON_200: IO-Fehler am KT nach VerifyPin (Störung io-error, LIANA-41) → "
          + "ExternalAuthenticate 4044")
  void stoerungIoFehler() throws Exception {
    String smcb = cards.card("KT-01", 2).orElseThrow().cardHandle();
    verifyPin(smcb);
    terminals.terminal("KT-01").fault(2, Fault.ioError());
    try {
      fault(externalAuthenticate(smcb, HASH, "application/octet-stream"), "4044");
    } finally {
      terminals.terminal("KT-01").clearFault(2);
    }
  }
}

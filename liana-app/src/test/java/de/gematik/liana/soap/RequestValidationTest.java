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

import static de.gematik.liana.soap.DocumentOperationsTest.context;
import static de.gematik.liana.soap.DocumentOperationsTest.encryptDocument;
import static de.gematik.liana.soap.DocumentOperationsTest.signDocument;
import static de.gematik.liana.soap.EventServiceTest.bodyElement;
import static de.gematik.liana.soap.EventServiceTest.getCards;
import static de.gematik.liana.soap.EventServiceTest.xpath;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.TestPorts;
import de.gematik.liana.kern.card.CardList;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;

/**
 * {@code liana.soap.request-validation=reject} (LIANA-48): schema violation → 4000, wrong
 * SOAPAction → client fault.
 */
@QuarkusTest
@TestProfile(RequestValidationTest.Profile.class)
class RequestValidationTest {

  public static class Profile implements QuarkusTestProfile {
    @Override
    public Map<String, String> getConfigOverrides() {
      return TestPorts.config("liana.soap.request-validation", "reject");
    }
  }

  static final String GET_CARDS = "\"http://ws.gematik.de/conn/EventService/v7.2#GetCards\"";
  private static final String SIG = "http://ws.gematik.de/conn/SignatureService/v7.5";
  private static final String CRYPT = "http://ws.gematik.de/conn/EncryptionService/v6.1";

  @Inject CardList cards;

  static Element post(String service, String soapAction, String body, int status) throws Exception {
    var request = given().contentType("text/xml; charset=utf-8").body(body);
    if (soapAction != null) {
      request.header("SOAPAction", soapAction);
    }
    return bodyElement(
        request.post("/ws/" + service).then().statusCode(status).extract().asString());
  }

  @Test
  @DisplayName(
      "TIP1-A_4605-03 GetCards schemakonform mit der soapAction der WSDL → beantwortet wie ohne Prüfung")
  void gueltig() throws Exception {
    Element response =
        post(
            "EventService",
            GET_CARDS,
            getCards(
                "M1", "CS1", "WP1", "<ns5:CtId>KT-01</ns5:CtId><ns5:CardType>EGK</ns5:CardType>"),
            200);
    assertEquals("GetCardsResponse", response.getLocalName());
  }

  @Test
  @DisplayName(
      "TIP1-A_5058-01 / A_14159 GetCards mit einem Element, das EventService.xsd nicht kennt → gematik-SOAP-Fault "
          + "4000 Syntaxfehler")
  void schemaverletzung() throws Exception {
    Element fault =
        post(
            "EventService",
            GET_CARDS,
            getCards(
                "M1", "CS1", "WP1", "<ns5:CardType>EGK</ns5:CardType><ns5:CtId>KT-01</ns5:CtId>"),
            500);
    assertEquals("SOAP-ENV:Server", xpath(fault, "faultcode"));
    assertEquals("4000", xpath(fault, "//*[local-name()='Code']"));
    assertEquals("Syntaxfehler", xpath(fault, "//*[local-name()='ErrorText']"));
  }

  @Test
  @DisplayName(
      "BasicProfile 1.2 R2744 SOAPAction mit falschem Namensraum (v7.1 statt v7.2) → SOAP-ENV:Client mit der "
          + "erwarteten soapAction")
  void falscherSoapActionNamensraum() throws Exception {
    Element fault =
        post(
            "EventService",
            "\"http://ws.gematik.de/conn/EventService/v7.1#GetCards\"",
            getCards("M1", "CS1", "WP1", ""),
            500);
    assertEquals("SOAP-ENV:Client", xpath(fault, "faultcode"));
    assertTrue(
        xpath(fault, "faultstring").contains("erwartet " + GET_CARDS.replace("\"", "")),
        xpath(fault, "faultstring"));
  }

  @Test
  @DisplayName(
      "SOAPAction ohne Anführungszeichen wie in den Konnektor-PoPP-Postman-Collections → kein Verstoß")
  void ohneAnfuehrungszeichen() throws Exception {
    assertEquals(
        "GetCardsResponse",
        post("EventService", GET_CARDS.replace("\"", ""), getCards("M1", "CS1", "WP1", ""), 200)
            .getLocalName());
  }

  @Test
  @DisplayName("BasicProfile 1.2 R2744 ohne SOAPAction → SOAP-ENV:Client")
  void ohneSoapAction() throws Exception {
    Element fault = post("EventService", null, getCards("M1", "CS1", "WP1", ""), 500);
    assertEquals("SOAP-ENV:Client", xpath(fault, "faultcode"));
  }

  @Test
  @DisplayName(
      "SignDocument v7.5 schemakonform (SignatureService_V7_5_6.xsd mit dss und xmldsig) → weiter bis zur "
          + "Zugriffsprüfung (TAB_KON_514-01, unbekannte MandantId → 4021)")
  void signDocumentGueltig() throws Exception {
    String smcb = cards.card("KT-01", 2).orElseThrow().cardHandle();
    Element fault =
        post(
            "SignatureService",
            "\"" + SIG + "#SignDocument\"",
            signDocument(smcb, context("unbekannt", "CS1", "WP1", "bert")),
            500);
    assertEquals("4021", xpath(fault, "//*[local-name()='Code']"));
  }

  @Test
  @DisplayName("SignDocument v7.5 mit JobNumber vor TvMode → 4000")
  void signDocumentReihenfolge() throws Exception {
    String smcb = cards.card("KT-01", 2).orElseThrow().cardHandle();
    String body =
        signDocument(smcb, context("M1", "CS1", "WP1", "bert"))
            .replace(
                "<ns4:TvMode>NONE</ns4:TvMode><ns4:JobNumber>ABC-123</ns4:JobNumber>",
                "<ns4:JobNumber>ABC-123</ns4:JobNumber><ns4:TvMode>NONE</ns4:TvMode>");
    Element fault = post("SignatureService", "\"" + SIG + "#SignDocument\"", body, 500);
    assertEquals("4000", xpath(fault, "//*[local-name()='Code']"));
  }

  @Test
  @DisplayName(
      "TIP1-A_5694-03 EncryptDocument als MTOM: xop:Include im Base64Data ist schemakonform → weiter bis "
          + "TUC_KON_000 R9 / 4003")
  void mtom() throws Exception {
    String hba = cards.card("KT-01", 3).orElseThrow().cardHandle();
    String root =
        encryptDocument(
            hba,
            context("M1", "CS1", "WP1", ""),
            "<xop:Include xmlns:xop=\"http://www.w3.org/2004/08/xop/include\" href=\"cid:doc-1@liana\"/>");
    String boundary = "----=_Part_0_48";
    String body =
        "--"
            + boundary
            + "\r\nContent-Type: application/xop+xml; charset=utf-8; type=\"text/xml\"\r\n"
            + "Content-ID: <root@liana>\r\n\r\n"
            + root
            + "\r\n--"
            + boundary
            + "\r\nContent-Type: text/xml\r\n"
            + "Content-ID: <doc-1@liana>\r\n\r\n<Sammelerklaerung/>\r\n--"
            + boundary
            + "--\r\n";
    String xml =
        given()
            .contentType(
                "multipart/related; type=\"application/xop+xml\"; boundary=\""
                    + boundary
                    + "\"; start=\"<root@liana>\"; start-info=\"text/xml\"")
            .header("SOAPAction", "\"" + CRYPT + "#EncryptDocument\"")
            .body(body.getBytes(StandardCharsets.UTF_8))
            .post("/ws/EncryptionService")
            .then()
            .statusCode(500)
            .extract()
            .asString();
    assertEquals("4003", xpath(bodyElement(xml), "//*[local-name()='Code']"));
  }
}

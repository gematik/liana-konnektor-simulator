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

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.gematik.liana.kern.card.CardList;
import de.gematik.liana.sds.XsdValidator;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.ValidatableResponse;
import jakarta.inject.Inject;
import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;

/** EventService v7.2 against the YAML state: KT-01 with egk-valid in slot 1, context M1/CS1/WP1. */
@QuarkusTest
class EventServiceTest {

  private static final String ACTION = "\"http://ws.gematik.de/conn/EventService/v7.2#GetCards\"";

  @Inject CardList cards;

  static String getCards(String mandant, String clientSystem, String workplace, String inner) {
    return """
                <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body>\
                <ns4:GetCards xmlns:ns2="http://ws.gematik.de/conn/ConnectorCommon/v5.0" \
                xmlns:ns4="http://ws.gematik.de/conn/EventService/v7.2" \
                xmlns:ns5="http://ws.gematik.de/conn/CardServiceCommon/v2.0" \
                xmlns:ns9="http://ws.gematik.de/conn/ConnectorContext/v2.0"><ns9:Context>\
                <ns2:MandantId>%s</ns2:MandantId><ns2:ClientSystemId>%s</ns2:ClientSystemId>\
                <ns2:WorkplaceId>%s</ns2:WorkplaceId></ns9:Context>%s</ns4:GetCards></SOAP-ENV:Body></SOAP-ENV:Envelope>"""
        .formatted(mandant, clientSystem, workplace, inner);
  }

  private static ValidatableResponse post(String action, String body) {
    var request = given().contentType("text/xml; charset=utf-8").body(body);
    if (action != null) {
      request.header("SOAPAction", action);
    }
    return request.post("/ws/EventService").then();
  }

  @Test
  @DisplayName(
      "TIP1-A_4605-03 GetCards EGK in KT-01: Karte mit Handle, Typ, ICCSN, Version; Antwort gegen EventService.xsd")
  void getCardsEgk() throws Exception {
    String xml =
        post(
                ACTION,
                getCards(
                    "M1",
                    "CS1",
                    "WP1",
                    "<ns5:CtId>KT-01</ns5:CtId><ns5:CardType>EGK</ns5:CardType>"))
            .statusCode(200)
            .contentType(containsString("text/xml"))
            .extract()
            .asString();
    Element response = bodyElement(xml);
    XsdValidator.validate("conn/EventService.xsd", serialize(response));

    var card = cards.card("KT-01", 1).orElseThrow();
    assertEquals("OK", xpath(response, "//*[local-name()='Result']"));
    assertEquals(card.cardHandle(), xpath(response, "//*[local-name()='CardHandle']"));
    assertEquals("EGK", xpath(response, "//*[local-name()='CardType']"));
    assertEquals("80276883110000168584", xpath(response, "//*[local-name()='Iccsn']"));
    assertEquals("1", xpath(response, "//*[local-name()='SlotId']"));
    assertEquals("4", xpath(response, "//*[local-name()='COSVersion']/*[local-name()='Major']"));
    assertEquals("X110630769", xpath(response, "//*[local-name()='Kvnr']"));
    assertEquals("2030-04-06Z", xpath(response, "//*[local-name()='CertificateExpirationDate']"));
  }

  @Test
  @DisplayName(
      "TIP1-A_4605-03 GetCards SMC-B in KT-01 (wie der popp-client für ZETA): genau die SMC-B mit Handle, ICCSN, "
          + "Name und Ablauf aus C.HCI.AUT, ohne KVNR; Antwort gegen EventService.xsd")
  void getCardsSmcb() throws Exception {
    String xml =
        post(
                ACTION,
                getCards(
                    "M1",
                    "CS1",
                    "WP1",
                    "<ns5:CtId>KT-01</ns5:CtId><ns5:CardType>SMC-B</ns5:CardType>"))
            .statusCode(200)
            .extract()
            .asString();
    Element response = bodyElement(xml);
    XsdValidator.validate("conn/EventService.xsd", serialize(response));

    assertEquals("1", xpath(response, "count(//*[local-name()='Card'])"));
    assertEquals(
        cards.card("KT-01", 2).orElseThrow().cardHandle(),
        xpath(response, "//*[local-name()='CardHandle']"));
    assertEquals("SMC-B", xpath(response, "//*[local-name()='CardType']"));
    assertEquals("80276883110000168650", xpath(response, "//*[local-name()='Iccsn']"));
    assertEquals("2", xpath(response, "//*[local-name()='SlotId']"));
    assertEquals(
        "Praxis Münchhausen-HohenfelsTEST-ONLY",
        xpath(response, "//*[local-name()='CardHolderName']"));
    assertEquals("0", xpath(response, "count(//*[local-name()='Kvnr'])"));
    assertEquals("2030-04-06Z", xpath(response, "//*[local-name()='CertificateExpirationDate']"));

    String sm =
        post(ACTION, getCards("M1", "CS1", "WP1", "<ns5:CardType>SM-B</ns5:CardType>"))
            .statusCode(200)
            .extract()
            .asString();
    assertEquals("SMC-B", xpath(bodyElement(sm), "//*[local-name()='CardType']"));
    String alle =
        post(ACTION, getCards("M1", "CS1", "WP1", "")).statusCode(200).extract().asString();
    assertEquals(
        "EGK SMC-B HBA",
        xpath(
            bodyElement(alle),
            "concat(//*[local-name()='Card'][1]/*[local-name()='CardType'], ' ', "
                + "//*[local-name()='Card'][2]/*[local-name()='CardType'], ' ', "
                + "//*[local-name()='Card'][3]/*[local-name()='CardType'])"));
  }

  @Test
  @DisplayName(
      "TIP1-A_4565-03 / TIP1-A_4605-03 GetCards HBA in KT-01/3 (Testprofil): CardType HBA mit Handle, ICCSN, "
          + "CardVersion, Name und Ablauf aus C.HP.AUT, ohne KVNR; Filter HBAx; Antwort gegen EventService.xsd")
  void getCardsHba() throws Exception {
    String xml =
        post(
                ACTION,
                getCards(
                    "M1",
                    "CS1",
                    "WP1",
                    "<ns5:CtId>KT-01</ns5:CtId><ns5:CardType>HBA</ns5:CardType>"))
            .statusCode(200)
            .extract()
            .asString();
    Element response = bodyElement(xml);
    XsdValidator.validate("conn/EventService.xsd", serialize(response));

    assertEquals("1", xpath(response, "count(//*[local-name()='Card'])"));
    assertEquals(
        cards.card("KT-01", 3).orElseThrow().cardHandle(),
        xpath(response, "//*[local-name()='CardHandle']"));
    assertEquals("HBA", xpath(response, "//*[local-name()='CardType']"));
    assertEquals("80276883119000000020", xpath(response, "//*[local-name()='Iccsn']"));
    assertEquals("KT-01", xpath(response, "//*[local-name()='Card']/*[local-name()='CtId']"));
    assertEquals("3", xpath(response, "//*[local-name()='SlotId']"));
    assertEquals(
        "8", xpath(response, "//*[local-name()='ObjectSystemVersion']/*[local-name()='Minor']"));
    assertEquals(
        "Maximilian PopówitschTEST-ONLY", xpath(response, "//*[local-name()='CardHolderName']"));
    assertEquals("0", xpath(response, "count(//*[local-name()='Kvnr'])"));
    assertEquals("2031-06-03Z", xpath(response, "//*[local-name()='CertificateExpirationDate']"));

    String hbax =
        post(ACTION, getCards("M1", "CS1", "WP1", "<ns5:CardType>HBAx</ns5:CardType>"))
            .statusCode(200)
            .extract()
            .asString();
    assertEquals("HBA", xpath(bodyElement(hbax), "//*[local-name()='CardType']"));
  }

  @Test
  @DisplayName(
      "GetCards ohne SOAPAction (Operation aus dem Body), leeres KT-02 → leere Kartenliste")
  void ohneSoapAction() throws Exception {
    String xml =
        post(null, getCards("M1", "CS1", "WP1", "<ns5:CtId>KT-02</ns5:CtId>"))
            .statusCode(200)
            .extract()
            .asString();
    Element response = bodyElement(xml);
    XsdValidator.validate("conn/EventService.xsd", serialize(response));
    assertEquals("0", xpath(response, "count(//*[local-name()='Card'])"));
  }

  @Test
  @DisplayName(
      "TAB_KON_514-01 / TIP1-A_4524-03: unbekannter Mandant → SOAP-Fault 4021, GERROR gegen TelematikError.xsd")
  void unbekannterKontext() throws Exception {
    String xml =
        post(ACTION, getCards("M9", "CS1", "WP1", "")).statusCode(500).extract().asString();
    Element fault = bodyElement(xml);
    assertEquals("SOAP-ENV:Server", xpath(fault, "faultcode"));
    assertEquals("4021", xpath(fault, "//*[local-name()='Code']"));
    assertEquals("Technical", xpath(fault, "//*[local-name()='ErrorType']"));
    XsdValidator.validate(
        "tel/error/TelematikError.xsd",
        serialize(
            (Element)
                XPathFactory.newInstance()
                    .newXPath()
                    .evaluate("detail/*", fault, XPathConstants.NODE)));
  }

  @Test
  @DisplayName("TAB_KON_560 / TIP1-A_4600: unbekanntes KT → SOAP-Fault 4007")
  void unbekanntesKt() throws Exception {
    String xml =
        post(ACTION, getCards("M1", "CS1", "WP1", "<ns5:CtId>KT-99</ns5:CtId>"))
            .statusCode(500)
            .extract()
            .asString();
    Element fault = bodyElement(xml);
    assertEquals("4007", xpath(fault, "//*[local-name()='Code']"));
    assertEquals("Ungültige Kartenterminal-ID", xpath(fault, "faultstring"));
  }

  @Test
  @DisplayName(
      "SOAPAction passt nicht zur Operation im Body, kein XML, unbekannte Operation → SOAP-ENV:Client")
  void clientFaults() throws Exception {
    String wrongAction =
        post(
                "\"http://ws.gematik.de/conn/EventService/v7.2#Subscribe\"",
                getCards("M1", "CS1", "WP1", ""))
            .statusCode(500)
            .extract()
            .asString();
    assertEquals("SOAP-ENV:Client", xpath(bodyElement(wrongAction), "faultcode"));
    post(ACTION, "kein xml").statusCode(500).body(containsString("SOAP-ENV:Client"));
    post(null, getCards("M1", "CS1", "WP1", "").replace("GetCards", "GetFoo"))
        .statusCode(500)
        .body(containsString("GetFoo wird von LIANA nicht unterstützt"));
  }

  static Element bodyElement(String envelope) throws Exception {
    var factory = DocumentBuilderFactory.newInstance();
    factory.setNamespaceAware(true);
    var doc =
        factory
            .newDocumentBuilder()
            .parse(new ByteArrayInputStream(envelope.getBytes(StandardCharsets.UTF_8)));
    return (Element)
        XPathFactory.newInstance()
            .newXPath()
            .evaluate(
                "/*[local-name()='Envelope']/*[local-name()='Body']/*", doc, XPathConstants.NODE);
  }

  static String serialize(Element element) throws Exception {
    var out = new StringWriter();
    TransformerFactory.newInstance()
        .newTransformer()
        .transform(new DOMSource(element), new StreamResult(out));
    return out.toString();
  }

  static String xpath(Element element, String expression) throws Exception {
    return XPathFactory.newInstance().newXPath().evaluate(expression, element);
  }
}

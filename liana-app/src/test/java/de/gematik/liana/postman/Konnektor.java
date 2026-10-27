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
package de.gematik.liana.postman;

import static io.restassured.RestAssured.given;

import io.restassured.path.xml.XmlPath;
import io.restassured.response.Response;
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * The Konnektor requests of the Konnektor PoPP Postman collections against LIANA, bodies and
 * SOAPAction as in the collections (context from the Postman environment: {@code mandantId}, {@code
 * clientsystemId}, {@code workplaceId}).
 */
final class Konnektor {

  static final String EVENT_NS = "http://ws.gematik.de/conn/EventService/v7.2";
  static final String CARD_NS = "http://ws.gematik.de/conn/CardService/v8.2";

  private final String mandant;
  private final String clientSystem;
  private final String workplace;

  Konnektor(String mandant, String clientSystem, String workplace) {
    this.mandant = mandant;
    this.clientSystem = clientSystem;
    this.workplace = workplace;
  }

  /**
   * Endpoints from {@code connector.sds} as in the test script of „GetConnector.sds“ (tag {@code
   * Endpoint}).
   */
  record Endpoints(
      String eventService, String cardService, String signatureService, String encryptionService) {}

  /** A response: HTTP status and SOAP body (first child of {@code Body}). */
  record Answer(int status, Element body) {

    String text(String localName) {
      NodeList nodes = body.getElementsByTagNameNS("*", localName);
      return nodes.getLength() == 0 ? null : nodes.item(0).getTextContent();
    }

    boolean isFault() {
      return body.getLocalName().equals("Fault");
    }

    /**
     * {@code detail/Error/Trace} of the SOAP fault or {@code Status/Error/Trace} of the response:
     * code → ErrorText.
     */
    List<Map.Entry<String, String>> traces() {
      List<Map.Entry<String, String>> traces = new ArrayList<>();
      NodeList nodes = body.getElementsByTagNameNS("*", "Trace");
      for (int i = 0; i < nodes.getLength(); i++) {
        Element trace = (Element) nodes.item(i);
        traces.add(Map.entry(child(trace, "Code"), child(trace, "ErrorText")));
      }
      return traces;
    }

    /** {@code Severity} of the first trace. */
    String severity() {
      return text("Severity");
    }

    List<String> responseApdus() {
      List<String> apdus = new ArrayList<>();
      NodeList nodes = body.getElementsByTagNameNS("*", "ResponseApdu");
      for (int i = 0; i < nodes.getLength(); i++) {
        apdus.add(nodes.item(i).getTextContent());
      }
      return apdus;
    }

    private static String child(Element element, String localName) {
      NodeList nodes = element.getElementsByTagNameNS("*", localName);
      return nodes.getLength() == 0 ? null : nodes.item(0).getTextContent();
    }
  }

  /** GetConnector.sds */
  Endpoints connectorSds() {
    XmlPath sds =
        new XmlPath(given().get("/connector.sds").then().statusCode(200).extract().asString());
    return new Endpoints(
        endpoint(sds, "EventService", null),
        endpoint(sds, "CardService", "8.2.1"),
        endpoint(sds, "SignatureService", "7.5.5"),
        endpoint(sds, "EncryptionService", "6.1.1"));
  }

  private static String endpoint(XmlPath sds, String service, String version) {
    String versionFilter = version == null ? "" : " && it.@Version == '" + version + "'";
    String location =
        sds.getString(
            "ConnectorServices.ServiceInformation.Service.find { it.@Name == '"
                + service
                + "' }.Versions.Version.find { true"
                + versionFilter
                + " }.Endpoint.@Location");
    return location == null || location.isEmpty() ? null : location;
  }

  /** GetCards */
  Answer getCards(Endpoints endpoints) {
    return post(
        endpoints.eventService(),
        EVENT_NS + "#GetCards",
        """
                <ns5:GetCards xmlns:ns2="http://ws.gematik.de/conn/ConnectorCommon/v5.0" \
                xmlns:ns3="http://ws.gematik.de/conn/ConnectorContext/v2.0" xmlns:ns5="%s">%s</ns5:GetCards>"""
            .formatted(EVENT_NS, context("ns3", "ns2")));
  }

  /**
   * CardHandle of the first card of type {@code cardType} in the GetCards response, otherwise
   * {@code null}.
   */
  static String cardHandle(Answer getCards, String cardType) {
    NodeList cards = getCards.body().getElementsByTagNameNS("*", "Card");
    for (int i = 0; i < cards.getLength(); i++) {
      Element card = (Element) cards.item(i);
      if (cardType.equals(Answer.child(card, "CardType"))) {
        return Answer.child(card, "CardHandle");
      }
    }
    return null;
  }

  /** StartCardSession */
  Answer startCardSession(Endpoints endpoints, String cardHandle) {
    return post(
        endpoints.cardService(),
        CARD_NS + "#StartCardSession",
        """
                <ns5:StartCardSession xmlns:ns2="http://ws.gematik.de/conn/ConnectorCommon/v5.0" \
                xmlns:ns3="http://ws.gematik.de/conn/ConnectorContext/v2.0" xmlns:ns5="%s">%s\
                <ns2:CardHandle>%s</ns2:CardHandle></ns5:StartCardSession>"""
            .formatted(CARD_NS, context("ns3", "ns2"), cardHandle));
  }

  /** SecureSendApdu n */
  Answer secureSendApdu(Endpoints endpoints, String signedScenario) {
    return secureSendApdu(endpoints, signedScenario, CARD_NS + "#SecureSendAPDU");
  }

  Answer secureSendApdu(Endpoints endpoints, String signedScenario, String soapAction) {
    return post(
        endpoints.cardService(),
        soapAction,
        """
                <ns5:SecureSendAPDU xmlns:ns5="%s"><ns5:SignedScenario>%s</ns5:SignedScenario></ns5:SecureSendAPDU>"""
            .formatted(CARD_NS, signedScenario));
  }

  /** StopCardSession */
  Answer stopCardSession(Endpoints endpoints, String sessionId) {
    return post(
        endpoints.cardService(),
        CARD_NS + "#StopCardSession",
        """
                <ns4:StopCardSession xmlns:ns4="%s"><ns4:SessionId>%s</ns4:SessionId></ns4:StopCardSession>"""
            .formatted(CARD_NS, sessionId));
  }

  private String context(String contextPrefix, String commonPrefix) {
    return ("<%1$s:Context><%2$s:MandantId>%3$s</%2$s:MandantId><%2$s:ClientSystemId>%4$s</%2$s:ClientSystemId>"
            + "<%2$s:WorkplaceId>%5$s</%2$s:WorkplaceId></%1$s:Context>")
        .formatted(contextPrefix, commonPrefix, mandant, clientSystem, workplace);
  }

  private static Answer post(String endpoint, String soapAction, String operation) {
    String envelope =
        """
                <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Header/>\
                <SOAP-ENV:Body>%s</SOAP-ENV:Body></SOAP-ENV:Envelope>"""
            .formatted(operation);
    Response response =
        given()
            .contentType("text/xml; charset=utf-8")
            .header("SOAPAction", soapAction)
            .body(envelope)
            .post(URI.create(endpoint).getPath());
    return new Answer(response.statusCode(), body(response.asString()));
  }

  private static Element body(String envelope) {
    try {
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
    } catch (Exception e) {
      throw new IllegalStateException("Antwort ist kein SOAP: " + envelope, e);
    }
  }
}

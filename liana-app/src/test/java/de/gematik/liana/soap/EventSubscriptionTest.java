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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.adapter.fake.FakeTerminals;
import de.gematik.liana.admin.AdminServer;
import de.gematik.liana.kern.card.CardList;
import de.gematik.liana.kern.event.Subscriptions;
import de.gematik.liana.kern.management.ClientSystemBinding;
import de.gematik.liana.sds.XsdValidator;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.ValidatableResponse;
import jakarta.inject.Inject;
import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;

/**
 * Subscribe, Unsubscribe, RenewSubscriptions, GetSubscription (LIANA-59) and CETP delivery to a
 * local Ereignissenke ({@link CetpReceiver}): by default, with ANCL_TLS_MANDATORY Disabled, over
 * TCP without TLS (TAB_KON_852 CETP2); with Enabled, over TLS (CETP1, LIANA-117); context
 * M1/CS1/WP1 with KT-01.
 */
@QuarkusTest
class EventSubscriptionTest {

  private static final String NS = "http://ws.gematik.de/conn/EventService/v7.2";

  @Inject AdminServer admin;

  @Inject FakeTerminals terminals;

  @Inject CardList cards;

  @Inject Subscriptions subscriptions;

  @Inject ClientSystemBinding binding;

  /** LIANA's clock; it may be ahead of the system time (ShiftableClock, LIANA-55). */
  @Inject Clock clock;

  @AfterEach
  void reset() {
    given().port(admin.port()).post("/admin/reset").then().statusCode(200);
  }

  /**
   * Request like konnektor-service-client 1.6.2 (JAXB, prefixes ns2 …), operation with {@code
   * inner} after Context.
   */
  static String request(String operation, String attributes, String inner) {
    return """
                <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body>\
                <ns4:%s%s xmlns:ns2="http://ws.gematik.de/conn/ConnectorCommon/v5.0" \
                xmlns:ns4="http://ws.gematik.de/conn/EventService/v7.2" \
                xmlns:ns9="http://ws.gematik.de/conn/ConnectorContext/v2.0"><ns9:Context>\
                <ns2:MandantId>M1</ns2:MandantId><ns2:ClientSystemId>CS1</ns2:ClientSystemId>\
                <ns2:WorkplaceId>WP1</ns2:WorkplaceId><ns2:UserId>bert</ns2:UserId></ns9:Context>%s</ns4:%s>\
                </SOAP-ENV:Body></SOAP-ENV:Envelope>"""
        .formatted(operation, attributes, inner, operation);
  }

  static String subscribe(String eventTo, String topic, String filter) {
    return request(
        "Subscribe",
        "",
        "<ns4:Subscription><ns4:EventTo>"
            + eventTo
            + "</ns4:EventTo><ns4:Topic>"
            + topic
            + "</ns4:Topic>"
            + (filter == null ? "" : "<ns4:Filter>" + filter + "</ns4:Filter>")
            + "</ns4:Subscription>");
  }

  private static ValidatableResponse post(String operation, String body) {
    return given()
        .contentType("text/xml; charset=utf-8")
        .header("SOAPAction", "\"" + NS + "#" + operation + "\"")
        .body(body)
        .post("/ws/EventService")
        .then();
  }

  /** Response element in the body, validated against EventService.xsd. */
  private static Element ok(String operation, String body) throws Exception {
    Element response = bodyElement(post(operation, body).statusCode(200).extract().asString());
    XsdValidator.validate("conn/EventService.xsd", serialize(response));
    return response;
  }

  private static Element fault(String operation, String body, String code) throws Exception {
    Element fault = bodyElement(post(operation, body).statusCode(500).extract().asString());
    assertEquals(code, xpath(fault, "//*[local-name()='Code']"));
    return fault;
  }

  @Test
  @DisplayName(
      "TIP1-A_4608 / TIP1-A_4610 / TIP1-A_5112 / TIP1-A_4609: Subscribe → SubscriptionID und TerminationTime "
          + "+25 h, GetSubscription (mandant-wide wie PSSIM) mit EventTo, Topic, Filter, RenewSubscriptions mit "
          + "Warning 4102 für ungültige IDs, Unsubscribe per EventTo; alle Antworten gegen EventService.xsd")
  void operationen() throws Exception {
    Element subscribed =
        ok(
            "Subscribe",
            subscribe(
                "cetp://192.168.197.2:7001",
                "CARD/INSERTED",
                "/Event/Message/Parameter[Key='CardType' and Value='HBA']"));
    assertEquals("OK", xpath(subscribed, "//*[local-name()='Result']"));
    String id = xpath(subscribed, "//*[local-name()='SubscriptionID']");
    Instant termination = Instant.parse(xpath(subscribed, "//*[local-name()='TerminationTime']"));
    assertTrue(
        Duration.between(clock.instant(), termination)
                .minus(Duration.ofHours(25))
                .abs()
                .compareTo(Duration.ofMinutes(1))
            < 0,
        termination.toString());
    assertEquals(
        id,
        xpath(
            ok(
                "Subscribe",
                subscribe(
                    "cetp://192.168.197.2:7001",
                    "CARD/INSERTED",
                    "/Event/Message/Parameter[Key='CardType' and Value='HBA']")),
            "//*[local-name()='SubscriptionID']"),
        "dieselbe Anmeldung");
    String second =
        xpath(
            ok("Subscribe", subscribe("cetp://192.168.197.2:7001", "CARD/REMOVED", null)),
            "//*[local-name()='SubscriptionID']");

    Element list = ok("GetSubscription", request("GetSubscription", " mandant-wide=\"true\"", ""));
    assertEquals("2", xpath(list, "count(//*[local-name()='Subscription'])"));
    assertEquals(
        "cetp://192.168.197.2:7001",
        xpath(list, "//*[local-name()='Subscription'][1]/*[local-name()='EventTo']"));
    assertEquals(
        "CARD/INSERTED",
        xpath(list, "//*[local-name()='Subscription'][1]/*[local-name()='Topic']"));
    assertEquals(
        "/Event/Message/Parameter[Key='CardType' and Value='HBA']",
        xpath(list, "//*[local-name()='Subscription'][1]/*[local-name()='Filter']"));
    assertEquals(
        "0", xpath(list, "count(//*[local-name()='Subscription'][2]/*[local-name()='Filter'])"));
    assertEquals(
        second,
        xpath(
            ok(
                "GetSubscription",
                request(
                    "GetSubscription",
                    "",
                    "<ns4:SubscriptionID>" + second + "</ns4:SubscriptionID>")),
            "//*[local-name()='SubscriptionID']"));

    Element renewed =
        ok(
            "RenewSubscriptions",
            request(
                "RenewSubscriptions",
                "",
                "<ns4:SubscriptionID>"
                    + id
                    + "</ns4:SubscriptionID><ns4:SubscriptionID>weg</ns4:SubscriptionID>"));
    assertEquals("Warning", xpath(renewed, "//*[local-name()='Result']"));
    assertEquals("4102", xpath(renewed, "//*[local-name()='Code']"));
    assertEquals("Ungültige SubscriptionId: weg", xpath(renewed, "//*[local-name()='ErrorText']"));
    assertEquals(
        id,
        xpath(renewed, "//*[local-name()='SubscriptionRenewal']/*[local-name()='SubscriptionID']"));

    ok(
        "Unsubscribe",
        request("Unsubscribe", "", "<ns4:EventTo>cetp://192.168.197.2:7001</ns4:EventTo>"));
    assertEquals(
        "0",
        xpath(
            ok("GetSubscription", request("GetSubscription", " mandant-wide=\"true\"", "")),
            "count(//*[local-name()='Subscription'])"));
  }

  @Test
  @DisplayName(
      "TAB_KON_573/576/579/794: SubscriptionID im Subscribe oder EventTo nicht cetp:// → 4000, unbekannte "
          + "SubscriptionID bei Unsubscribe, GetSubscription und RenewSubscriptions → 4102, Fault gegen XSD")
  void fehler() throws Exception {
    fault(
        "Subscribe",
        request(
            "Subscribe",
            "",
            "<ns4:Subscription><ns4:SubscriptionID>x</ns4:SubscriptionID>"
                + "<ns4:EventTo>cetp://ps:7001</ns4:EventTo><ns4:Topic>CARD</ns4:Topic></ns4:Subscription>"),
        "4000");
    fault("Subscribe", subscribe("http://ps:7001", "CARD", null), "4000");
    fault(
        "Unsubscribe",
        request("Unsubscribe", "", "<ns4:SubscriptionID>weg</ns4:SubscriptionID>"),
        "4102");
    fault(
        "GetSubscription",
        request("GetSubscription", "", "<ns4:SubscriptionID>weg</ns4:SubscriptionID>"),
        "4102");
    fault(
        "RenewSubscriptions",
        request("RenewSubscriptions", "", "<ns4:SubscriptionID>weg</ns4:SubscriptionID>"),
        "4102");
    fault("Subscribe", subscribe("cetp://ps:7001", "CARD", null).replace(">M1<", ">M9<"), "4021");
  }

  @Test
  @DisplayName(
      "TIP1-A_4594 / TIP1-A_4595 / TIP1-A_4596 / TUC_KON_256 / TAB_KON_852 CETP1: mit ANCL_TLS_MANDATORY "
          + "Enabled CARD/REMOVED und CARD/INSERTED per CETP über TLS an EventTo, Konnektor authentisiert sich mit "
          + "ID.AK.AUT, Event gegen EventService.xsd mit SubscriptionID und den Parametern aus TUC_KON_001 / "
          + "TIP1-A_4562")
  void zustellung() throws Exception {
    try (CetpReceiver ps = CetpReceiver.tls()) {
      String id =
          xpath(
              ok("Subscribe", subscribe(ps.eventTo(), "CARD", null)),
              "//*[local-name()='SubscriptionID']");
      String egk = cards.card("KT-01", 1).orElseThrow().cardHandle();
      // only after Subscribe: with ANCL_TLS_MANDATORY, LIANA rejects SOAP over HTTP (TIP1-A_4515)
      binding.state(binding.state().withTlsMandatory(true));

      terminals.remove("KT-01", 1);
      CetpReceiver.Message removed = ps.next(10);
      assertNotNull(removed, "CARD/REMOVED kam nicht an");
      assertTrue(removed.tls(), "CETP1: über TLS");
      XsdValidator.validate("conn/EventService.xsd", removed.xml());
      Element event = document(removed.xml());
      assertEquals(
          "CARD/REMOVED", xpath(event, "/*[local-name()='Event']/*[local-name()='Topic']"));
      assertEquals("Operation", xpath(event, "//*[local-name()='Type']"));
      assertEquals("Info", xpath(event, "//*[local-name()='Severity']"));
      assertEquals(id, xpath(event, "//*[local-name()='SubscriptionID']"));
      assertEquals(egk, parameter(event, "CardHandle"));
      assertEquals("EGK", parameter(event, "Type"));
      assertEquals("X110630769", parameter(event, "KVNR"));
      assertEquals(
          "CN=LIANA ID.AK.AUT p256 TEST-ONLY",
          removed.client().getSubjectX500Principal().getName().split(",O=")[0]);

      terminals.put("KT-01", 1, "egk-valid");
      CetpReceiver.Message inserted = ps.next(10);
      assertNotNull(inserted, "CARD/INSERTED kam nicht an");
      XsdValidator.validate("conn/EventService.xsd", inserted.xml());
      event = document(inserted.xml());
      assertEquals("CARD/INSERTED", xpath(event, "//*[local-name()='Topic']"));
      assertEquals(
          cards.card("KT-01", 1).orElseThrow().cardHandle(), parameter(event, "CardHandle"));
      assertEquals("EGK", parameter(event, "CardType"));
      assertEquals("80276883110000168584", parameter(event, "ICCSN"));
      assertEquals("KT-01", parameter(event, "CtID"));
      assertEquals("1", parameter(event, "SlotID"));
      assertEquals("2030-04-06", parameter(event, "CertExpirationDate"));
      assertTrue(
          parameter(event, "CardVersion").startsWith("COSVersion=4."),
          parameter(event, "CardVersion"));

      binding.reset();
      ok(
          "Unsubscribe",
          request("Unsubscribe", "", "<ns4:SubscriptionID>" + id + "</ns4:SubscriptionID>"));
      terminals.remove("KT-01", 1);
      assertNull(ps.next(1), "nach Unsubscribe nichts mehr");
    }
  }

  @Test
  @DisplayName(
      "TAB_KON_852 CETP2 / TIP1-A_5009: mit ANCL_TLS_MANDATORY Disabled (Standard) kommt CARD/REMOVED per "
          + "CETP über TCP ohne TLS an EventTo, ohne Authentifizierung des Konnektors")
  void cetp2OhneTls() throws Exception {
    try (CetpReceiver ps = CetpReceiver.plain()) {
      ok("Subscribe", subscribe(ps.eventTo(), "CARD/REMOVED", null));
      terminals.remove("KT-01", 1);
      CetpReceiver.Message removed = ps.next(10);
      assertNotNull(removed, "CARD/REMOVED kam nicht an");
      assertFalse(removed.tls());
      assertNull(removed.client());
      XsdValidator.validate("conn/EventService.xsd", removed.xml());
      assertEquals("CARD/REMOVED", xpath(document(removed.xml()), "//*[local-name()='Topic']"));
    }
  }

  @Test
  @DisplayName(
      "TUC_KON_012 Schritte 7a und 7d / TUC_KON_256: VerifyPin PIN.SMC → CARD/PIN/VERIFY_STARTED und "
          + "VERIFY_FINISHED per CETP an die Abonnements wie in EE_KON_CETP_ECC_001, Events gegen EventService.xsd "
          + "mit CardHandle, CardType, ICCSN, CtID, SlotID, PinRef, PinInputCtID und Result")
  void pinEreignisse() throws Exception {
    try (CetpReceiver ps = CetpReceiver.plain()) {
      ok("Subscribe", subscribe(ps.eventTo(), "CARD/PIN/VERIFY_STARTED", null));
      ok("Subscribe", subscribe(ps.eventTo(), "CARD/PIN/VERIFY_FINISHED", null));
      String smcb = cards.card("KT-01", 2).orElseThrow().cardHandle();
      String ns = "http://ws.gematik.de/conn/CardService/v8.2";
      given()
          .contentType("text/xml; charset=utf-8")
          .header("SOAPAction", "\"" + ns + "#VerifyPin\"")
          .body(
              """
                            <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body>\
                            <ns4:VerifyPin xmlns:ns2="http://ws.gematik.de/conn/ConnectorCommon/v5.0" xmlns:ns4="%s" \
                            xmlns:ns5="http://ws.gematik.de/conn/CardServiceCommon/v2.0" \
                            xmlns:ns9="http://ws.gematik.de/conn/ConnectorContext/v2.0"><ns9:Context>\
                            <ns2:MandantId>M1</ns2:MandantId><ns2:ClientSystemId>CS1</ns2:ClientSystemId>\
                            <ns2:WorkplaceId>WP1</ns2:WorkplaceId></ns9:Context><ns2:CardHandle>%s</ns2:CardHandle>\
                            <ns5:PinTyp>PIN.SMC</ns5:PinTyp></ns4:VerifyPin></SOAP-ENV:Body></SOAP-ENV:Envelope>"""
                  .formatted(ns, smcb))
          .post("/ws/CardService")
          .then()
          .statusCode(200);

      CetpReceiver.Message started = ps.next(10);
      assertNotNull(started, "CARD/PIN/VERIFY_STARTED kam nicht an");
      XsdValidator.validate("conn/EventService.xsd", started.xml());
      Element event = document(started.xml());
      assertEquals(
          "CARD/PIN/VERIFY_STARTED",
          xpath(event, "/*[local-name()='Event']/*[local-name()='Topic']"));
      assertEquals("Operation", xpath(event, "//*[local-name()='Type']"));
      assertEquals("Info", xpath(event, "//*[local-name()='Severity']"));
      assertEquals(smcb, parameter(event, "CardHandle"));
      assertEquals("SMC-B", parameter(event, "CardType"));
      assertEquals("80276883110000168650", parameter(event, "ICCSN"));
      assertEquals("KT-01", parameter(event, "CtID"));
      assertEquals("2", parameter(event, "SlotID"));
      assertEquals("PIN.SMC", parameter(event, "PinRef"));
      assertEquals("KT-01", parameter(event, "PinInputCtID"));
      assertEquals(
          "0",
          xpath(event, "count(//*[local-name()='Parameter'][*[local-name()='Key']='Result'])"));

      CetpReceiver.Message finished = ps.next(10);
      assertNotNull(finished, "CARD/PIN/VERIFY_FINISHED kam nicht an");
      XsdValidator.validate("conn/EventService.xsd", finished.xml());
      event = document(finished.xml());
      assertEquals(
          "CARD/PIN/VERIFY_FINISHED",
          xpath(event, "/*[local-name()='Event']/*[local-name()='Topic']"));
      assertEquals("OK", parameter(event, "Result"));
      assertEquals("PIN.SMC", parameter(event, "PinRef"));
      assertNull(ps.next(1), "je Topic genau ein Ereignis");
    }
  }

  @Test
  @DisplayName(
      "TUC_KON_256 Schritte 5a und 5c: Topic CARD/REMOVED und Filter auf CardType HBA lassen nur das "
          + "passende Ereignis durch")
  void topicUndFilter() throws Exception {
    try (CetpReceiver ps = CetpReceiver.plain()) {
      ok(
          "Subscribe",
          subscribe(
              ps.eventTo(),
              "CARD/INSERTED",
              "/Event/Message/Parameter[Key='CardType' and Value='HBA']"));
      ok("Subscribe", subscribe(ps.eventTo(), "CARD/REMOVED", null));
      terminals.put("KT-01", 1, "smcb-valid");
      assertEquals("CARD/REMOVED", xpath(document(ps.next(10).xml()), "//*[local-name()='Topic']"));
      terminals.put("KT-01", 1, "hba-valid");
      assertEquals("CARD/REMOVED", xpath(document(ps.next(10).xml()), "//*[local-name()='Topic']"));
      Element hba = document(ps.next(10).xml());
      assertEquals("CARD/INSERTED", xpath(hba, "//*[local-name()='Topic']"));
      assertEquals("HBA", parameter(hba, "CardType"));
      assertNull(ps.next(1));
    }
  }

  @Test
  @DisplayName(
      "TAB_KON_571 / TAB_KON_580: nicht erreichbare Ereignissenke → nach EVT_MAX_TRY (3) Fehlversuchen "
          + "Auto-Unsubscribe")
  void autoUnsubscribe() throws Exception {
    int closed;
    try (ServerSocket probe = new ServerSocket(0)) {
      closed = probe.getLocalPort();
    }
    ok("Subscribe", subscribe("cetp://127.0.0.1:" + closed, "CARD", null));
    terminals.remove("KT-01", 1);
    terminals.put("KT-01", 1, "egk-valid");
    terminals.remove("KT-01", 1);
    long deadline = System.nanoTime() + Duration.ofSeconds(20).toNanos();
    while (!subscriptions.all().isEmpty() && System.nanoTime() < deadline) {
      Thread.sleep(50);
    }
    assertEquals(0, subscriptions.all().size());
  }

  private static String parameter(Element event, String key) throws Exception {
    return xpath(
        event,
        "//*[local-name()='Parameter'][*[local-name()='Key']='"
            + key
            + "']/*[local-name()='Value']");
  }

  static Element document(String xml) throws Exception {
    var factory = DocumentBuilderFactory.newInstance();
    factory.setNamespaceAware(true);
    return factory
        .newDocumentBuilder()
        .parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)))
        .getDocumentElement();
  }

  static Element bodyElement(String xml) throws Exception {
    Element envelope = document(xml);
    return (Element)
        XPathFactory.newInstance()
            .newXPath()
            .evaluate(
                "/*[local-name()='Envelope']/*[local-name()='Body']/*[1]",
                envelope,
                XPathConstants.NODE);
  }

  static String xpath(Element element, String expression) throws Exception {
    return XPathFactory.newInstance().newXPath().evaluate(expression, element);
  }

  static String serialize(Element element) throws Exception {
    StringWriter out = new StringWriter();
    TransformerFactory.newInstance()
        .newTransformer()
        .transform(new DOMSource(element), new StreamResult(out));
    return out.toString();
  }
}

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

import de.gematik.liana.sds.XsdValidator;
import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;

/**
 * LIANA-108: EventService GetCardTerminals against the YAML state (WP1 with the fake KTs KT-01 and
 * KT-02, M1/CS1).
 */
@QuarkusTest
class GetCardTerminalsTest {

  private static final String ACTION =
      "\"http://ws.gematik.de/conn/EventService/v7.2#GetCardTerminals\"";

  static String request(String attributes, String context) {
    return """
                <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body>\
                <ns4:GetCardTerminals xmlns:ns2="http://ws.gematik.de/conn/ConnectorCommon/v5.0" \
                xmlns:ns4="http://ws.gematik.de/conn/EventService/v7.2" \
                xmlns:ns9="http://ws.gematik.de/conn/ConnectorContext/v2.0"%s><ns9:Context>%s</ns9:Context>\
                </ns4:GetCardTerminals></SOAP-ENV:Body></SOAP-ENV:Envelope>"""
        .formatted(attributes, context);
  }

  private static String post(String body, int status) {
    return given()
        .contentType("text/xml; charset=utf-8")
        .header("SOAPAction", ACTION)
        .body(body)
        .post("/ws/EventService")
        .then()
        .statusCode(status)
        .extract()
        .asString();
  }

  @Test
  @DisplayName(
      "TIP1-A_4604 / TUC_KON_252: die KTs von WP1 mit CtId, WorkplaceIds, Name, MAC, Slots, IS_PHYSICAL und "
          + "Connected, ProductInformation des Fake-KT, IPAddress 127.0.0.1 (der Konnektor-Client der eHealth-KT-Suite "
          + "setzt sie voraus); Antwort gegen EventService.xsd")
  void arbeitsplatz() throws Exception {
    Element response =
        bodyElement(
            post(
                request(
                    "",
                    "<ns2:MandantId>M1</ns2:MandantId>"
                        + "<ns2:ClientSystemId>CS1</ns2:ClientSystemId><ns2:WorkplaceId>WP1</ns2:WorkplaceId>"),
                200));
    XsdValidator.validate("conn/EventService.xsd", serialize(response));
    assertEquals("OK", xpath(response, "//*[local-name()='Result']"));
    assertEquals("2", xpath(response, "count(//*[local-name()='CardTerminal'])"));
    assertEquals(
        "KT-01", xpath(response, "//*[local-name()='CardTerminal'][1]/*[local-name()='CtId']"));
    assertEquals(
        "KT-02", xpath(response, "//*[local-name()='CardTerminal'][2]/*[local-name()='CtId']"));
    String kt01 = "//*[local-name()='CardTerminal'][1]/*[local-name()='%s']";
    assertEquals(
        "WP1", xpath(response, kt01.formatted("WorkplaceIds") + "/*[local-name()='WorkplaceId']"));
    assertEquals("KT-01", xpath(response, kt01.formatted("Name")));
    assertTrue(xpath(response, kt01.formatted("MacAddress")).matches("02-4C(-[0-9A-F]{2}){4}"));
    assertEquals("3", xpath(response, kt01.formatted("Slots")));
    assertEquals("true", xpath(response, kt01.formatted("IS_PHYSICAL")));
    assertEquals("true", xpath(response, kt01.formatted("Connected")));
    assertEquals(
        "127.0.0.1",
        xpath(response, kt01.formatted("IPAddress") + "/*[local-name()='IPV4Address']"));
    assertEquals(
        "FAKEKT",
        xpath(response, kt01.formatted("ProductInformation") + "//*[local-name()='ProductCode']"));
  }

  @Test
  @DisplayName(
      "TAB_KON_563 @mandant-wide=true: alle KTs der Arbeitsplätze von M1/CS1, auch ohne WorkplaceId")
  void mandantWide() throws Exception {
    Element response =
        bodyElement(
            post(
                request(
                    " mandant-wide=\"true\"",
                    "<ns2:MandantId>M1</ns2:MandantId>"
                        + "<ns2:ClientSystemId>CS1</ns2:ClientSystemId>"),
                200));
    XsdValidator.validate("conn/EventService.xsd", serialize(response));
    assertEquals("2", xpath(response, "count(//*[local-name()='CardTerminal'])"));
  }

  @Test
  @DisplayName(
      "TAB_KON_564 Schritt 2, TUC_KON_000: unbekannter Mandant 4021, fehlende WorkplaceId ohne "
          + "@mandant-wide 4021, unbekanntes Clientsystem 4021")
  void zugriff() throws Exception {
    for (String context :
        new String[] {
          "<ns2:MandantId>M9</ns2:MandantId><ns2:ClientSystemId>CS1</ns2:ClientSystemId>"
              + "<ns2:WorkplaceId>WP1</ns2:WorkplaceId>",
          "<ns2:MandantId>M1</ns2:MandantId><ns2:ClientSystemId>CS1</ns2:ClientSystemId>",
          "<ns2:MandantId>M1</ns2:MandantId><ns2:ClientSystemId>CS9</ns2:ClientSystemId>"
              + "<ns2:WorkplaceId>WP1</ns2:WorkplaceId>"
        }) {
      Element fault = bodyElement(post(request("", context), 500));
      assertEquals("4021", xpath(fault, "//*[local-name()='Code']"), context);
    }
  }
}

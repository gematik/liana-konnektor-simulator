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
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.gematik.liana.admin.AdminServer;
import de.gematik.liana.kern.card.CardList;
import de.gematik.liana.sds.XsdValidator;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;

/**
 * LIANA-187: EventService GetResourceInformation against the YAML state (KT-01 with egk-valid in
 * slot 1, M1/CS1/WP1).
 */
@QuarkusTest
class GetResourceInformationTest {

  private static final String ACTION =
      "\"http://ws.gematik.de/conn/EventService/v7.2#GetResourceInformation\"";

  @Inject CardList cards;

  @Inject AdminServer admin;

  /**
   * The request from Epikur from PS session 013 (XML-WS Runtime 4.0.3: default namespace, unused
   * prefixes, UserId), only the context MEpikur/Epikur/ap2 replaced by M1/CS1/WP1 of the test
   * profile; {@code inner} follows the context.
   */
  static String epikur(String inner) {
    return "<?xml version='1.0' encoding='UTF-8'?><S:Envelope xmlns:S=\"http://schemas.xmlsoap.org/soap/envelope/\" "
        + "xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\"><SOAP-ENV:Header/><S:Body>"
        + "<GetResourceInformation xmlns=\"http://ws.gematik.de/conn/EventService/v7.2\" "
        + "xmlns:ns10=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:ns11=\"urn:oasis:names:tc:SAML:1.0:assertion\" "
        + "xmlns:ns2=\"http://ws.gematik.de/conn/ConnectorCommon/v5.0\" "
        + "xmlns:ns3=\"http://ws.gematik.de/conn/ConnectorContext/v2.0\" "
        + "xmlns:ns4=\"http://ws.gematik.de/tel/error/v2.0\" "
        + "xmlns:ns5=\"http://ws.gematik.de/conn/CardServiceCommon/v2.0\" "
        + "xmlns:ns6=\"http://ws.gematik.de/conn/CardService/v8.1\" "
        + "xmlns:ns7=\"http://ws.gematik.de/int/version/ProductInformation/v1.1\" "
        + "xmlns:ns8=\"http://ws.gematik.de/conn/CardTerminalInfo/v8.0\" "
        + "xmlns:ns9=\"urn:oasis:names:tc:dss:1.0:core:schema\"><ns3:Context><ns2:MandantId>M1</ns2:MandantId>"
        + "<ns2:ClientSystemId>CS1</ns2:ClientSystemId><ns2:WorkplaceId>WP1</ns2:WorkplaceId>"
        + "<ns2:UserId>1</ns2:UserId></ns3:Context>"
        + inner
        + "</GetResourceInformation></S:Body></S:Envelope>";
  }

  private static Element post(String body, int status) throws Exception {
    return bodyElement(
        given()
            .contentType("text/xml; charset=utf-8")
            .header("SOAPAction", ACTION)
            .body(body)
            .post("/ws/EventService")
            .then()
            .statusCode(status)
            .extract()
            .asString());
  }

  @AfterEach
  void reset() {
    given().port(admin.port()).post("/admin/reset").then().statusCode(200);
  }

  @Test
  @DisplayName(
      "TIP1-A_4607 / TUC_KON_254 Schritt 3: der Request von Epikur (Sitzung 013) ergibt 200 mit Connector, "
          + "VPNTIStatus Online, VPNSISStatus Offline, Fehlerzustandsliste TAB_KON_503; Antwort gegen EventService.xsd")
  void epikurKonnektor() throws Exception {
    Element response = post(epikur(""), 200);
    XsdValidator.validate("conn/EventService.xsd", serialize(response));
    assertEquals("OK", xpath(response, "//*[local-name()='Result']"));
    assertEquals(
        "Online",
        xpath(response, "//*[local-name()='VPNTIStatus']/*[local-name()='ConnectionStatus']"));
    assertEquals(
        "Offline",
        xpath(response, "//*[local-name()='VPNSISStatus']/*[local-name()='ConnectionStatus']"));
    assertEquals(
        "false",
        xpath(
            response,
            "//*[local-name()='ErrorState'][*[local-name()='ErrorCondition']="
                + "'EC_No_VPN_TI_Connection']/*[local-name()='Value']"));
    assertEquals(
        "Operation",
        xpath(
            response,
            "//*[local-name()='ErrorState'][*[local-name()='ErrorCondition']="
                + "'EC_No_VPN_TI_Connection']/*[local-name()='Type']"));
    assertEquals(
        "0",
        xpath(response, "count(//*[local-name()='ErrorState'][*[local-name()='Value']='true'])"));
    assertEquals("0", xpath(response, "count(//*[local-name()='Card'])"));
  }

  @Test
  @DisplayName(
      "TUC_KON_254 Schritte 1 und 2: CardHandle bzw. CtId+SlotId liefern die Karte wie GetCards, CtId allein "
          + "das KT wie GetCardTerminals; Antworten gegen EventService.xsd")
  void karteUndKt() throws Exception {
    String handle = cards.card("KT-01", 1).orElseThrow().cardHandle();
    for (String inner :
        new String[] {
          "<ns2:CardHandle>" + handle + "</ns2:CardHandle>",
          "<ns5:CtId>KT-01</ns5:CtId><ns5:SlotId>1</ns5:SlotId>",
          "<ns5:Iccsn>80276883110000168584</ns5:Iccsn>"
        }) {
      Element response = post(epikur(inner), 200);
      XsdValidator.validate("conn/EventService.xsd", serialize(response));
      assertEquals(
          handle, xpath(response, "//*[local-name()='Card']/*[local-name()='CardHandle']"), inner);
      assertEquals(
          "EGK", xpath(response, "//*[local-name()='Card']/*[local-name()='CardType']"), inner);
      assertEquals("0", xpath(response, "count(//*[local-name()='Connector'])"), inner);
    }
    Element kt = post(epikur("<ns5:CtId>KT-02</ns5:CtId>"), 200);
    XsdValidator.validate("conn/EventService.xsd", serialize(kt));
    assertEquals("KT-02", xpath(kt, "//*[local-name()='CardTerminal']/*[local-name()='CtId']"));
    assertEquals(
        "WP1", xpath(kt, "//*[local-name()='CardTerminal']//*[local-name()='WorkplaceId']"));
  }

  @Test
  @DisplayName(
      "TAB_KON_562 / TAB_KON_570: SlotId ohne CtId 4000, unbekanntes KT 4007, unbekanntes CardHandle 4101, "
          + "unbekannte Iccsn 4099")
  void fehler() throws Exception {
    String[][] cases = {
      {"<ns5:SlotId>1</ns5:SlotId>", "4000"},
      {"<ns5:CtId>KT-99</ns5:CtId>", "4007"},
      {"<ns2:CardHandle>unbekannt</ns2:CardHandle>", "4101"},
      {"<ns5:Iccsn>80276000000000000000</ns5:Iccsn>", "4099"}
    };
    for (String[] c : cases) {
      assertEquals(c[1], xpath(post(epikur(c[0]), 500), "//*[local-name()='Code']"), c[0]);
    }
  }

  @Test
  @DisplayName(
      "LIANA-187 AC3 / A_17085 / TIP1-A_4512-06: PUT /admin/operating-state mit vpnTi=false setzt VPNTIStatus "
          + "Offline und EC_No_VPN_TI_Connection, das Protokoll hat OPERATIONAL_STATE/EC_No_VPN_TI_Connection; reset "
          + "stellt die YAML her")
  void betriebszustandUeberAdminApi() throws Exception {
    given()
        .port(admin.port())
        .contentType("application/json")
        .body("{\"vpnTi\":false}")
        .put("/admin/operating-state")
        .then()
        .statusCode(200)
        .body("vpnTi.online", equalTo(false))
        .body(
            "errorStates.find { it.condition == 'EC_No_VPN_TI_Connection' }.value", equalTo(true));
    Element response = post(epikur(""), 200);
    assertEquals(
        "Offline",
        xpath(response, "//*[local-name()='VPNTIStatus']/*[local-name()='ConnectionStatus']"));
    assertEquals(
        "true",
        xpath(
            response,
            "//*[local-name()='ErrorState'][*[local-name()='ErrorCondition']="
                + "'EC_No_VPN_TI_Connection']/*[local-name()='Value']"));
    given()
        .port(admin.port())
        .get("/admin/log")
        .then()
        .body("topic", hasItem("OPERATIONAL_STATE/EC_No_VPN_TI_Connection"));
    given()
        .port(admin.port())
        .contentType("application/json")
        .body("{}")
        .put("/admin/operating-state")
        .then()
        .statusCode(400);

    given().port(admin.port()).post("/admin/reset").then().statusCode(200);
    assertEquals(
        "Online",
        xpath(
            post(epikur(""), 200),
            "//*[local-name()='VPNTIStatus']/*[local-name()='ConnectionStatus']"));
  }
}

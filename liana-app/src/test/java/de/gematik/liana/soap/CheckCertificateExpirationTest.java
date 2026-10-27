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

import de.gematik.liana.admin.AdminServer;
import de.gematik.liana.kern.card.CardList;
import de.gematik.liana.kern.card.CardType;
import de.gematik.liana.sds.XsdValidator;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;

/**
 * LIANA-188: CertificateService CheckCertificateExpiration against the YAML state (KT-01:
 * egk-valid, smcb-valid, hba-valid; gSMC-K image gsmc-k), plus the gSMC-KT gsmckt-root6 in KT-02/2
 * as in the card terminal of the PS lab.
 */
@QuarkusTest
class CheckCertificateExpirationTest {

  private static final String ACTION =
      "\"http://ws.gematik.de/conn/CertificateService/v6.0#CheckCertificateExpiration\"";
  private static final String GSMC_K_ICCSN = "80276883119000000019";

  @Inject CardList cards;

  @Inject AdminServer admin;

  /**
   * The request from Epikur from PS session 013 (XML-WS Runtime 4.0.3: default namespace
   * TelematikError, prefix ns2 for the service), only the context MEpikur/Epikur/ap2 replaced by
   * M1/CS1/WP1 of the test profile.
   */
  static String epikur(String inner) {
    return "<?xml version='1.0' encoding='UTF-8'?><S:Envelope xmlns:S=\"http://schemas.xmlsoap.org/soap/envelope/\" "
        + "xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\"><SOAP-ENV:Header/><S:Body>"
        + "<ns2:CheckCertificateExpiration xmlns=\"http://ws.gematik.de/tel/error/v2.0\" "
        + "xmlns:ns2=\"http://ws.gematik.de/conn/CertificateService/v6.0\" "
        + "xmlns:ns3=\"http://ws.gematik.de/conn/ConnectorCommon/v5.0\" "
        + "xmlns:ns4=\"http://ws.gematik.de/conn/ConnectorContext/v2.0\" "
        + "xmlns:ns5=\"http://ws.gematik.de/conn/CertificateServiceCommon/v2.0\" "
        + "xmlns:ns6=\"urn:oasis:names:tc:dss:1.0:core:schema\" xmlns:ns7=\"http://www.w3.org/2000/09/xmldsig#\" "
        + "xmlns:ns8=\"urn:oasis:names:tc:SAML:1.0:assertion\">"
        + inner.replace(
            "{context}",
            "<ns4:Context><ns3:MandantId>M1</ns3:MandantId><ns3:ClientSystemId>CS1</ns3:ClientSystemId>"
                + "<ns3:WorkplaceId>WP1</ns3:WorkplaceId><ns3:UserId>1</ns3:UserId></ns4:Context>")
        + "</ns2:CheckCertificateExpiration></S:Body></S:Envelope>";
  }

  private static Element post(String body, int status) throws Exception {
    return bodyElement(
        given()
            .contentType("text/xml; charset=utf-8")
            .header("SOAPAction", ACTION)
            .body(body)
            .post("/ws/CertificateService")
            .then()
            .statusCode(status)
            .extract()
            .asString());
  }

  @BeforeEach
  void gsmcKtStecken() {
    given()
        .port(admin.port())
        .contentType("application/json")
        .body(Map.of("image", "gsmckt-root6"))
        .put("/admin/terminals/KT-02/slots/2")
        .then()
        .statusCode(200);
  }

  @AfterEach
  void reset() {
    given().port(admin.port()).post("/admin/reset").then().statusCode(200);
  }

  private static String entry(Element response, String iccsn, String field) throws Exception {
    return xpath(
        response,
        "//*[local-name()='CertificateExpiration'][*[local-name()='ICCSN']='"
            + iccsn
            + "']/*[local-name()='"
            + field
            + "']");
  }

  @Test
  @DisplayName(
      "TIP1-A_4699-07 / TAB_KON_677: der Request von Epikur (Sitzung 013) mit Crypt=ECC ergibt 200 mit je einem "
          + "CertificateExpiration für SM-B, HBA und gSMC-KT (CN = ICCSN, validity aus C.SMKT.AUT), die gSMC-K ohne "
          + "ECC-C.NK.VPN als Warnung 4257; Antwort gegen CertificateService.xsd")
  void epikurEcc() throws Exception {
    Element response = post(epikur("{context}<ns2:Crypt>ECC</ns2:Crypt>"), 200);
    XsdValidator.validate("conn/CertificateService.xsd", serialize(response));
    String smkt =
        cards.cards().stream()
            .filter(c -> c.data().type() == CardType.SMC_KT)
            .findFirst()
            .orElseThrow()
            .data()
            .iccsn();
    assertEquals("Warning", xpath(response, "//*[local-name()='Result']"));
    assertEquals("4257", xpath(response, "//*[local-name()='Trace']/*[local-name()='Code']"));
    assertEquals(
        "ECCZertifikat nicht vorhanden auf Karte: gSMC-K",
        xpath(response, "//*[local-name()='Trace']/*[local-name()='ErrorText']"));
    assertEquals("KT-02", entry(response, smkt, "CtID"));
    assertEquals(smkt, entry(response, smkt, "subject_commonName"));
    assertEquals("2028-09-19Z", entry(response, smkt, "validity"));
    for (CardType type : new CardType[] {CardType.SMC_B, CardType.HBA}) {
      var card =
          cards.cards().stream().filter(c -> c.data().type() == type).findFirst().orElseThrow();
      assertEquals(
          card.cardHandle(), entry(response, card.data().iccsn(), "CardHandle"), type.value());
      assertEquals(
          card.data().certExpirationDate() + "Z",
          entry(response, card.data().iccsn(), "validity"),
          type.value());
    }
    assertEquals("3", xpath(response, "count(//*[local-name()='CertificateExpiration'])"));
  }

  @Test
  @DisplayName(
      "TIP1-A_4699-07 / TUC_KON_033 mit checkSMCK: Crypt=RSA liefert die gSMC-K mit C.NK.VPN.R2048, CtID und "
          + "CardHandle leer; Antwort gegen CertificateService.xsd")
  void epikurRsa() throws Exception {
    Element response = post(epikur("{context}<ns2:Crypt>RSA</ns2:Crypt>"), 200);
    XsdValidator.validate("conn/CertificateService.xsd", serialize(response));
    assertEquals("", entry(response, GSMC_K_ICCSN, "CtID"));
    assertEquals("", entry(response, GSMC_K_ICCSN, "CardHandle"));
    assertEquals(
        "80276883119000000019-20261020", entry(response, GSMC_K_ICCSN, "subject_commonName"));
    assertEquals("2031-10-19Z", entry(response, GSMC_K_ICCSN, "validity"));
  }

  @Test
  @DisplayName(
      "TAB_KON_677 Schritt 1 / TAB_KON_603: Crypt außerhalb RSA, ECC 4000, CardHandle der eGK 4058; mit "
          + "CardHandle nur diese Karte, ohne gSMC-K")
  void cardHandle() throws Exception {
    assertEquals(
        "4000",
        xpath(
            post(epikur("{context}<ns2:Crypt>DSA</ns2:Crypt>"), 500), "//*[local-name()='Code']"));
    String egk = cards.card("KT-01", 1).orElseThrow().cardHandle();
    assertEquals(
        "4058",
        xpath(
            post(epikur("<ns3:CardHandle>" + egk + "</ns3:CardHandle>{context}"), 500),
            "//*[local-name()='Code']"));
    var smcb = cards.card("KT-01", 2).orElseThrow();
    Element response =
        post(epikur("<ns3:CardHandle>" + smcb.cardHandle() + "</ns3:CardHandle>{context}"), 200);
    XsdValidator.validate("conn/CertificateService.xsd", serialize(response));
    assertEquals("1", xpath(response, "count(//*[local-name()='CertificateExpiration'])"));
    assertEquals(smcb.data().iccsn(), xpath(response, "//*[local-name()='ICCSN']"));
  }
}

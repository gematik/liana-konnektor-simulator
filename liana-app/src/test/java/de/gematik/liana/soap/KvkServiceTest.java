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
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.gematik.liana.admin.AdminServer;
import de.gematik.liana.kern.card.CardList;
import de.gematik.liana.sds.XsdValidator;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.ValidatableResponse;
import jakarta.inject.Inject;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.HexFormat;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Element;

/**
 * KVKService v4.0, ReadKVK (LIANA-113), against the YAML state with the KVK {@code kvk-valid}
 * (support/images/kvk) in KT-02/1, inserted via the Admin API. The fake KT executes the KVK itself,
 * without card engine.
 */
@QuarkusTest
class KvkServiceTest {

  private static final String NS = "http://ws.gematik.de/conn/vsds/KvkService/v4.0";

  /**
   * SOAPAction according to KvkService.wsdl ({@code #ReadVDT}, not {@code #ReadKVK}), as
   * konnektor-service-client sends it.
   */
  private static final String SOAP_ACTION = "\"" + NS + "#ReadVDT\"";

  private static final String GET_CARDS =
      "\"http://ws.gematik.de/conn/EventService/v7.2#GetCards\"";

  /** The VersichertenDatenTemplate from kvk-valid.xml. */
  static final String TEMPLATE =
      "607F800F546573746B61737365204C49414E418107313233343536378F053939393939820A3132333435"
          + "3637383930830431303030900131840344722E85054572696B61870A4D75737465726D616E6E88083132303831393634890D5465"
          + "7374737472617373652031"
          + "8B0531303131378C064265726C696E8D04313233308E01B3";

  @Inject CardList cards;

  @Inject AdminServer admin;

  @TempDir Path images;

  @BeforeEach
  void kvkInKt02() {
    put("kvk-valid");
  }

  @AfterEach
  void reset() {
    given().port(admin.port()).post("/admin/reset").then().statusCode(200);
  }

  private void put(String image) {
    given()
        .port(admin.port())
        .contentType("application/json")
        .body("{\"image\":\"" + image + "\"}")
        .put("/admin/terminals/KT-02/slots/1")
        .then()
        .statusCode(200);
  }

  static ValidatableResponse readKvk(String handle, String soapAction) throws Exception {
    String operation =
        """
                <KVK:ReadKVK xmlns:KVK="%s"><KVK:KVKHandle>%s</KVK:KVKHandle>\
                <CCTX:Context xmlns:CCTX="http://ws.gematik.de/conn/ConnectorContext/v2.0" \
                xmlns:CONN="http://ws.gematik.de/conn/ConnectorCommon/v5.0"><CONN:MandantId>M1</CONN:MandantId>\
                <CONN:ClientSystemId>CS1</CONN:ClientSystemId><CONN:WorkplaceId>WP1</CONN:WorkplaceId></CCTX:Context>\
                </KVK:ReadKVK>"""
            .formatted(NS, handle);
    XsdValidator.validate("conn/vsds/KvkService.xsd", operation);
    return given()
        .contentType("text/xml; charset=utf-8")
        .header("SOAPAction", soapAction)
        .body(
            "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\"><SOAP-ENV:Body>"
                + operation
                + "</SOAP-ENV:Body></SOAP-ENV:Envelope>")
        .post("/ws/KVKService")
        .then();
  }

  private String kvkHandle() {
    return cards.card("KT-02", 1).orElseThrow().cardHandle();
  }

  @Test
  @DisplayName(
      "LIANA-113 AC #2 / TUC_KON_001 / TIP1-A_4605-03: die KVK im Fake-KT ist CardType KVK; GetCards mit "
          + "CardType KVK liefert sie ohne Iccsn und CardVersion; Antwort gegen EventService.xsd")
  void getCardsKvk() throws Exception {
    String xml =
        given()
            .contentType("text/xml; charset=utf-8")
            .header("SOAPAction", GET_CARDS)
            .body(EventServiceTest.getCards("M1", "CS1", "WP1", "<ns5:CardType>KVK</ns5:CardType>"))
            .post("/ws/EventService")
            .then()
            .statusCode(200)
            .extract()
            .asString();
    Element response = bodyElement(xml);
    XsdValidator.validate("conn/EventService.xsd", serialize(response));
    assertEquals("1", xpath(response, "count(//*[local-name()='Card'])"));
    assertEquals("KVK", xpath(response, "//*[local-name()='Card']/*[local-name()='CardType']"));
    assertEquals(
        kvkHandle(), xpath(response, "//*[local-name()='Card']/*[local-name()='CardHandle']"));
    assertEquals("KT-02", xpath(response, "//*[local-name()='Card']/*[local-name()='CtId']"));
    assertEquals(
        "0", xpath(response, "count(//*[local-name()='Iccsn'] | //*[local-name()='CardVersion'])"));
  }

  @Test
  @DisplayName(
      "LIANA-113 AC #3 / VSDM-A_2609: ReadKVK mit der SOAPAction der WSDL (#ReadVDT) liefert das "
          + "VersichertenDatenTemplate unverändert als base64Binary; Antwort gegen KvkService.xsd")
  void readKvk() throws Exception {
    Element response =
        bodyElement(readKvk(kvkHandle(), SOAP_ACTION).statusCode(200).extract().asString());
    XsdValidator.validate("conn/vsds/KvkService.xsd", serialize(response));
    assertArrayEquals(
        HexFormat.of().parseHex(TEMPLATE),
        Base64.getDecoder().decode(xpath(response, "//*[local-name()='KVK']")));
  }

  @Test
  @DisplayName(
      "ReadKVK mit SOAPAction #ReadKVK (Operationsname statt WSDL-Wert) wird ebenfalls beantwortet")
  void readKvkOperationName() throws Exception {
    readKvk(kvkHandle(), "\"" + NS + "#ReadKVK\"").statusCode(200);
  }

  @Test
  @DisplayName(
      "VSDM-A_2611: falsche Prüfsumme → 3021, Template ohne FamilienName → 3020 (gemILF_PS "
          + "Tab_ILF_PS_Fehlercodes_VSDM)")
  void pruefungScheitert() throws Exception {
    String original = Files.readString(Path.of("support/images/kvk/kvk-valid.xml"));
    Path corrupt = images.resolve("kvk-checksum.xml");
    Files.writeString(corrupt, original.replace("8E01B3", "8E01B4"));
    put(corrupt.toAbsolutePath().toString());
    assertEquals(
        "3021",
        xpath(
            bodyElement(readKvk(kvkHandle(), SOAP_ACTION).statusCode(500).extract().asString()),
            "//*[local-name()='Code']"));

    Path incomplete = images.resolve("kvk-ohne-name.xml");
    Files.writeString(
        incomplete, original.replace("870A4D75737465726D616E6E", "860A4D75737465726D616E6E"));
    put(incomplete.toAbsolutePath().toString());
    assertEquals(
        "3020",
        xpath(
            bodyElement(readKvk(kvkHandle(), SOAP_ACTION).statusCode(500).extract().asString()),
            "//*[local-name()='Code']"));
  }

  @Test
  @DisplayName(
      "ReadKVK mit dem Handle einer eGK → 4209, mit unbekanntem Handle → 4008 (TUC_KON_000)")
  void falscheKarte() throws Exception {
    String egk = cards.card("KT-01", 1).orElseThrow().cardHandle();
    assertEquals(
        "4209",
        xpath(
            bodyElement(readKvk(egk, SOAP_ACTION).statusCode(500).extract().asString()),
            "//*[local-name()='Code']"));
    assertEquals(
        "4008",
        xpath(
            bodyElement(readKvk("unbekannt", SOAP_ACTION).statusCode(500).extract().asString()),
            "//*[local-name()='Code']"));
  }
}

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
package de.gematik.liana.sds;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.path.xml.XmlPath;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.IntStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

@QuarkusTest
class ServiceDirectoryResourceTest {

  private static String connectorSds() {
    return given()
        .when()
        .get("/connector.sds")
        .then()
        .statusCode(200)
        .contentType("application/xml")
        .extract()
        .asString();
  }

  @Test
  @DisplayName("TIP1-A_4529-02 connector.sds ist valide gegen conn/ServiceDirectory.xsd")
  void validAgainstXsd() throws Exception {
    XsdValidator.validate("conn/ServiceDirectory.xsd", connectorSds());
  }

  @Test
  @DisplayName(
      "TIP1-A_4528 connector.sds nennt EventService, CardTerminalService (LIANA-110), CardService, "
          + "CertificateService, AuthSignatureService, SignatureService (LIANA-85), EncryptionService, VSDService "
          + "(LIANA-119) und KVKService (LIANA-189.01, LIANA-113), mit Endpunkten aus kon-export.url")
  void servicesAndEndpoints() {
    XmlPath sds = new XmlPath(connectorSds());
    assertEquals(Services.NAMES, sds.getList("ConnectorServices.ServiceInformation.Service.@Name"));
    assertEquals(
        Services.endpoints("http://localhost:8080"),
        Services.NAMES.stream()
            .map(
                name ->
                    sds.getString(
                        "ConnectorServices.ServiceInformation.Service.find { it.@Name == '"
                            + name
                            + "' }.Versions.Version[0].Endpoint.@Location"))
            .toList());
    assertTrue(
        sds.getString(
                "ConnectorServices.ProductInformation.ProductIdentification.ProductVersion.Local.FWVersion")
            .matches("\\d+\\.\\d+\\.\\d+"));
  }

  @ParameterizedTest(name = "{0}")
  @CsvSource(
      delimiter = '|',
      value = {
        "EventService         | v7.2:7.2.0",
        "CardTerminalService  | v1.1:1.1.0",
        "CardService          | v8.1:8.1.0 v8.1:8.1.1 v8.1:8.1.2 v8.2:8.2.0 v8.2:8.2.1",
        "CertificateService   | v6.0:6.0.0 v6.0:6.0.1 v6.0:6.0.2",
        "AuthSignatureService | v7.4:7.4.0 v7.4:7.4.1",
        "SignatureService     | v7.4:7.4.0 v7.4:7.4.1 v7.4:7.4.2 v7.4:7.4.3 v7.5:7.5.0 v7.5:7.5.1 v7.5:7.5.2 "
            + "v7.5:7.5.3 v7.5:7.5.4 v7.5:7.5.5",
        "EncryptionService    | v6.1:6.1.0 v6.1:6.1.1",
        "VSDService           | v5.2:5.2.0",
        "KVKService           | v4.0:4.0.0"
      })
  @DisplayName(
      "LIANA-120 TIP1-A_4529-02 TAB_KON_518 / TIP1-A_4586-04: je Dienst alle bedienten Versionen "
          + "(Namensraum:Version), aufsteigend, jede mit demselben Endpunkt")
  void versions(String service, String expected) {
    XmlPath sds = new XmlPath(connectorSds());
    String versions =
        "ConnectorServices.ServiceInformation.Service.find { it.@Name == '"
            + service
            + "' }.Versions.Version";
    List<String> namespaces = sds.getList(versions + ".@TargetNamespace");
    List<String> numbers = sds.getList(versions + ".@Version");
    String base =
        service.equals("AuthSignatureService")
            ? "SignatureService"
            : service.equals("VSDService")
                ? "vsds/VSDService"
                : service.equals("KVKService") ? "vsds/KvkService" : service;
    assertEquals(
        Arrays.asList(expected.split(" ")),
        IntStream.range(0, numbers.size())
            .mapToObj(
                i ->
                    namespaces.get(i).replace("http://ws.gematik.de/conn/" + base + "/", "")
                        + ":"
                        + numbers.get(i))
            .toList());
    assertEquals(
        Collections.nCopies(numbers.size(), "http://localhost:8080/ws/" + service),
        sds.getList(versions + ".Endpoint.@Location"));
  }

  @ParameterizedTest(name = "{0}")
  @CsvSource({
    "SignatureService, http://ws.gematik.de/conn/SignatureService/v7.5, ExternalAuthenticate",
    "EncryptionService, http://ws.gematik.de/conn/EncryptionService/v6.1, ExternalAuthenticate"
  })
  @DisplayName(
      "LIANA-85 angekündigter, teilweise umgesetzter Dienst (LIANA-60): Endpunkt aus connector.sds antwortet "
          + "auf eine nicht umgesetzte Operation mit SOAP-Fault (decision-12)")
  void announcedButUnsupported(String service, String namespace, String operation) {
    String location =
        new XmlPath(connectorSds())
            .getString(
                "ConnectorServices.ServiceInformation.Service.find { it.@Name == '"
                    + service
                    + "' }.Versions.Version[0].Endpoint.@Location");
    assertEquals("http://localhost:8080/ws/" + service, location);
    given()
        .contentType("text/xml; charset=utf-8")
        .body(
            """
                <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body>\
                <ns:%s xmlns:ns="%s"/></SOAP-ENV:Body></SOAP-ENV:Envelope>"""
                .formatted(operation, namespace))
        .post("/ws/" + service)
        .then()
        .statusCode(500)
        .body(containsString("<faultcode>SOAP-ENV:Client</faultcode>"))
        .body(
            containsString(
                service + ": Operation " + operation + " wird von LIANA nicht unterstützt"));
  }

  @Test
  @DisplayName("Tab_FM_VSDM_23: VSDService mit Abstract „VSD von eGK lesen“ (LIANA-119)")
  void vsdService() {
    assertEquals(
        "VSD von eGK lesen",
        new XmlPath(connectorSds())
            .getString(
                "ConnectorServices.ServiceInformation.Service.find { it.@Name == 'VSDService' }.Abstract"));
  }

  @Test
  @DisplayName("VSDM-A_2793: KVKService mit Abstract „Versichertendaten von KVK lesen“ (LIANA-113)")
  void kvkService() {
    assertEquals(
        "Versichertendaten von KVK lesen",
        new XmlPath(connectorSds())
            .getString(
                "ConnectorServices.ServiceInformation.Service.find { it.@Name == 'KVKService' }.Abstract"));
  }

  @Test
  @DisplayName("XsdValidator weist ein Dienstverzeichnis ohne ServiceInformation ab")
  void validatorRejectsInvalid() {
    String invalid =
        connectorSds().replaceAll("(?s)<SI:ServiceInformation>.*</SI:ServiceInformation>", "");
    assertThrows(
        org.xml.sax.SAXException.class,
        () -> XsdValidator.validate("conn/ServiceDirectory.xsd", invalid));
  }
}

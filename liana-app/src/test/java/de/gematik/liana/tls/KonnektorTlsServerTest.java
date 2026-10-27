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
package de.gematik.liana.tls;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.TlsProbe;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.path.xml.XmlPath;
import jakarta.inject.Inject;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * HTTPS port of the Konnektor interface with the YAML: ID.AK.AUT P-256, no client authentication.
 */
@QuarkusTest
public class KonnektorTlsServerTest {

  /** GetCards with the context of the YAML (M1/CS1/WP1), as in {@code EventServiceTest}. */
  public static final String GET_CARDS =
      """
            <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body>\
            <ns4:GetCards xmlns:ns2="http://ws.gematik.de/conn/ConnectorCommon/v5.0" \
            xmlns:ns4="http://ws.gematik.de/conn/EventService/v7.2" \
            xmlns:ns9="http://ws.gematik.de/conn/ConnectorContext/v2.0"><ns9:Context>\
            <ns2:MandantId>M1</ns2:MandantId><ns2:ClientSystemId>CS1</ns2:ClientSystemId>\
            <ns2:WorkplaceId>WP1</ns2:WorkplaceId></ns9:Context></ns4:GetCards></SOAP-ENV:Body></SOAP-ENV:Envelope>""";

  public static final String GET_CARDS_ACTION =
      "http://ws.gematik.de/conn/EventService/v7.2#GetCards";

  @Inject KonnektorTlsServer tls;

  @Test
  @DisplayName(
      "TIP1-A_4514-01: connector.sds über TLS 1.2, Server authentisiert sich mit ID.AK.AUT")
  void serviceDirectory() throws Exception {
    TlsProbe.Result result = TlsProbe.bc().get(tls.port(), "/connector.sds");
    assertEquals(200, result.status());
    assertEquals("TLSv1.2", result.session().getProtocol());
    assertTrue(
        result.serverCertificate().getSubjectX500Principal().getName().contains("ID.AK.AUT p256"));
    XmlPath sds = new XmlPath(result.body());
    assertEquals("false", sds.getString("ConnectorServices.ClientAutMandatory"));
    assertTrue(
        sds
            .getList(
                "ConnectorServices.ServiceInformation.Service.Versions.Version.EndpointTLS.@Location")
            .stream()
            .allMatch(l -> l.toString().startsWith("https://localhost:8443/ws/")));
  }

  @Test
  @DisplayName("TIP1-A_4514-01: SOAP-Basisdienst (EventService GetCards) über TLS wie über HTTP")
  void soapOverTls() throws Exception {
    TlsProbe.Result result =
        TlsProbe.bc().soap(tls.port(), "/ws/EventService", GET_CARDS_ACTION, GET_CARDS);
    assertEquals(200, result.status(), result.response());
    String overHttp =
        given()
            .contentType("text/xml; charset=utf-8")
            .header("SOAPAction", "\"" + GET_CARDS_ACTION + "\"")
            .body(GET_CARDS)
            .post("/ws/EventService")
            .then()
            .statusCode(200)
            .extract()
            .asString();
    assertEquals(
        new XmlPath(overHttp).getString("Envelope.Body.GetCardsResponse.Status.Result"),
        new XmlPath(result.body()).getString("Envelope.Body.GetCardsResponse.Status.Result"));
  }

  @Test
  @DisplayName(
      "LIANA-189.02 Erreichbarkeitsprüfung von Epikur: GET / über HTTPS und HTTP liefert 200, text/html, "
          + "ohne Caching")
  void reachability() throws Exception {
    TlsProbe.Result result = TlsProbe.bc().get(tls.port(), "/");
    assertEquals(200, result.status(), result.response());
    assertTrue(result.body().contains("<body>OK</body>"), result.body());
    given()
        .get("/")
        .then()
        .statusCode(200)
        .contentType("text/html")
        .header("Cache-Control", containsString("no-store"))
        .body(containsString("<body>OK</body>"));
    given().get("/gibtsnicht").then().statusCode(404);
  }

  @Test
  @DisplayName("TIP1-A_4515: HTTP bleibt offen (ANCL_TLS_MANDATORY Disabled)")
  void httpStillOpen() {
    given().get("/connector.sds").then().statusCode(200);
  }
}

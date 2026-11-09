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
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.gematik.liana.TlsProbe;
import de.gematik.liana.tls.KonnektorTlsServer;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.path.xml.XmlPath;
import io.restassured.specification.RequestSpecification;
import jakarta.inject.Inject;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** LIANA-217: without configured URLs the endpoints in {@code connector.sds} follow the request. */
@QuarkusTest
@TestProfile(ServiceDirectoryRequestTest.PublicPorts.class)
class ServiceDirectoryRequestTest {

  public static class PublicPorts implements QuarkusTestProfile {
    @Override
    public Map<String, String> getConfigOverrides() {
      return Map.of(
          "liana.endpoints.public-http-port", "28080", "liana.endpoints.public-tls-port", "28443");
    }
  }

  @Inject KonnektorTlsServer tls;

  /** {@code element} of EventService, one entry per version. */
  static List<String> endpoints(RequestSpecification request, String element) {
    return locations(
        request.get("/connector.sds").then().statusCode(200).extract().asString(), element);
  }

  private static List<String> locations(String sds, String element) {
    return new XmlPath(sds)
        .getList(
            "ConnectorServices.ServiceInformation.Service.find { it.@Name == 'EventService' }"
                + ".Versions.Version."
                + element
                + ".@Location");
  }

  @Test
  @DisplayName(
      "LIANA-217 AC 1 über HTTP: Endpoint aus dem Host, EndpointTLS mit dem öffentlichen TLS-Port")
  void hostOverHttp() {
    RequestSpecification request = given().header("Host", "example.test:28081");
    assertEquals(
        List.of("http://example.test:28081/ws/EventService"), endpoints(request, "Endpoint"));
    assertEquals(
        List.of("https://example.test:28443/ws/EventService"), endpoints(request, "EndpointTLS"));
  }

  @Test
  @DisplayName(
      "LIANA-217 AC 1 über HTTPS: EndpointTLS mit dem Port des Requests, Endpoint mit dem öffentlichen HTTP-Port")
  void hostOverHttps() throws Exception {
    String sds = TlsProbe.bc().get(tls.port(), "/connector.sds").body();
    assertEquals(
        List.of("https://localhost:" + tls.port() + "/ws/EventService"),
        locations(sds, "EndpointTLS"));
    assertEquals(List.of("http://localhost:28080/ws/EventService"), locations(sds, "Endpoint"));
  }

  @Test
  @DisplayName("LIANA-217 AC 4 Standard: Forwarded (RFC 7239) geht dem Host vor")
  void forwarded() {
    RequestSpecification request =
        given()
            .header("Host", "liana:8080")
            .header("Forwarded", "for=1.2.3.4;host=public.test:9443;proto=https");
    assertEquals(
        List.of("https://public.test:9443/ws/EventService"), endpoints(request, "EndpointTLS"));
    assertEquals(
        List.of("http://public.test:28080/ws/EventService"), endpoints(request, "Endpoint"));
  }

  @Test
  @DisplayName("LIANA-217 AC 4 Standard: X-Forwarded-Host, -Proto, -Port gehen dem Host vor")
  void xForwarded() {
    RequestSpecification request =
        given()
            .header("Host", "liana:8080")
            .header("X-Forwarded-Host", "public.test")
            .header("X-Forwarded-Proto", "http")
            .header("X-Forwarded-Port", "8081");
    assertEquals(
        List.of("http://public.test:8081/ws/EventService"), endpoints(request, "Endpoint"));
  }
}

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
package de.gematik.liana.trace;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpServer;
import de.gematik.liana.TestPorts;
import de.gematik.liana.admin.AdminServer;
import de.gematik.liana.cats.CatsServer;
import de.gematik.liana.kms.KmsServer;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * LIANA-195: with {@code liana.trace.push-url} every request to LIANA and its response go to the
 * Tiger proxy, here a stub: Konnektor interface over HTTP and HTTPS, KMS and CATS on the management
 * port; the Admin API and the GUI do not.
 */
@QuarkusTest
@TestProfile(TrafficPushChannelsTest.Profile.class)
class TrafficPushChannelsTest {

  public static class Profile implements QuarkusTestProfile {
    @Override
    public Map<String, String> getConfigOverrides() {
      return TestPorts.config(
          "liana.trace.push-url",
          "http://localhost:" + TestPorts.TRACE,
          "liana.trace.name",
          "konnektor-a");
    }
  }

  record Pushed(Headers headers, String body) {
    String header(String name) {
      return headers.getFirst(name);
    }
  }

  private static final LinkedBlockingQueue<Pushed> PUSHED = new LinkedBlockingQueue<>();

  static {
    try {
      HttpServer stub = HttpServer.create(new InetSocketAddress("localhost", TestPorts.TRACE), 0);
      stub.createContext(
          "/traffic",
          exchange -> {
            PUSHED.add(
                new Pushed(
                    exchange.getRequestHeaders(),
                    new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8)));
            exchange.sendResponseHeaders(200, -1);
            exchange.close();
          });
      stub.start();
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  @Inject AdminServer admin;

  @BeforeEach
  void leeren() throws InterruptedException {
    // pushes of earlier requests (startup, other tests) are not ours
    given().get("/connector.sds").then().statusCode(200);
    while (PUSHED.poll(500, TimeUnit.MILLISECONDS) != null) {
      // drain
    }
  }

  private static Pushed next() throws InterruptedException {
    Pushed pushed = PUSHED.poll(5, TimeUnit.SECONDS);
    assertNotNull(pushed, "kein Push angekommen");
    return pushed;
  }

  /** Request and response of one exchange: paired, supplementary, from the client to LIANA. */
  private static Pushed[] exchange(int port) throws InterruptedException {
    Pushed request = next();
    Pushed response = next();
    assertEquals("true", request.header("tgr-supplementary"));
    assertEquals("true", response.header("tgr-supplementary"));
    assertNull(request.header("tgr-response-to"));
    assertEquals(request.header("tgr-uuid"), response.header("tgr-response-to"));
    // LIANA-195.04: name/IP:Port of the connection, the name from liana.trace.name
    assertTrue(
        request.header("tgr-receiver").matches("konnektor-a/[0-9a-f.:]+:" + port),
        request.header("tgr-receiver"));
    assertEquals(request.header("tgr-sender"), response.header("tgr-receiver"));
    assertEquals(request.header("tgr-receiver"), response.header("tgr-sender"));
    return new Pushed[] {request, response};
  }

  private static String getCards() {
    return """
        <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body>\
        <ns4:GetCards xmlns:ns2="http://ws.gematik.de/conn/ConnectorCommon/v5.0" \
        xmlns:ns4="http://ws.gematik.de/conn/EventService/v7.2" \
        xmlns:ns9="http://ws.gematik.de/conn/ConnectorContext/v2.0"><ns9:Context>\
        <ns2:MandantId>M1</ns2:MandantId><ns2:ClientSystemId>CS1</ns2:ClientSystemId>\
        <ns2:WorkplaceId>WP1</ns2:WorkplaceId></ns9:Context></ns4:GetCards>\
        </SOAP-ENV:Body></SOAP-ENV:Envelope>""";
  }

  @Test
  @DisplayName("SOAP über HTTP: Anfrage mit Body, Antwort mit Status und Body, gepaart")
  void soapHttp() throws Exception {
    given()
        .contentType("text/xml; charset=utf-8")
        .header("SOAPAction", "\"http://ws.gematik.de/conn/EventService/v7.2#GetCards\"")
        .body(getCards())
        .post("/ws/EventService")
        .then()
        .statusCode(200);
    Pushed[] exchange = exchange(TestPorts.HTTP);
    assertTrue(exchange[0].body().startsWith("POST /ws/EventService HTTP/1.1\r\n"));
    assertTrue(exchange[0].body().endsWith(getCards()), exchange[0].body());
    assertTrue(exchange[1].body().startsWith("HTTP/1.1 200 OK\r\n"), exchange[1].body());
    assertTrue(exchange[1].body().contains("GetCardsResponse"), exchange[1].body());
  }

  @Test
  @DisplayName("SOAP über HTTPS (liana.tls.port): Klartext nach TLS")
  void soapHttps() throws Exception {
    given()
        .relaxedHTTPSValidation()
        .baseUri("https://localhost")
        .port(TestPorts.TLS)
        .contentType("text/xml; charset=utf-8")
        .header("SOAPAction", "\"http://ws.gematik.de/conn/EventService/v7.2#GetCards\"")
        .body(getCards())
        .post("/ws/EventService")
        .then()
        .statusCode(200);
    Pushed[] exchange = exchange(TestPorts.TLS);
    assertTrue(exchange[0].body().endsWith(getCards()), exchange[0].body());
    assertTrue(exchange[1].body().contains("GetCardsResponse"), exchange[1].body());
  }

  @Test
  @DisplayName("connector.sds: GET ohne Body, Antwort mit dem Dienstverzeichnis")
  void connectorSds() throws Exception {
    given().get("/connector.sds").then().statusCode(200);
    Pushed[] exchange = exchange(TestPorts.HTTP);
    assertTrue(exchange[0].body().startsWith("GET /connector.sds HTTP/1.1\r\n"));
    assertTrue(exchange[1].body().contains("ConnectorServices"), exchange[1].body());
  }

  @Test
  @DisplayName("KMS und CATS auf dem Management-Port; Admin-API und GUI nicht")
  void managementPort() throws Exception {
    given().port(admin.port()).get("/admin/info").then().statusCode(200);
    given().port(admin.port()).get("/").then().statusCode(200);
    given().port(admin.port()).get("/gui/app.js").then().statusCode(200);
    given().port(admin.port()).get(KmsServer.MOUNT + "/ak/dienste/karten/einstellungen");
    Pushed[] kms = exchange(admin.port());
    assertTrue(kms[0].body().startsWith("GET " + KmsServer.MOUNT + "/"), kms[0].body());

    given().port(admin.port()).get(CatsServer.MOUNT + "/KT-01/config");
    Pushed[] cats = exchange(admin.port());
    assertTrue(cats[0].body().startsWith("GET " + CatsServer.MOUNT + "/KT-01/"), cats[0].body());

    given().port(admin.port()).get("/admin/info").then().statusCode(200);
    given().get("/connector.sds").then().statusCode(200);
    assertTrue(exchange(TestPorts.HTTP)[0].body().startsWith("GET /connector.sds "));
  }
}

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
package de.gematik.liana.admin;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.TestPorts;
import de.gematik.liana.trace.TigerStub;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * LIANA-195.03: the Admin API hands the message list of the linked Tiger proxy through (stub with
 * the responses of Tiger {@value TigerStub#VERSION}) and shows where the traffic goes;
 * LIANA-195.05: each channel can be switched.
 */
@QuarkusTest
@TestProfile(TraceApiTest.Profile.class)
class TraceApiTest {

  public static class Profile implements QuarkusTestProfile {
    @Override
    public Map<String, String> getConfigOverrides() {
      return TestPorts.config(
          "liana.trace.push-url",
          "http://localhost:" + TestPorts.TIGER,
          "liana.events.redirect",
          "ps-cetp:7001",
          "liana.tls.url",
          "https://konnektor-b.example");
    }
  }

  private static final TigerStub TIGER = new TigerStub(TestPorts.TIGER);

  @Inject AdminServer admin;

  @Test
  @DisplayName(
      "GET /admin/trace: Push an <push-url>/traffic, Link zur WebUI, je Kanal Teile und Weg; Admin-API nie")
  void overview() throws InterruptedException {
    // pushes from the startup may have come before the stub; the next one succeeds
    given().get("/connector.sds").then().statusCode(200);
    for (int i = 0; i < 50 && !"ok".equals(state()); i++) {
      Thread.sleep(100);
    }
    given()
        .port(admin.port())
        .get("/admin/trace")
        .then()
        .statusCode(200)
        .body("push.url", equalTo("http://localhost:" + TestPorts.TIGER))
        .body("push.target", equalTo("http://localhost:" + TestPorts.TIGER + "/traffic"))
        .body("push.state", equalTo("ok"))
        // LIANA-195.04: without liana.trace.name the host of liana.tls.url
        .body("name", equalTo("konnektor-b.example"))
        .body("webUi", equalTo("http://localhost:" + TestPorts.TIGER + "/webui/"))
        .body(
            "routes.find { it.channel.startsWith('Konnektor-Schnittstelle') }.endpoint",
            equalTo("HTTP :" + TestPorts.HTTP + ", HTTPS :" + TestPorts.TLS))
        .body(
            "routes.find { it.channel.startsWith('Konnektor-Schnittstelle') }.pushed",
            equalTo(true))
        .body(
            "routes.find { it.channel.startsWith('Konnektor-Schnittstelle') }.trace",
            equalTo(
                "Client-IP:Port → konnektor-b.example/<IP>:"
                    + TestPorts.HTTP
                    + " bzw. konnektor-b.example/<IP>:"
                    + TestPorts.TLS
                    + ", Antwort zurück"))
        .body("routes.find { it.channel == 'Admin-API und Control Center' }.pushed", equalTo(false))
        .body(
            "routes.find { it.channel.startsWith('CETP') }.endpoint",
            equalTo("TCP/TLS an ps-cetp:7001 (liana.events.redirect)"))
        .body(
            "routes.find { it.channel == 'Fake-KT KT-01' }.trace",
            equalTo("konnektor-b.example → konnektor-b.example-KT-01:<Slot>, zurück"))
        .body("routes.channel", hasItem("Fake-KT KT-01"));
  }

  @Test
  @DisplayName(
      "GET /admin/trace/messages: getMessagesWithMeta unverändert, Filter und Zeitfenster gehen durch")
  void messages() throws InterruptedException {
    TIGER.queries.clear();
    String body =
        given()
            .port(admin.port())
            .queryParam("filter", TigerStub.FILTER)
            .queryParam("from", "2026-11-16T13:00:00Z")
            .get("/admin/trace/messages")
            .then()
            .statusCode(200)
            .contentType("application/json")
            .extract()
            .asString();
    assertEquals(TigerStub.fixture("getMessagesWithMeta-filter.json"), body);
    assertEquals(
        "filterRbelPath=" + TigerStub.FILTER + "&minTimestamp=2026-11-16T13:00:00Z",
        TIGER.queries.take());
  }

  @Test
  @DisplayName("Filter, den Tiger ablehnt, und Zeit ohne ISO-8601: 400")
  void badRequest() {
    given()
        .port(admin.port())
        .queryParam("filter", "$.foo ==")
        .get("/admin/trace/messages")
        .then()
        .statusCode(400)
        .body("error", containsString("vom Tiger-Proxy abgelehnt"));
    given()
        .port(admin.port())
        .queryParam("from", "gestern")
        .get("/admin/trace/messages")
        .then()
        .statusCode(400)
        .body("error", containsString("ISO-8601"));
  }

  @Test
  @DisplayName(
      "LIANA-195.05 PUT /admin/trace/channels/{id}: Kanal aus und wieder an, POST /admin/reset schaltet alle an")
  void channels() {
    String kt = "routes.find { it.channel == 'Fake-KT KT-01' }";
    given()
        .port(admin.port())
        .get("/admin/trace")
        .then()
        .body(kt + ".id", equalTo("kt:KT-01"))
        .body(kt + ".on", equalTo(true))
        .body("routes.find { it.channel == 'Admin-API und Control Center' }.id", nullValue());
    given()
        .port(admin.port())
        .contentType("application/json")
        .body("{\"on\": false}")
        .put("/admin/trace/channels/kt:KT-01")
        .then()
        .statusCode(200)
        .body(kt + ".on", equalTo(false))
        .body(kt + ".pushed", equalTo(false))
        .body("routes.find { it.id == 'konnektor' }.on", equalTo(true));
    given().port(admin.port()).post("/admin/reset").then().statusCode(200);
    given().port(admin.port()).get("/admin/trace").then().body(kt + ".on", equalTo(true));
  }

  @Test
  @DisplayName(
      "LIANA-195.05: ein Filter, den Tiger sekundenlang auswertet, hält Übersicht und Schalter nicht auf")
  void langsamerFilterBlockiertNicht() throws Exception {
    var slow =
        java.util.concurrent.CompletableFuture.runAsync(
            () ->
                given()
                    .port(admin.port())
                    .queryParam("filter", TigerStub.SLOW_FILTER)
                    .get("/admin/trace/messages")
                    .then()
                    .statusCode(200));
    Thread.sleep(300);
    long start = System.nanoTime();
    given().port(admin.port()).get("/admin/trace").then().statusCode(200);
    given()
        .port(admin.port())
        .contentType("application/json")
        .body("{\"on\": true}")
        .put("/admin/trace/channels/konnektor")
        .then()
        .statusCode(200);
    long millis = (System.nanoTime() - start) / 1_000_000;
    assertTrue(millis < TigerStub.SLOW_MILLIS / 2, "Übersicht und Schalter in " + millis + " ms");
    slow.get();
  }

  @Test
  @DisplayName("PUT /admin/trace/channels/{id}: unbekannter Kanal 404, ohne on 400")
  void channelErrors() {
    given()
        .port(admin.port())
        .contentType("application/json")
        .body("{\"on\": false}")
        .put("/admin/trace/channels/admin")
        .then()
        .statusCode(404);
    given()
        .port(admin.port())
        .contentType("application/json")
        .body("{}")
        .put("/admin/trace/channels/konnektor")
        .then()
        .statusCode(400);
  }

  @Test
  @DisplayName(
      "LIANA-195.05: keine gerenderte Nachricht mehr über LIANA, die öffnet die Tiger-WebUI")
  void keinRendering() {
    given()
        .port(admin.port())
        .get("/admin/trace/messages/" + TigerStub.UUID + "/html")
        .then()
        .statusCode(404);
  }

  private String state() {
    return given().port(admin.port()).get("/admin/trace").jsonPath().getString("push.state");
  }
}

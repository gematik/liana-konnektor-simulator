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
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import de.gematik.liana.kern.event.SystemLog;
import de.gematik.liana.kern.vendor.PeerDeviations;
import de.gematik.liana.sds.Services;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;
import io.restassured.path.xml.XmlPath;
import jakarta.inject.Inject;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * LIANA-218: {@code /ws/<Service>/<Version>} answers like {@code /ws/<Service>} for the versions
 * {@code connector.sds} offers.
 */
@QuarkusTest
class VersionedEndpointTest {

  @Inject PeerDeviations deviations;

  @Inject SystemLog log;

  private static final String GET_JOB_NUMBER =
      """
      <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body>\
      <ns:GetJobNumber xmlns:ns="http://ws.gematik.de/conn/SignatureService/v7.5">%s\
      </ns:GetJobNumber></SOAP-ENV:Body></SOAP-ENV:Envelope>"""
          .formatted(DocumentOperationsTest.context("M1", "CS1", "WP1", null));

  @BeforeEach
  void clearLog() {
    log.clear();
  }

  @AfterEach
  void reset() {
    deviations.reset();
  }

  private List<SystemLog.Entry> deviationEntries(String path) {
    return log.entries(null, null).stream()
        .filter(entry -> PeerDeviations.TOPIC.equals(entry.topic()))
        .filter(entry -> path.equals(entry.parameters().get("Pfad")))
        .toList();
  }

  private static String post(String path, String body) {
    return given()
        .contentType("text/xml; charset=utf-8")
        .body(body)
        .post(path)
        .then()
        .contentType("text/xml")
        .extract()
        .asString();
  }

  @Test
  @DisplayName("LIANA-218 /ws/EventService/7.2.0 antwortet wie /ws/EventService")
  void eventService() {
    String getCards = EventServiceTest.getCards("M1", "CS1", "WP1", "");
    String unversioned = post("/ws/EventService", getCards);
    assertEquals(unversioned, post("/ws/EventService/7.2.0", getCards));
  }

  @Test
  @DisplayName(
      "LIANA-218 /ws/SignatureService/7.5.5 antwortet wie /ws/SignatureService (Jobnummer je Aufruf neu)")
  void signatureService() {
    String jobNumber = "[A-Z]{3}-[0-9]{3}";
    String unversioned = post("/ws/SignatureService", GET_JOB_NUMBER);
    String versioned = post("/ws/SignatureService/7.5.5", GET_JOB_NUMBER);
    assertEquals(unversioned.replaceAll(jobNumber, "JOB"), versioned.replaceAll(jobNumber, "JOB"));
  }

  @Test
  @DisplayName("LIANA-218 jede Version aus connector.sds erreicht den Dienst, kein 404")
  void everyOfferedVersion() {
    XmlPath sds = new XmlPath(given().get("/connector.sds").asString());
    for (String service : Services.NAMES) {
      List<String> versions =
          sds.getList(
              "ConnectorServices.ServiceInformation.Service.find { it.@Name == '"
                  + service
                  + "' }.Versions.Version.@Version");
      assertFalse(versions.isEmpty(), service);
      for (String version : versions) {
        given()
            .contentType("text/xml; charset=utf-8")
            .body("kein SOAP")
            .post("/ws/" + service + "/" + version)
            .then()
            .statusCode(500)
            .body(containsString("SOAP-ENV:Client"));
      }
    }
  }

  @ParameterizedTest
  @CsvSource({
    "/ws/EventService/7.1.0",
    "/ws/EventService/7.5.5",
    "/ws/EventService/7.2",
    "/ws/SignatureService/7.5.6",
    "/ws/NFDService/1.0.0",
    "/ws/EventService/7.2.0/GetCards"
  })
  @DisplayName("LIANA-218 Version, die connector.sds nicht anbietet → 404")
  void versionNotOffered(String path) {
    given()
        .contentType("text/xml; charset=utf-8")
        .body(EventServiceTest.getCards("M1", "CS1", "WP1", ""))
        .post(path)
        .then()
        .statusCode(404);
  }

  @Test
  @DisplayName(
      "LIANA-218 TIP1-A_4967 ohne strict: versionierter Pfad bedient, HARDCODED_VERSIONED_ENDPOINT als Warning")
  void toleratedDeviationIsLogged() {
    post("/ws/EventService/7.2.0", EventServiceTest.getCards("M1", "CS1", "WP1", ""));
    List<SystemLog.Entry> entries = deviationEntries("/ws/EventService/7.2.0");
    assertEquals(1, entries.size());
    assertEquals(SystemLog.Severity.WARN, entries.get(0).severity());
    assertEquals("HARDCODED_VERSIONED_ENDPOINT", entries.get(0).parameters().get("Deviation"));
    assertEquals("Clientsystem", entries.get(0).parameters().get("Peer"));
  }

  @Test
  @DisplayName(
      "LIANA-218 TIP1-A_4967 mit strict: versionierter Pfad 404, Eintrag als Error, Pfad ohne Version bedient")
  void strictRejects() {
    deviations.setStrict(true);
    String getCards = EventServiceTest.getCards("M1", "CS1", "WP1", "");
    given()
        .contentType("text/xml; charset=utf-8")
        .body(getCards)
        .post("/ws/EventService/7.2.0")
        .then()
        .statusCode(404);
    List<SystemLog.Entry> entries = deviationEntries("/ws/EventService/7.2.0");
    assertEquals(1, entries.size());
    assertEquals(SystemLog.Severity.ERR, entries.get(0).severity());
    given()
        .contentType("text/xml; charset=utf-8")
        .body(getCards)
        .post("/ws/EventService")
        .then()
        .statusCode(200);
  }

  @Test
  @DisplayName(
      "LIANA-218 Version, die connector.sds nicht anbietet: kein Eintrag im Systemprotokoll")
  void notOfferedIsNoDeviation() {
    given().contentType("text/xml; charset=utf-8").body("x").post("/ws/EventService/7.1.0");
    assertEquals(List.of(), deviationEntries("/ws/EventService/7.1.0"));
  }

  @Test
  @DisplayName("LIANA-218 connector.sds nennt weiter nur die Endpunkte ohne Version")
  void connectorSdsUnversioned() {
    XmlPath sds = new XmlPath(given().get("/connector.sds").asString());
    for (String service : Services.NAMES) {
      String versions =
          "ConnectorServices.ServiceInformation.Service.find { it.@Name == '"
              + service
              + "' }.Versions.Version";
      for (Object location : sds.getList(versions + ".Endpoint.@Location")) {
        assertEquals("http://localhost:" + RestAssured.port + "/ws/" + service, location);
      }
      for (Object location : sds.getList(versions + ".EndpointTLS.@Location")) {
        assertEquals("https://localhost:8443/ws/" + service, location);
      }
    }
  }
}

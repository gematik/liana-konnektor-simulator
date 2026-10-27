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
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * {@code .kon} export (kon-format v1.0.0, decision-5) against application.yaml: CS1 at WP1 with M1,
 * kon-export basic.
 */
@QuarkusTest
class KonExportTest {

  @Inject AdminServer server;

  private String kon(String clientSystemId) {
    return given()
        .port(server.port())
        .get("/admin/clients/" + clientSystemId + "/config.kon")
        .then()
        .statusCode(200)
        .contentType("application/json")
        .extract()
        .asString();
  }

  @Test
  @DisplayName(
      "config.kon für CS1: Aufrufkontext aus dem Infomodell, Verbindung aus liana.kon-export, Reihenfolge wie §8")
  void exportCs1() throws Exception {
    String raw = kon("CS1");
    assertEquals(
        List.of(
            "version",
            "url",
            "rewriteServiceEndpoints",
            "mandantId",
            "workplaceId",
            "clientSystemId",
            "credentials",
            "env",
            "trustStore"),
        List.copyOf(new ObjectMapper().readValue(raw, Map.class).keySet()));
    var kon = KonFile.load(raw, Map.of());
    assertEquals("1.0.0", kon.get("version").asText());
    assertEquals("http://localhost:8080", kon.get("url").asText());
    assertEquals(true, kon.get("rewriteServiceEndpoints").asBoolean());
    assertEquals("M1", kon.get("mandantId").asText());
    assertEquals("WP1", kon.get("workplaceId").asText());
    assertEquals("CS1", kon.get("clientSystemId").asText());
    assertEquals(
        "{\"type\":\"basic\",\"username\":\"liana\",\"password\":\"liana\"}",
        kon.get("credentials").toString());
    assertEquals("ru", kon.get("env").asText());
    // Chain of the server identity: C.AK.AUT, then component CA
    assertEquals(2, kon.get("trustStore").size());
    var certificates = CertificateFactory.getInstance("X.509");
    var akAut =
        (X509Certificate)
            certificates.generateCertificate(
                new ByteArrayInputStream(
                    Base64.getDecoder().decode(kon.get("trustStore").get(0).asText())));
    assertEquals(
        "CN=LIANA ID.AK.AUT p256 TEST-ONLY,O=LIANA NOT-VALID,C=DE",
        akAut.getSubjectX500Principal().getName());
  }

  @Test
  @DisplayName("kon-format §7: der Export besteht alle Validierungsregeln")
  void exportGueltig() throws Exception {
    assertEquals(List.of(), KonValidator.errors(KonFile.load(kon("CS1"), Map.of())));
  }

  @Test
  @DisplayName("Unbekanntes Clientsystem → 404 mit Fehler-JSON")
  void unbekannt() {
    given()
        .port(server.port())
        .get("/admin/clients/CS9/config.kon")
        .then()
        .statusCode(404)
        .body("error", containsString("unbekanntes Clientsystem 'CS9'"));
  }
}

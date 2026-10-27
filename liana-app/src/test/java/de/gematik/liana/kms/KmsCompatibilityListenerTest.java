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
package de.gematik.liana.kms;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.gematik.liana.TestPorts;
import de.gematik.liana.admin.AdminServer;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.specification.RequestSpecification;
import jakarta.inject.Inject;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * KMS compatibility listener (LIANA-146): with {@code liana.kms.port}, an additional own HTTPS port
 * as up to 0.6 on 8500, the same router as under {@code /rest/mgmt} on the management port.
 */
@QuarkusTest
@TestProfile(KmsCompatibilityListenerTest.Profile.class)
class KmsCompatibilityListenerTest {

  public static class Profile implements QuarkusTestProfile {
    @Override
    public Map<String, String> getConfigOverrides() {
      return Map.of("liana.kms.port", String.valueOf(TestPorts.KMS));
    }
  }

  @Inject KmsServer kms;

  @Inject AdminServer admin;

  @AfterEach
  void reset() {
    given().port(admin.port()).post("/admin/reset").then().statusCode(200);
  }

  private RequestSpecification compatibility() {
    return given().relaxedHTTPSValidation().baseUri("https://localhost").port(TestPorts.KMS);
  }

  private void vendor(String vendor) {
    given()
        .port(admin.port())
        .contentType("application/json")
        .body(Map.of("vendor", vendor))
        .put("/admin/vendor")
        .then()
        .statusCode(200);
  }

  @Test
  @DisplayName("LIANA-55 / LIANA-146: EHEX-Login und Kartendienst auf liana.kms.port per HTTPS")
  void ehex() {
    assertEquals(TestPorts.KMS, kms.compatibilityPort().orElseThrow());
    vendor("EHEX");
    String token =
        compatibility()
            .contentType("application/json")
            .body("{\"username\":\"super\",\"password\":\"33ee§§EE\"}")
            .post(EhexKms.LOGIN)
            .then()
            .statusCode(204)
            .extract()
            .header("Authorization");
    compatibility()
        .header("Authorization", token)
        .get(EhexKms.CARD_SETTINGS)
        .then()
        .statusCode(200)
        .body("cardSessionTimeout.unit", equalTo("SECONDS"));
  }

  @Test
  @DisplayName(
      "LIANA-96: KOCO-Login (j_security_check) und Verwaltung auf liana.kms.port, wie konnektor-service-client "
          + "auf 9443")
  void koco() {
    vendor("KOCO");
    String session =
        compatibility()
            .redirects()
            .follow(false)
            .formParam("j_username", "super")
            .formParam("j_password", "33ee§§EE")
            .post(KocoKms.SECURITY_CHECK)
            .then()
            .statusCode(303)
            .header("Location", KocoKms.START)
            .extract()
            .cookie(KocoKms.SESSION_COOKIE);
    String token =
        compatibility()
            .redirects()
            .follow(false)
            .cookie(KocoKms.SESSION_COOKIE, session)
            .get(KocoKms.START)
            .then()
            .statusCode(302)
            .extract()
            .cookie(KocoKms.TOKEN_COOKIE);
    compatibility()
        .cookie(KocoKms.SESSION_COOKIE, session)
        .header("X-Token", token)
        .get(KocoKms.MANAGEMENT_RETRIEVE)
        .then()
        .statusCode(200)
        .body("MGM_LU_ONLINE", equalTo("ENABLE"));
  }

  @ParameterizedTest(name = "{0}: {1} {2} → 501")
  @DisplayName(
      "decision-12: Login-Pfade anderer Hersteller (kms-client RiseConstants, KocoConstants) und nicht "
          + "umgesetzte → 501 mit Herstellerprofil")
  @CsvSource({"EHEX, POST, /api/v1/auth/login", "KOCO, POST, /login.htm", "CGM,  POST, /login.htm"})
  void andereHersteller(String vendor, String method, String path) {
    vendor(vendor);
    compatibility()
        .contentType("application/json")
        .body("{}")
        .request(method, path)
        .then()
        .statusCode(501)
        .body("vendor", equalTo(vendor))
        .body("path", equalTo(path));
  }
}

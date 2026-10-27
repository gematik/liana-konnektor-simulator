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
import static org.hamcrest.Matchers.startsWith;

import de.gematik.liana.TestPorts;
import io.quarkus.test.junit.QuarkusIntegrationTest;
import io.quarkus.test.junit.TestProfile;
import io.restassured.specification.RequestSpecification;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * KMS from the native image (LIANA-55): HTTPS with a certificate generated at startup (BC, BCJSSE),
 * EHEX login and card service, 501 for the neutral profile. The artifact runs in the prod profile
 * on ports from {@link TestPorts}; runs with {@code ./mvnw verify -Dnative}.
 */
@QuarkusIntegrationTest
@TestProfile(TestPorts.Profile.class)
class KmsServerIT {

  private static RequestSpecification kms() {
    return given().relaxedHTTPSValidation().baseUri("https://localhost").port(TestPorts.ADMIN);
  }

  private static void vendor(String vendor) {
    given()
        .port(TestPorts.ADMIN)
        .contentType("application/json")
        .body("{\"vendor\":\"" + vendor + "\"}")
        .put("/admin/vendor")
        .then()
        .statusCode(200);
  }

  @Test
  @DisplayName(
      "HTTPS: neutral → 501, EHEX → Login 204 mit Token, Kartendienst mit cardSessionTimeout, Protokoll-Download")
  void ehexOverTls() {
    kms()
        .contentType("application/json")
        .body("{}")
        .post(EhexKms.LOGIN)
        .then()
        .statusCode(501)
        .body("vendor", equalTo("neutral"));
    vendor("EHEX");
    try {
      String token =
          kms()
              .contentType("application/json")
              .body("{\"username\":\"super\",\"password\":\"33ee§§EE\"}")
              .post(EhexKms.LOGIN)
              .then()
              .statusCode(204)
              .extract()
              .header("Authorization");
      kms()
          .header("Authorization", token)
          .get(EhexKms.CARD_SETTINGS)
          .then()
          .statusCode(200)
          .body("cardSessionTimeout.amount", equalTo(120))
          .body("cardSessionTimeout.unit", equalTo("SECONDS"));
      kms()
          .header("Authorization", token)
          .get("/rest/mgmt/ak/dienste/protokoll/download/system/OP/0/0")
          .then()
          .statusCode(200)
          .contentType(startsWith("text/plain"));
    } finally {
      given().port(TestPorts.ADMIN).post("/admin/reset").then().statusCode(200);
    }
  }
}

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
import static org.hamcrest.Matchers.nullValue;

import de.gematik.liana.TestPorts;
import io.quarkus.test.junit.QuarkusIntegrationTest;
import io.quarkus.test.junit.TestProfile;
import io.restassured.specification.RequestSpecification;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Admin API from the native image: JSON in both directions (records, reflection) and its own port.
 * The artifact runs in the prod profile, ports from {@link TestPorts}; runs with {@code ./mvnw
 * verify -Dnative}.
 */
@QuarkusIntegrationTest
@TestProfile(TestPorts.Profile.class)
class AdminApiIT {

  private static RequestSpecification admin() {
    return given().port(TestPorts.ADMIN);
  }

  @Test
  @DisplayName(
      "info, Stecken per JSON-Body, reset, Fehler-JSON und config.kon aus dem nativen Image")
  void roundTrip() {
    admin()
        .get("/admin/info")
        .then()
        .statusCode(200)
        .body("product", equalTo("LIANA"))
        .body("adminPort", equalTo(TestPorts.ADMIN));
    admin()
        .contentType("application/json")
        .body("{\"image\":\"egk-valid\"}")
        .put("/admin/terminals/KT-02/slots/1")
        .then()
        .statusCode(200)
        .body("slots[0].image", equalTo("egk-valid"));
    admin().post("/admin/reset").then().statusCode(200);
    admin()
        .get("/admin/terminals/KT-02")
        .then()
        .statusCode(200)
        .body("slots[0].image", nullValue());
    admin()
        .get("/admin/terminals/KT-99")
        .then()
        .statusCode(404)
        .body("error", containsString("KT-99"));
    admin().get("/admin/infomodel").then().statusCode(200).body("workplaces[0].id", equalTo("WP1"));
    admin()
        .get("/admin/clients/CS1/config.kon")
        .then()
        .statusCode(200)
        .contentType("application/json")
        .body("mandantId", equalTo("M1"))
        .body("credentials.type", equalTo("basic"))
        .body("credentials.containsKey('data')", equalTo(false));
  }
}

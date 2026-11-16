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
import static org.hamcrest.Matchers.everyItem;
import static org.hamcrest.Matchers.nullValue;

import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** LIANA-195.03 without {@code liana.trace.push-url}: nothing goes anywhere, nothing to read. */
@QuarkusTest
class TraceApiOffTest {

  @Inject AdminServer admin;

  @Test
  @DisplayName("GET /admin/trace ohne push-url: Zustand off, kein Kanal gemeldet, kein Link")
  void overview() {
    given()
        .port(admin.port())
        .get("/admin/trace")
        .then()
        .statusCode(200)
        .body("push.state", equalTo("off"))
        .body("push.url", nullValue())
        .body("webUi", nullValue())
        .body("routes.pushed", everyItem(equalTo(false)));
  }

  @Test
  @DisplayName("Nachrichten ohne push-url: 404 mit Hinweis auf liana.trace.push-url")
  void messages() {
    given()
        .port(admin.port())
        .get("/admin/trace/messages")
        .then()
        .statusCode(404)
        .body("error", containsString("liana.trace.push-url"));
  }
}

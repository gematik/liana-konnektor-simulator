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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import jakarta.inject.Inject;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.FieldSource;

/**
 * Control Center (LIANA-148, decision-018) without a browser: delivery of the static files, and
 * that every endpoint the GUI calls exists in the Admin API. {@code verify} does not check the
 * behavior in the browser.
 */
@QuarkusTest
class GuiTest {

  private static final Path SOURCES = Path.of("liana-app/src/main/resources/gui");

  /** A call in {@code api.js}: {@code get(`/admin/…`)} and relatives, one template literal each. */
  private static final Pattern CALL =
      Pattern.compile("\\b(get|put|post|del|getText)\\(`(/admin/[^`]*)`");

  private static final Pattern HOST =
      Pattern.compile("(https?:)?//[a-z0-9.-]+\\.[a-z]{2,}/", Pattern.CASE_INSENSITIVE);
  private static final Pattern NAMESPACES =
      Pattern.compile(
          "\"http://www\\.w3\\.org/(2000/svg|1999/xlink|1999/xhtml|1998/Math/MathML)\"");

  /** The license header (license.header.txt) names the license URL; a comment, not a request. */
  private static final String LICENSE_URL = "http://www.apache.org/licenses/LICENSE-2.0";

  private static final Pattern PLACEHOLDER = Pattern.compile("\\$\\{([^}]*)\\}");

  @Inject AdminServer admin;

  @AfterEach
  void reset() {
    given().port(admin.port()).post("/admin/reset").then().statusCode(200);
  }

  @Test
  @DisplayName(
      "GET / liefert index.html mit Content-Type, no-cache, nosniff und einer CSP nur für LIANA selbst")
  void index() {
    given()
        .port(admin.port())
        .get("/")
        .then()
        .statusCode(200)
        .contentType("text/html; charset=utf-8")
        .header("Cache-Control", "no-cache")
        .header("X-Content-Type-Options", "nosniff")
        .header("Content-Security-Policy", containsString("default-src 'self'"))
        .body(containsString("<script type=\"module\" src=\"/gui/app.js\"></script>"));
  }

  @Test
  @DisplayName("Auch per HTTPS auf dem Management-Port (decision-017)")
  void https() {
    given()
        .relaxedHTTPSValidation()
        .baseUri("https://localhost")
        .port(admin.port())
        .get("/gui/app.js")
        .then()
        .statusCode(200)
        .contentType("text/javascript; charset=utf-8");
  }

  @ParameterizedTest(name = "/gui/{0}")
  @FieldSource("de.gematik.liana.admin.Gui#FILES")
  @DisplayName("Jede Datei der GUI: 200, Content-Type nach Endung, Inhalt wie im Quellbaum")
  void datei(String name) throws IOException {
    Response response = given().port(admin.port()).get(Gui.MOUNT + "/" + name);
    assertEquals(200, response.statusCode());
    assertEquals(Gui.contentType(name), response.contentType());
    assertEquals(Files.readString(SOURCES.resolve(name)), response.asString());
  }

  @Test
  @DisplayName(
      "Gui.FILES nennt genau die Dateien unter gui/ (ohne die Doku in vendor/: SOURCE.md, LICENSE-*.txt); unbekannte → 404")
  void vollstaendig() throws IOException {
    try (Stream<Path> walk = Files.walk(SOURCES)) {
      List<String> sources =
          walk.filter(Files::isRegularFile)
              .map(p -> SOURCES.relativize(p).toString().replace('\\', '/'))
              .filter(
                  name -> !name.equals("vendor/SOURCE.md") && !name.startsWith("vendor/LICENSE-"))
              .sorted()
              .toList();
      assertEquals(sources, Gui.FILES.stream().sorted().toList());
    }
    given()
        .port(admin.port())
        .get("/gui/fehlt.js")
        .then()
        .statusCode(404)
        .body("error", containsString("/gui/fehlt.js"));
    given().port(admin.port()).get("/gui/vendor/SOURCE.md").then().statusCode(404);
    given().port(admin.port()).get("/gui/vendor/LICENSE-htm.txt").then().statusCode(404);
  }

  @Test
  @DisplayName(
      "Kein externer Request: keine URL mit Schema in den GUI-Dateien, fetch und /admin-Pfade nur in api.js")
  void nurLiana() throws IOException {
    for (String name : Gui.FILES) {
      String source = Files.readString(SOURCES.resolve(name));
      // XML namespaces (createElementNS in Preact) are identifiers, not requests
      String withoutNamespaces = NAMESPACES.matcher(source.replace(LICENSE_URL, "")).replaceAll("");
      assertFalse(
          HOST.matcher(withoutNamespaces).find(), name + " verweist auf einen fremden Host");
      if (!name.equals("api.js")) {
        assertFalse(source.contains("fetch("), name + " ruft fetch selbst auf, statt über api.js");
        assertFalse(
            Pattern.compile("['\"`]/admin/").matcher(source).find(),
            name + " nennt einen /admin-Pfad selbst, statt über api.js");
      }
    }
  }

  @Test
  @DisplayName(
      "Jeder Endpunkt aus api.js trifft eine Route der Admin-API, nicht den 404- oder 501-Catch-all, und "
          + "antwortet auch auf einen leeren Body ohne 5xx")
  void endpunkteExistieren() throws IOException {
    Matcher calls = CALL.matcher(Files.readString(SOURCES.resolve("api.js")));
    List<String> checked = new ArrayList<>();
    while (calls.find()) {
      String method =
          switch (calls.group(1)) {
            case "get", "getText" -> "GET";
            case "put" -> "PUT";
            case "post" -> "POST";
            default -> "DELETE";
          };
      String path = sample(calls.group(2));
      Response response =
          given()
              .port(admin.port())
              .contentType("application/json")
              .body("{}")
              .request(method, path);
      String body = response.asString();
      assertFalse(
          response.statusCode() == 404 && body.contains("unbekannter Pfad"),
          method + " " + path + ": " + body);
      assertTrue(response.statusCode() < 500, method + " " + path + ": " + body);
      checked.add(method + " " + path);
    }
    assertTrue(
        checked.size() >= 20, "zu wenige Aufrufe gefunden, Muster in api.js geändert? " + checked);
    assertTrue(
        checked.contains("PUT /admin/terminals/KT-01/slots/1/fault"), String.valueOf(checked));
  }

  @Test
  @DisplayName(
      "LIANA-150: die GUI hört auf GET /admin/events (EventSource in api.js), die Route gibt es")
  void push() throws IOException {
    String api = Files.readString(SOURCES.resolve("api.js"));
    assertTrue(api.contains("stream(`" + AdminEvents.PATH + "`)"), "admin.events in api.js");
    assertTrue(admin.adminRoutes().contains("GET " + AdminEvents.PATH));
    assertTrue(
        Files.readString(SOURCES.resolve("ui.js")).contains("admin.events()"),
        "ein Stream in ui.js");
  }

  @Test
  @DisplayName(
      "Die Admin-API bleibt unter /admin; / und /gui gehören der GUI, andere Pfade weiter 501 (decision-12)")
  void routen() {
    given()
        .port(admin.port())
        .get("/admin/info")
        .then()
        .statusCode(200)
        .body("product", equalTo("LIANA"));
    given().port(admin.port()).post("/login.htm").then().statusCode(501);
  }

  /**
   * Sample values for the placeholders in the paths of api.js: KT-01, slot 1, Clientsystem from the
   * test profile.
   */
  private static String sample(String template) {
    Matcher placeholders = PLACEHOLDER.matcher(template);
    StringBuilder path = new StringBuilder();
    while (placeholders.find()) {
      String expression = placeholders.group(1);
      String value;
      if (expression.contains("kt")) {
        value = "KT-01";
      } else if (expression.contains("slot")) {
        value = "1";
      } else if (expression.contains("client")) {
        value = "CS1";
      } else if (expression.startsWith("range(")) {
        value = "";
      } else {
        throw new IllegalStateException(
            "unbekannter Platzhalter ${" + expression + "} in " + template);
      }
      placeholders.appendReplacement(path, Matcher.quoteReplacement(value));
    }
    placeholders.appendTail(path);
    return path.toString();
  }
}

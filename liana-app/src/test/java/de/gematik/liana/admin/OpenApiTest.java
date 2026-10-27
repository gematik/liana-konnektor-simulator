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
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** LIANA-149: {@code /admin/openapi.yaml} describes exactly the routes of the Admin API. */
@QuarkusTest
class OpenApiTest {

  private static final Pattern PATH = Pattern.compile("^  (/admin/\\S+):$");
  private static final Pattern METHOD = Pattern.compile("^    (get|put|post|delete):$");
  private static final Pattern REF =
      Pattern.compile("\\$ref: \"#/components/(schemas|responses|parameters)/(\\w+)\"");

  @Inject AdminServer admin;

  @ConfigProperty(name = "quarkus.application.version")
  String version;

  private String yaml() {
    return given()
        .port(admin.port())
        .get(OpenApi.PATH)
        .then()
        .statusCode(200)
        .contentType("application/yaml; charset=utf-8")
        .body(startsWith("openapi: 3.0.3\n"))
        .extract()
        .asString();
  }

  /** {@code METHOD /admin/path/{param}} per described operation. */
  private static List<String> described(String yaml) {
    List<String> operations = new ArrayList<>();
    String path = null;
    for (String line : yaml.split("\n")) {
      Matcher p = PATH.matcher(line);
      Matcher m = METHOD.matcher(line);
      if (p.matches()) {
        path = p.group(1);
      } else if (!line.startsWith("  ") && !line.isBlank()) {
        path = null;
      } else if (path != null && m.matches()) {
        operations.add(m.group(1).toUpperCase(java.util.Locale.ROOT) + " " + path);
      }
    }
    return operations.stream().sorted().toList();
  }

  @Test
  @DisplayName(
      "Jede Route unter /admin ist beschrieben und jede beschriebene Operation ist eine Route")
  void deckungMitDemRouter() {
    List<String> routes = admin.adminRoutes();
    List<String> described = described(yaml());
    assertTrue(routes.size() >= 30, String.valueOf(routes));
    assertEquals(routes, described);
  }

  @Test
  @DisplayName(
      "info.version ist die Version von LIANA, jeder $ref zeigt auf eine vorhandene Komponente")
  void inhalt() {
    String yaml = yaml();
    assertTrue(yaml.contains("  version: \"" + version + "\"\n"), "info.version");
    assertFalse(yaml.contains("${"), "Platzhalter ersetzt");
    Matcher refs = REF.matcher(yaml);
    int count = 0;
    while (refs.find()) {
      count++;
      String components = yaml.substring(yaml.indexOf("\ncomponents:\n"));
      String section = components.substring(components.indexOf("\n  " + refs.group(1) + ":\n"));
      int next = section.indexOf("\n  ", 1);
      while (next >= 0 && section.startsWith("\n   ", next)) {
        next = section.indexOf("\n  ", next + 1);
      }
      String block = next < 0 ? section : section.substring(0, next);
      assertTrue(block.contains("\n    " + refs.group(2) + ":\n"), refs.group() + " fehlt");
    }
    assertTrue(count > 20, "zu wenige $ref gefunden");
  }
}

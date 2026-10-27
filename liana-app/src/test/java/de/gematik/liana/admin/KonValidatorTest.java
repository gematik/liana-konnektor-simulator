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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The test helpers themselves: §4 substitution in {@link KonFile}, §7 rules in {@link
 * KonValidator}.
 */
class KonValidatorTest {

  private static final String EXAMPLE =
      """
            {
              "version": "1.0.0",
              "url": "https://konnektor.example.com:8443",
              "mandantId": "M1", "workplaceId": "W1", "clientSystemId": "C1",
              "credentials": { "type": "pkcs12", "data": "MIIB\\nAAAA", "password": "00" },
              "env": "ru",
              "trustStore": ["AAAA", "AAAA\\r\\nAAAA"]
            }""";

  private static ObjectNode example() throws Exception {
    return (ObjectNode) new ObjectMapper().readTree(EXAMPLE);
  }

  @Test
  @DisplayName("§8-Beispiel ist gültig, MIME-Base64 mit Zeilenumbruch eingeschlossen")
  void beispielGueltig() throws Exception {
    assertEquals(List.of(), KonValidator.errors(example()));
  }

  @Test
  @DisplayName("§7 meldet alle Feldfehler auf einmal: Pflichtfelder leer, env, Base64")
  void alleFehlerAufEinmal() throws Exception {
    ObjectNode kon = example();
    kon.put("url", " ").remove("workplaceId");
    kon.put("env", "xu");
    kon.withArray("trustStore").add("kein base64!");
    ((ObjectNode) kon.get("credentials")).put("data", "%%");
    assertEquals(
        List.of(
            "url is required",
            "workplaceId is required",
            "env muss ru, tu oder pu sein, ist 'xu'",
            "credentials.data ist kein gültiges Base64",
            "trustStore[2] ist kein gültiges Base64"),
        KonValidator.errors(kon));
  }

  @Test
  @DisplayName(
      "§7 credentials: fehlend, ohne type, unbekannter type, basic und system ohne Pflichtfelder")
  void credentials() throws Exception {
    ObjectNode kon = example();
    kon.remove("credentials");
    assertEquals(List.of("credentials is required"), KonValidator.errors(kon));
    kon.putObject("credentials");
    assertEquals(List.of("credentials.type is required"), KonValidator.errors(kon));
    kon.putObject("credentials").put("type", "oauth");
    assertEquals(List.of("credentials.type 'oauth' ist unbekannt"), KonValidator.errors(kon));
    kon.putObject("credentials").put("type", "basic").put("username", "u").put("password", "");
    assertEquals(List.of("credentials.password is required"), KonValidator.errors(kon));
    kon.putObject("credentials").put("type", "system");
    assertEquals(List.of("credentials.name is required"), KonValidator.errors(kon));
  }

  @Test
  @DisplayName(
      "§4 ${VAR} im Rohtext an jeder Stelle, undefiniert → leer, $VAR und ${A:-b} wörtlich")
  void substitution() throws Exception {
    assertEquals(
        "https://h:8443 $PORT x",
        KonFile.substitute(
            "https://${HOST}:${PORT} $PORT x${UNSET}", Map.of("HOST", "h", "PORT", "8443")));
    assertEquals("[b]", KonFile.substitute("[${A:-b}]", Map.of("A:-b", "b")));
    assertEquals(
        true,
        KonFile.load("{\"rewrite\": ${FLAG}}", Map.of("FLAG", "true")).get("rewrite").asBoolean());
    assertThrows(Exception.class, () -> KonFile.load("{\"url\": ${UNSET}}", Map.of()));
  }

  @Test
  @DisplayName(
      "Beispiel liana-phase0.kon: mit LIANA_BASIC_PASSWORD gültig, ohne → password is required (§4.1)")
  void beispielDateiMitVariable() throws Exception {
    String raw = Files.readString(Path.of("support/kon/examples/liana-phase0.kon"));
    assertEquals(
        List.of(),
        KonValidator.errors(KonFile.load(raw, Map.of("LIANA_BASIC_PASSWORD", "geheim"))));
    assertEquals(
        "geheim",
        KonFile.load(raw, Map.of("LIANA_BASIC_PASSWORD", "geheim"))
            .at("/credentials/password")
            .asText());
    assertEquals(
        List.of("credentials.password is required"),
        KonValidator.errors(KonFile.load(raw, Map.of())));
  }
}

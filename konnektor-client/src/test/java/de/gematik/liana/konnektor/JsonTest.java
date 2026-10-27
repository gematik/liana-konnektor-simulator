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
package de.gematik.liana.konnektor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class JsonTest {

  @Test
  @DisplayName("RFC 8259: Objekte, Arrays, Zeichenketten mit Escapes, Zahlen, Literale")
  void parse() {
    assertEquals(
        Map.of("a", List.of(1.0, -2.5, true, false), "b", "x\"\\/\nä", "c", Map.of()),
        Json.parse(
            " {\"a\": [1, -2.5, true, false], \"b\": \"x\\\"\\\\\\/\\n\\u00e4\", \"c\": {}} "));
    assertEquals(null, Json.parse("null"));
  }

  @Test
  @DisplayName("Fehler nennen Zeile und Spalte, nie den Inhalt")
  void fehler() {
    IllegalArgumentException e =
        assertThrows(
            IllegalArgumentException.class, () -> Json.parse("{\n  \"password\": \"geheim\" x}"));
    assertEquals("kein gültiges JSON (Zeile 2, Spalte 24): '}' erwartet", e.getMessage());
    assertFalse(e.getMessage().contains("geheim"));
    assertThrows(IllegalArgumentException.class, () -> Json.parse("{\"a\":1,\"a\":2}"));
    assertThrows(IllegalArgumentException.class, () -> Json.parse("[1,]"));
    assertThrows(IllegalArgumentException.class, () -> Json.parse("\"offen"));
    assertThrows(IllegalArgumentException.class, () -> Json.parse("{} {}"));
  }
}

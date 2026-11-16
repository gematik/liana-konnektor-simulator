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
package de.gematik.liana.wiring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** LIANA-195.04: the symbolic name of this connector in the trace. */
class TraceWiringTest {

  private static final Optional<String> NONE = Optional.empty();

  @Test
  @DisplayName("liana.trace.name geht vor, sonst Host aus liana.tls.url, dann liana.kon-export.url")
  void reihenfolge() {
    assertEquals(
        "konnektor-a",
        TraceWiring.name(
            Optional.of("konnektor-a"),
            Optional.of("https://tls.example"),
            Optional.of("http://kon.example")));
    assertEquals(
        "tls.example",
        TraceWiring.name(NONE, Optional.of("https://tls.example:443"), Optional.of("http://k")));
    assertEquals("kon.example", TraceWiring.name(NONE, NONE, Optional.of("http://kon.example")));
  }

  @Test
  @DisplayName(
      "Ohne brauchbaren Host (IP, localhost, keine URL) gilt konnektor: Tiger nimmt nur Namen")
  void rueckfall() {
    assertEquals("konnektor", TraceWiring.name(NONE, NONE, NONE));
    assertEquals(
        "konnektor",
        TraceWiring.name(
            NONE, Optional.of("https://192.168.1.10:8443"), Optional.of("http://localhost:8080")));
    assertEquals("konnektor", TraceWiring.name(NONE, Optional.of("kein url"), NONE));
  }

  @ParameterizedTest
  @ValueSource(strings = {"10.0.0.5", "localhost", "konnektor a", "konnektor/1.2.3.4", ""})
  @DisplayName("liana.trace.name als IP, localhost oder mit fremden Zeichen bricht den Start ab")
  void ungueltig(String name) {
    IllegalArgumentException e =
        assertThrows(
            IllegalArgumentException.class, () -> TraceWiring.name(Optional.of(name), NONE, NONE));
    assertTrue(e.getMessage().startsWith("liana.trace.name"), e.getMessage());
  }
}

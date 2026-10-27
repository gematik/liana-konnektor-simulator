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
package de.gematik.liana.contract;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class SchemasTest {

  private static final Path SCHEMAS = Path.of("support/schemas");

  @Test
  @DisplayName("LIANA-131: jede Datei aus support/schemas liegt unverändert auf dem Klassenpfad")
  void allSchemasPackaged() throws Exception {
    List<Path> files;
    try (Stream<Path> walk = Files.walk(SCHEMAS)) {
      files = walk.filter(Files::isRegularFile).toList();
    }
    assertTrue(files.size() > 50, "Schemas gefunden: " + files.size());
    for (Path file : files) {
      try (InputStream in =
          Schemas.resource(SCHEMAS.relativize(file).toString().replace('\\', '/')).openStream()) {
        assertArrayEquals(Files.readAllBytes(file), in.readAllBytes(), file.toString());
      }
    }
  }

  @Test
  @DisplayName("LIANA-131: relative schemaLocation löst innerhalb des Vertrags auf")
  void relativeImportsResolve() throws Exception {
    URL wsdl = Schemas.resource("conn/EventService.wsdl");
    assertEquals(Schemas.resource("conn/EventService.xsd"), new URL(wsdl, "EventService.xsd"));
  }

  @Test
  @DisplayName("Unbekannte Datei: IllegalArgumentException mit api-telematik-Version")
  void unknown() {
    IllegalArgumentException e =
        assertThrows(IllegalArgumentException.class, () -> Schemas.resource("conn/Unbekannt.wsdl"));
    assertTrue(e.getMessage().contains(Schemas.API_TELEMATIK));
  }
}

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
package de.gematik.liana.adapter.fake;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * LIANA-121: kartos binary from the configuration, otherwise from tools/kartos/; stand-ins are
 * shell scripts.
 */
class KartosLocatorTest {

  @TempDir Path root;

  private Path bundled;

  @BeforeEach
  void bundledPath() {
    bundled = KartosLocator.bundledPath(root).orElse(null);
    Assumptions.assumeTrue(bundled != null, "kein eingechecktes kartos für dieses System");
  }

  @Test
  @DisplayName("Konfigurierter Pfad gewinnt, die Version kommt aus kartos --version")
  void configured() throws IOException {
    Path kartos = script(root.resolve("bin/kartos"), "echo 'kartos 9.9.9'");
    script(bundled, "echo 'kartos 0.0.1'");
    assertEquals(
        new KartosLocator.Kartos(kartos, "kartos 9.9.9"), KartosLocator.resolve(kartos, root));
  }

  @Test
  @DisplayName(
      "Fehlt der konfigurierte Pfad (quarkus:dev, Default /opt/liana/bin/kartos), gilt tools/kartos/ im Repo")
  void fallbackToBundled() throws IOException {
    script(bundled, "echo 'kartos 0.0.1'");
    assertEquals(
        new KartosLocator.Kartos(bundled, "kartos 0.0.1"),
        KartosLocator.resolve(root.resolve("opt/liana/bin/kartos"), root));
  }

  @Test
  @DisplayName(
      "Ohne lauffähiges kartos scheitert die Auflösung; die Meldung nennt jeden Kandidaten und "
          + "LIANA_CARD_KARTOS_BIN")
  void notFound() throws IOException {
    Path configured = root.resolve("opt/liana/bin/kartos");
    IllegalStateException e =
        assertThrows(IllegalStateException.class, () -> KartosLocator.resolve(configured, root));
    assertTrue(e.getMessage().contains(configured + ": fehlt"), e.getMessage());
    assertTrue(e.getMessage().contains(bundled + ": fehlt"), e.getMessage());
    assertTrue(e.getMessage().contains("LIANA_CARD_KARTOS_BIN"), e.getMessage());
  }

  @Test
  @DisplayName(
      "Nicht ausführbar oder --version scheitert (z. B. falsche Architektur): kein Kandidat")
  void notRunnable() throws IOException {
    Path configured =
        script(root.resolve("bin/kartos"), "echo 'cannot execute binary file' >&2; exit 126");
    Files.createDirectories(bundled.getParent());
    Files.writeString(bundled, "#!/bin/sh\necho 'kartos 0.0.1'\n");
    IllegalStateException e =
        assertThrows(IllegalStateException.class, () -> KartosLocator.resolve(configured, root));
    assertTrue(
        e.getMessage()
            .contains(configured + ": --version endet mit Exit 126: cannot execute binary file"),
        e.getMessage());
    assertTrue(e.getMessage().contains(bundled + ": nicht ausführbar"), e.getMessage());
  }

  private static Path script(Path file, String body) throws IOException {
    Files.createDirectories(file.getParent());
    Files.writeString(file, "#!/bin/sh\n" + body + "\n");
    Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rwxr-xr-x"));
    return file;
  }
}

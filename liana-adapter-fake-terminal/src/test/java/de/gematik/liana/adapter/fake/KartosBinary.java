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

import java.nio.file.Path;
import org.junit.jupiter.api.Assumptions;

/**
 * kartos binary for ITs: {@code LIANA_KARTOS_BIN}, otherwise the checked-in one from {@code
 * tools/kartos/} by the same rule as LIANA ({@link KartosLocator}, LIANA-16, LIANA-121). On other
 * systems without {@code LIANA_KARTOS_BIN} the test is skipped.
 */
public final class KartosBinary {

  private KartosBinary() {}

  public static Path path() {
    String explicit = System.getenv("LIANA_KARTOS_BIN");
    if (explicit != null && !explicit.isBlank()) {
      return Path.of(explicit);
    }
    Path bundled = KartosLocator.bundledPath(Path.of("")).orElse(null);
    Assumptions.assumeTrue(
        bundled != null,
        "eingecheckte kartos-Binaries gibt es nur für Linux und macOS (amd64, arm64); sonst LIANA_KARTOS_BIN setzen");
    if (KartosLocator.bundled(Path.of("")).isEmpty()) {
      throw new IllegalStateException(bundled + " fehlt oder ist nicht ausführbar");
    }
    return bundled;
  }
}

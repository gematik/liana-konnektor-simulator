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

import java.net.URL;

/**
 * WSDL and XSD of the Konnektor's external interface (api-telematik, version see {@code SOURCE.md})
 * on the classpath, packaged from {@code support/schemas} (LIANA-131). Relative {@code
 * schemaLocation}s resolve because the directory structure is unchanged.
 */
public final class Schemas {

  /** Pinned version of api-telematik. */
  public static final String API_TELEMATIK = "6.0.3";

  private static final String ROOT = "schemas/";

  /**
   * Quirks table (LIANA-134): known deviations of real Konnektors and of LIANA, each entry with its
   * source.
   */
  public static URL quirks() {
    return Schemas.class.getResource("quirks.json");
  }

  private Schemas() {}

  /**
   * A schema file relative to {@code support/schemas}, such as {@code conn/EventService.wsdl}.
   *
   * @throws IllegalArgumentException if the file is not part of the contract
   */
  public static URL resource(String path) {
    URL url = Schemas.class.getResource(ROOT + path);
    if (url == null) {
      throw new IllegalArgumentException(
          "Nicht im Vertrag (api-telematik " + API_TELEMATIK + "): " + path);
    }
    return url;
  }
}

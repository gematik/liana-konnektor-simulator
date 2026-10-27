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
package de.gematik.liana.konnektor.conformance;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import de.gematik.liana.control.LianaControl;
import de.gematik.liana.konnektor.Konnektor;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * LIANA-134 AC 1 against the running LIANA: for each vendor profile, switched via the Admin API
 * ({@code conformance.liana-admin}, e.g. {@code http://localhost:9090}), the client recognizes the
 * matching product of the quirks table. Against other Konnektors: the product is recognized, or the
 * client works from the SDS alone.
 */
@ExtendWith(ConformanceTarget.class)
class ProductIT {

  static final String ADMIN = "conformance.liana-admin";

  @Test
  @DisplayName("Produkt aus connector.sds und Quirks-Tabelle; unbekannt ist kein Fehler")
  void produkt() throws Exception {
    Konnektor kon = ConformanceTarget.konnektor();
    assertNotNull(kon.info().product(), "ProductInformation aus connector.sds");
    System.out.println(
        "Produkt: "
            + kon.info().product()
            + " → "
            + kon.info().known().map(k -> k.id()).orElse("unbekannt, nur connector.sds"));
  }

  @Test
  @DisplayName("LIANA je Herstellerprofil als LIANA, LIANA-KOCO, LIANA-RISE, LIANA-SECUNET erkannt")
  void lianaProfile() throws Exception {
    String admin = ConformanceTarget.setting(ADMIN);
    assumeTrue(admin != null, ADMIN + " nicht gesetzt");
    LianaControl liana = LianaControl.connect(admin);
    Konnektor kon = ConformanceTarget.konnektor();
    try {
      for (Map.Entry<String, String> profile :
          Map.of(
                  "neutral",
                  "LIANA",
                  "KOCO",
                  "LIANA-KOCO",
                  "RISE",
                  "LIANA-RISE",
                  "SECUNET",
                  "LIANA-SECUNET",
                  "EHEX",
                  "LIANA",
                  "CGM",
                  "LIANA")
              .entrySet()) {
        liana.setVendor(profile.getKey(), null);
        kon.refresh();
        assertEquals(profile.getValue(), kon.info().known().orElseThrow().id(), profile.getKey());
      }
    } finally {
      liana.reset();
      kon.refresh();
    }
  }
}

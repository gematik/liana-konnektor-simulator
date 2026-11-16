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
package de.gematik.liana.config;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.gematik.liana.crypto.TestP12;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** LIANA-220: the startup check for a slot with a PKCS#12. */
class ConfigCheckP12Test {

  @TempDir Path folder;

  private List<String> errors(String slot) throws Exception {
    return ConfigCheck.errors(
        TestConfig.load(
            Map.of(
                "liana.card-images",
                "./support/images,./support/images/gsmc-kt,./support/images/gsmc-k," + folder,
                "liana.infrastructure.terminals.KT-02.slots.1",
                slot)));
  }

  @Test
  @DisplayName(
      "LIANA-220 Startprüfung: brauchbare p12 im Slot ohne Fehler; unbrauchbare meldet KT/Slot,"
          + " Datei und Grund; eine unbrauchbare p12, die kein Slot wählt, stört nicht")
  void slots() throws Exception {
    TestP12.write(folder.resolve("smcb_private.p12"), "00", "1-SMC-B-Testkarte--883110000999930");
    Path secret = TestP12.write(folder.resolve("kaputt.p12"), "geheim-220", "x");
    Path noAdmission = TestP12.write(folder.resolve("ohne.p12"), "00", null);

    assertEquals(List.of(), errors("smcb_private"));
    assertEquals(
        List.of(
            "KT-02/1: "
                + secret
                + ": keine lesbare PKCS#12, keins der 7 Passwörter passt (card-p12.passwords und"
                + " leeres Passwort)"),
        errors("kaputt"));
    assertEquals(
        List.of(
            "KT-02/1: "
                + noAdmission
                + ": keine Telematik-ID (Admission, registrationNumber) im Zertifikat"
                + " CN=Praxis LIANA-220 TEST-ONLY,C=DE"),
        errors("ohne"));
  }
}

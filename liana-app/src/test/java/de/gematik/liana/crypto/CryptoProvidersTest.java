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
package de.gematik.liana.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class CryptoProvidersTest {

  private final String before = System.getProperty(CryptoProviders.RSA_MR_TESTS);

  @AfterEach
  void restore() {
    if (before == null) {
      System.clearProperty(CryptoProviders.RSA_MR_TESTS);
    } else {
      System.setProperty(CryptoProviders.RSA_MR_TESTS, before);
    }
  }

  @Test
  @DisplayName(
      "LIANA-178: configure schaltet die Miller-Rabin-Prüfung der RSA-Moduli von BC ab, ein gesetzter Wert bleibt")
  void millerRabinAus() {
    System.clearProperty(CryptoProviders.RSA_MR_TESTS);
    CryptoProviders.configure();
    assertEquals("0", System.getProperty(CryptoProviders.RSA_MR_TESTS));
    System.setProperty(CryptoProviders.RSA_MR_TESTS, "5");
    CryptoProviders.configure();
    assertEquals("5", System.getProperty(CryptoProviders.RSA_MR_TESTS));
  }
}

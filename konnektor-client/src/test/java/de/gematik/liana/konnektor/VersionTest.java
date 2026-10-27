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
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class VersionTest {

  @Test
  @DisplayName(
      "TIP1-A_4966: Haupt- und Nebenversion müssen passen, die Revision nicht; Ordnung numerisch")
  void version() {
    assertTrue(Version.parse("8.2.5").compatibleWith(8, 2));
    assertFalse(Version.parse("8.1.2").compatibleWith(8, 2));
    assertTrue(Version.parse("8.10.0").compareTo(Version.parse("8.9.9")) > 0);
    assertEquals(new Version(6, 1, 0), Version.parse("6.1"));
    assertThrows(IllegalArgumentException.class, () -> Version.parse("v8"));
  }
}

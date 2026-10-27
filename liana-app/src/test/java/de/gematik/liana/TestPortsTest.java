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
package de.gematik.liana;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** LIANA-154: fixed test ports lie below the ephemeral ranges and are distinct. */
class TestPortsTest {

  @Test
  @DisplayName(
      "HTTP, HTTPS, Admin, TLS, KMS, CATS aus 20000..32000, keiner doppelt; free() vergibt nie zweimal")
  void ausserhalbEphemeral() {
    List<Integer> ports =
        List.of(
            TestPorts.HTTP,
            TestPorts.HTTPS,
            TestPorts.ADMIN,
            TestPorts.TLS,
            TestPorts.KMS,
            TestPorts.CATS);
    ports.forEach(
        p -> assertTrue(p >= TestPorts.RANGE_START && p < TestPorts.RANGE_END, String.valueOf(p)));
    assertEquals(ports.size(), Set.copyOf(ports).size());
    assertTrue(!ports.contains(TestPorts.free()));
  }
}

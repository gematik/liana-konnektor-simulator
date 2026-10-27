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
package de.gematik.liana.kern.signature;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.kern.access.Context;
import de.gematik.liana.kern.error.ConnectorError;
import de.gematik.liana.kern.error.ConnectorException;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class JobNumbersTest {

  private static final Context CTX = new Context("M1", "CS1", "WP1", null);

  @Test
  @DisplayName("TIP1-A_4643 / TIP1-A_4645: drei Buchstaben A-Z, Bindestrich, drei Ziffern")
  void format() {
    JobNumbers jobs = new JobNumbers();
    for (int i = 0; i < 100; i++) {
      assertTrue(jobs.next(CTX).matches("[A-Z]{3}-[0-9]{3}"));
    }
  }

  @Test
  @DisplayName(
      "TIP1-A_4644: innerhalb von 1000 Aufrufen eindeutig, auch wenn der Zufall sich wiederholt")
  void eindeutig() {
    // the randomness yields every number twice in a row: AAA-000, AAA-000, BAA-000, BAA-000, …
    JobNumbers jobs =
        new JobNumbers(
            new Random() {
              private int n;

              @Override
              public int nextInt(int bound) {
                int candidate = n / 12;
                int position = n++ % 6;
                return position < 3 ? candidate / (int) Math.pow(26, position) % 26 : 0;
              }
            });
    Set<String> seen = new HashSet<>();
    for (int i = 0; i < JobNumbers.UNIQUE_CALLS; i++) {
      assertTrue(seen.add(jobs.next(CTX)), "Wiederholung nach " + i + " Aufrufen");
    }
  }

  @Test
  @DisplayName(
      "TAB_KON_843 / TAB_KON_845: MandantId, ClientSystemId und WorkplaceId sind Pflicht, sonst 4000")
  void kontext() {
    ConnectorException e =
        assertThrows(
            ConnectorException.class,
            () -> new JobNumbers().next(new Context("M1", "CS1", null, null)));
    assertEquals(ConnectorError.SYNTAX, e.error());
  }

  @Test
  @DisplayName(
      "TAB_KON_757 4252: SignDocument verwendet eine Jobnummer nur einmal, nach 1000 weiteren wieder")
  void einmalVerwenden() {
    JobNumbers jobs = new JobNumbers();
    jobs.use("ABC-123");
    assertEquals(
        ConnectorError.JOB_NUMBER_USED,
        assertThrows(ConnectorException.class, () -> jobs.use("ABC-123")).error());
    for (int i = 0; i < JobNumbers.UNIQUE_CALLS; i++) {
      jobs.use("X" + i);
    }
    jobs.use("ABC-123");
  }
}

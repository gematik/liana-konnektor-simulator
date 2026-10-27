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
package de.gematik.liana.kern.vendor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.kern.event.SystemLog;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class PeerDeviationsTest {

  private final SystemLog log =
      new SystemLog(Clock.fixed(Instant.parse("2026-10-14T12:00:00Z"), ZoneOffset.UTC), 10);

  @Test
  @DisplayName(
      "LIANA-126 ohne strict: ausweichen, TUC_KON_271 Op/Warning LIANA/DEVIATION mit Gegenstelle, Spec-Stelle, Beobachtung und Ausweichen")
  void tolerated() {
    PeerDeviations deviations = new PeerDeviations(false, log);

    assertTrue(
        deviations.tolerate(
            Deviation.KARTOS_MODIFY_VERIFICATION_DATA, "KT-03", Map.of("StatusWord", "6A80")));

    SystemLog.Entry entry = single();
    assertEquals(SystemLog.Type.OP, entry.type());
    assertEquals(SystemLog.Severity.WARN, entry.severity());
    assertEquals("LIANA/DEVIATION", entry.topic());
    assertEquals(
        List.of("Deviation", "Peer", "Spec", "Observed", "StatusWord", "Action"),
        List.copyOf(entry.parameters().keySet()));
    assertEquals("KARTOS_MODIFY_VERIFICATION_DATA", entry.parameters().get("Deviation"));
    assertEquals("KT-03", entry.parameters().get("Peer"));
    assertEquals("SICCT 1.2.3 §5.20 MODIFY VERIFICATION DATA", entry.parameters().get("Spec"));
    assertEquals("6A80", entry.parameters().get("StatusWord"));
    assertEquals("Kommando im kartos-Format wiederholen", entry.parameters().get("Action"));
  }

  @Test
  @DisplayName("LIANA-126 mit strict: nicht ausweichen, derselbe Eintrag als Error")
  void strict() {
    PeerDeviations deviations = new PeerDeviations(true, log);

    assertFalse(deviations.tolerate(Deviation.KARTOS_MODIFY_VERIFICATION_DATA, "KT-03", Map.of()));

    SystemLog.Entry entry = single();
    assertEquals(SystemLog.Severity.ERR, entry.severity());
    assertEquals("LIANA/DEVIATION", entry.topic());
    assertEquals("abgewiesen (strict)", entry.parameters().get("Action"));
  }

  @Test
  @DisplayName("decision-4: Umschalten ist flüchtig, reset stellt den Boot-Stand her")
  void switchAndReset() {
    PeerDeviations deviations = new PeerDeviations(false, log);
    deviations.setStrict(true);
    assertTrue(deviations.strict());
    assertFalse(deviations.tolerate(Deviation.KARTOS_MODIFY_VERIFICATION_DATA, "KT-03", Map.of()));
    deviations.reset();
    assertFalse(deviations.strict());
    assertFalse(deviations.boot());
  }

  @Test
  @DisplayName(
      "LIANA-126: jede bekannte Abweichung nennt Gegenstelle, Spec-Stelle, Beobachtung und Ausweichen")
  void described() {
    for (Deviation deviation : Deviation.values()) {
      assertFalse(deviation.peer().isBlank(), deviation.name());
      assertFalse(deviation.spec().isBlank(), deviation.name());
      assertFalse(deviation.observed().isBlank(), deviation.name());
      assertFalse(deviation.fallback().isBlank(), deviation.name());
    }
  }

  private SystemLog.Entry single() {
    List<SystemLog.Entry> entries = log.entries(null, null);
    assertEquals(1, entries.size());
    return entries.getFirst();
  }
}

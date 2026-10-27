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
package de.gematik.liana.kern.event;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.gematik.liana.kern.card.CardData;
import de.gematik.liana.kern.card.CardEvent;
import de.gematik.liana.kern.card.CardObject;
import de.gematik.liana.kern.card.CardSessions;
import de.gematik.liana.kern.card.CardType;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class SystemLogTest {

  private static final Instant T0 = Instant.parse("2026-10-09T12:00:00Z");

  private Instant now = T0;
  private final SystemLog log =
      new SystemLog(
          new Clock() {
            @Override
            public java.time.ZoneId getZone() {
              return ZoneOffset.UTC;
            }

            @Override
            public Clock withZone(java.time.ZoneId zone) {
              return this;
            }

            @Override
            public Instant instant() {
              return now;
            }
          },
          3);

  @Test
  @DisplayName(
      "TIP1-A_4715 TUC_KON_271: Eintrag mit Zeitstempel, Typ, Schwere, Topic und Parametern in Reihenfolge")
  void write() {
    log.write(
        SystemLog.Type.OP,
        SystemLog.Severity.INFO,
        "CARD/SESSION/TIMEOUT",
        Map.of("Timer", "PoPP"));
    SystemLog.Entry entry = log.entries(null, null).getFirst();
    assertEquals(
        new SystemLog.Entry(
            T0,
            SystemLog.Type.OP,
            SystemLog.Severity.INFO,
            "CARD/SESSION/TIMEOUT",
            Map.of("Timer", "PoPP")),
        entry);
  }

  @Test
  @DisplayName(
      "LIANA-150: jeder neue Eintrag geht nach dem Schreiben an die Listener (Push der Admin-API)")
  void listener() {
    List<SystemLog.Entry> seen = new java.util.ArrayList<>();
    log.addListener(
        entry -> {
          seen.add(entry);
          assertEquals(List.of(entry), log.entries(null, null), "schon im Protokoll, Lock frei");
        });
    SystemLog.Entry entry =
        log.write(SystemLog.Type.OP, SystemLog.Severity.INFO, "LIANA/TEST", Map.of());
    assertEquals(List.of(entry), seen);
  }

  @Test
  @DisplayName(
      "A_25860-01: CARD/SESSION/TIMEOUT als Op/Info mit CardType, SessionID und Timer=Konnektor|PoPP")
  void sessionTimeout() {
    log.sessionTimeout(new CardSessions.Timeout("EGK", "s-1", CardSessions.Timeout.KONNEKTOR));
    log.sessionTimeout(new CardSessions.Timeout("EGK", "s-2", CardSessions.Timeout.POPP));
    List<SystemLog.Entry> entries = log.entries(null, null);
    assertEquals(
        List.of("CardType", "SessionID", "Timer"),
        List.copyOf(entries.getFirst().parameters().keySet()));
    assertEquals(
        Map.of("CardType", "EGK", "SessionID", "s-1", "Timer", "Konnektor"),
        entries.get(0).parameters());
    assertEquals(
        Map.of("CardType", "EGK", "SessionID", "s-2", "Timer", "PoPP"),
        entries.get(1).parameters());
    assertEquals("CARD/SESSION/TIMEOUT", entries.get(1).topic());
    assertEquals(SystemLog.Type.OP, entries.get(1).type());
    assertEquals(SystemLog.Severity.INFO, entries.get(1).severity());
  }

  @Test
  @DisplayName("TIP1-A_4710-02: CARD/INSERTED ohne ICCSN, CardHolderName und KVNR")
  void cardEventOhnePersonenbezug() {
    CardData data =
        new CardData(
            CardType.EGK, "80276883110000000001", null, "Erika Mustermann", "X110000001", null);
    log.cardEvent(
        new CardEvent(CardEvent.Topic.INSERTED, new CardObject("CH-1", "KT-01", 1, T0, data)));
    SystemLog.Entry entry = log.entries(null, null).getFirst();
    assertEquals("CARD/INSERTED", entry.topic());
    assertEquals(
        Map.of(
            "CardHandle",
            "CH-1",
            "CardType",
            "EGK",
            "CtID",
            "KT-01",
            "SlotID",
            "1",
            "InsertTime",
            "2026-10-09T12:00:00Z"),
        entry.parameters());
  }

  @Test
  @DisplayName(
      "Zeitfilter mit beiden Grenzen einschließlich, offene Grenzen, rollierend, clear leert")
  void filterRollingClear() {
    for (int i = 0; i < 4; i++) {
      log.write(SystemLog.Type.OP, SystemLog.Severity.INFO, "T" + i, Map.of());
      now = now.plus(1, ChronoUnit.SECONDS);
    }
    // capacity 3: T0 has dropped out
    assertEquals(List.of("T1", "T2", "T3"), topics(log.entries(null, null)));
    assertEquals(List.of("T1", "T2"), topics(log.entries(T0.plusSeconds(1), T0.plusSeconds(2))));
    assertEquals(List.of("T2", "T3"), topics(log.entries(T0.plusSeconds(2), null)));
    assertEquals(List.of("T1"), topics(log.entries(null, T0.plusSeconds(1))));
    log.clear();
    assertEquals(List.of(), log.entries(null, null));
  }

  private static List<String> topics(List<SystemLog.Entry> entries) {
    return entries.stream().map(SystemLog.Entry::topic).toList();
  }
}

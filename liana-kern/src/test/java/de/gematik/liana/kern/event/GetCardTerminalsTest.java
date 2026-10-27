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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.kern.access.Context;
import de.gematik.liana.kern.access.Infomodel;
import de.gematik.liana.kern.card.RecordedTerminal;
import de.gematik.liana.kern.error.ConnectorException;
import de.gematik.liana.kern.terminal.CardTerminalInfo;
import de.gematik.liana.kern.terminal.TerminalRegistry;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class GetCardTerminalsTest {

  private final TerminalRegistry registry =
      new TerminalRegistry(
          List.of(
              new RecordedTerminal("KT-01", 3, RecordedTerminal.EGK_VALID),
              new RecordedTerminal("KT-02", 2, RecordedTerminal.EGK_VALID),
              new RecordedTerminal("KT-03", 1, RecordedTerminal.EGK_VALID),
              new RecordedTerminal("KT-04", 1, RecordedTerminal.EGK_VALID)));
  private final Infomodel infomodel =
      new Infomodel(
          List.of("M1", "M2"),
          List.of("CS1", "CS2"),
          List.of(
              new Infomodel.Workplace(
                  "WP1", List.of("M1"), List.of("CS1"), List.of("KT-01", "KT-02")),
              new Infomodel.Workplace(
                  "WP2", List.of("M1"), List.of("CS1"), List.of("KT-02", "KT-03")),
              new Infomodel.Workplace("WP3", List.of("M2"), List.of("CS2"), List.of("KT-04"))));
  private final GetCardTerminals getCardTerminals = new GetCardTerminals(infomodel, registry);

  private List<String> ids(Context context, boolean mandantWide) {
    return getCardTerminals.execute(context, mandantWide).stream()
        .map(e -> e.info().ctId())
        .toList();
  }

  @Test
  @DisplayName(
      "TIP1-A_4604 / TUC_KON_252: ohne @mandant-wide die KTs des Arbeitsplatzes, mit allen Arbeitsplätzen "
          + "von Mandant und Clientsystem, in Reihenfolge der Konfiguration; fremde Mandanten bleiben außen vor")
  void auswahl() {
    assertEquals(List.of("KT-01", "KT-02"), ids(new Context("M1", "CS1", "WP1", null), false));
    assertEquals(List.of("KT-02", "KT-03"), ids(new Context("M1", "CS1", "WP2", null), false));
    assertEquals(
        List.of("KT-01", "KT-02", "KT-03"), ids(new Context("M1", "CS1", null, null), true));
    assertEquals(List.of("KT-04"), ids(new Context("M2", "CS2", null, null), true));
  }

  @Test
  @DisplayName(
      "TAB_KON_563: WorkplaceIds sind alle Arbeitsplätze, denen das KT als lokales KT zugeordnet ist; "
          + "ein Fake-KT ist verbunden, physisch, mit CT.SLOTCOUNT und lokal verwalteter MAC")
  void eintrag() {
    var entries = getCardTerminals.execute(new Context("M1", "CS1", "WP2", null), false);
    assertEquals(List.of("WP1", "WP2"), entries.getFirst().workplaceIds());
    CardTerminalInfo info = entries.getLast().info();
    assertEquals("KT-03", info.name());
    assertEquals(1, info.slots());
    assertTrue(info.connected() && info.physical());
    assertTrue(info.macAddress().matches("02-4C(-[0-9A-F]{2}){4}"), info.macAddress());
    assertEquals(
        CardTerminalInfo.fake("KT-03", 1).macAddress(), info.macAddress(), "stabil je CtId");
  }

  @Test
  @DisplayName(
      "TAB_KON_564 Schritt 2, TUC_KON_000: unvollständiger Kontext 4021, Arbeitsplatz eines anderen Mandanten "
          + "4011, Arbeitsplatz fehlt ohne @mandant-wide 4021")
  void zugriff() {
    assertEquals(4021, code(new Context("M9", "CS1", "WP1", null), false));
    assertEquals(4011, code(new Context("M2", "CS2", "WP1", null), false));
    assertEquals(4021, code(new Context("M1", "CS1", null, null), false));
  }

  private int code(Context context, boolean mandantWide) {
    return assertThrows(
            ConnectorException.class, () -> getCardTerminals.execute(context, mandantWide))
        .error()
        .code();
  }
}

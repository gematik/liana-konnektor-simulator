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

import de.gematik.liana.kern.access.Context;
import de.gematik.liana.kern.access.Infomodel;
import de.gematik.liana.kern.card.CardList;
import de.gematik.liana.kern.card.CardObject;
import de.gematik.liana.kern.card.CardType;
import de.gematik.liana.kern.card.RecordedTerminal;
import de.gematik.liana.kern.error.ConnectorError;
import de.gematik.liana.kern.error.ConnectorException;
import de.gematik.liana.kern.terminal.TerminalRegistry;
import java.time.Clock;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

class GetCardsTest {

  private static final Context CTX = new Context("M1", "CS1", "WP1", null);

  private final RecordedTerminal kt01 =
      new RecordedTerminal("KT-01", 3, RecordedTerminal.EGK_VALID);
  private final RecordedTerminal kt02 =
      new RecordedTerminal("KT-02", 2, RecordedTerminal.EGK_VALID);
  private final RecordedTerminal kt03 =
      new RecordedTerminal("KT-03", 1, RecordedTerminal.EGK_VALID);
  private final TerminalRegistry registry = new TerminalRegistry(List.of(kt01, kt02, kt03));
  private final CardList cards = new CardList(registry, Clock.systemUTC());
  private final Infomodel infomodel =
      new Infomodel(
          List.of("M1", "M2"),
          List.of("CS1", "CS2"),
          List.of(
              new Infomodel.Workplace(
                  "WP1", List.of("M1"), List.of("CS1"), List.of("KT-01", "KT-02")),
              new Infomodel.Workplace("WP2", List.of("M1"), List.of("CS1"), List.of("KT-03")),
              new Infomodel.Workplace("WP3", List.of("M2"), List.of("CS2"), List.of())));
  private final GetCards getCards = new GetCards(infomodel, registry, cards);

  @BeforeEach
  void stecken() {
    cards.start();
    kt01.insert(1);
    kt02.insert(2);
    kt03.insert(1);
  }

  private List<String> slots(String ctId, Integer slotId, String cardType, boolean mandantWide) {
    return getCards.execute(new GetCards.Request(CTX, ctId, slotId, cardType, mandantWide)).stream()
        .map(c -> c.ctId() + "/" + c.slotNo())
        .toList();
  }

  @Test
  @DisplayName(
      "TIP1-A_4605-03 / TUC_KON_253: Karten der KTs des Arbeitsplatzes, gefiltert nach CtId, SlotId, CardType")
  void filter() {
    assertEquals(List.of("KT-01/1", "KT-02/2"), slots(null, null, null, false));
    assertEquals(List.of("KT-01/1"), slots("KT-01", null, "EGK", false));
    assertEquals(List.of("KT-02/2"), slots("KT-02", 2, null, false));
    assertEquals(List.of(), slots("KT-02", 1, null, false));
    assertEquals(List.of(), slots(null, null, "SMC-B", false));
    assertEquals(List.of(), slots("KT-03", null, null, false), "KT-03 gehört nicht zu WP1");
    assertEquals(List.of("KT-01/1", "KT-02/2", "KT-03/1"), slots(null, null, null, true));
  }

  @Test
  @DisplayName("TUC_KON_001 2c: GetCards liefert die beim Stecken gelesenen Kartendaten")
  void kartendaten() {
    CardObject card =
        getCards.execute(new GetCards.Request(CTX, "KT-01", 1, "EGK", false)).getFirst();
    assertEquals(CardType.EGK, card.data().type());
    assertEquals("80276883110000168584", card.data().iccsn());
    assertEquals(cards.card("KT-01", 1).orElseThrow(), card);
  }

  @Test
  @DisplayName("TAB_KON_560: unbekannte CtId → 4007")
  void unbekanntesKt() {
    assertError(ConnectorError.INVALID_CT_ID, () -> slots("KT-99", null, null, false));
  }

  @Test
  @DisplayName(
      "TAB_KON_514-01: unbekannter Mandant, Clientsystem, Arbeitsplatz oder leerer Kontext → 4021")
  void unbekannterKontext() {
    for (Context ctx :
        List.of(
            new Context("M9", "CS1", "WP1", null),
            new Context("M1", "CS9", "WP1", null),
            new Context("M1", "CS1", "WP9", null),
            new Context("M1", "CS1", null, null),
            new Context(null, "CS1", "WP1", null))) {
      assertError(
          ConnectorError.CONTEXT_INCOMPLETE,
          () -> getCards.execute(new GetCards.Request(ctx, null, null, null, false)));
    }
  }

  @Test
  @DisplayName(
      "TAB_KON_514-01: Zuordnungen Mandant ↔ Clientsystem (4010), Arbeitsplatz ↔ Mandant (4011), ↔ CS (4014)")
  void zuordnungen() {
    assertError(
        ConnectorError.CS_NOT_IN_MANDANT,
        () ->
            getCards.execute(
                new GetCards.Request(
                    new Context("M1", "CS2", "WP1", null), null, null, null, false)));
    assertError(
        ConnectorError.WP_NOT_IN_MANDANT,
        () ->
            getCards.execute(
                new GetCards.Request(
                    new Context("M1", "CS1", "WP3", null), null, null, null, false)));
    Infomodel ohneCs =
        new Infomodel(
            List.of("M1"),
            List.of("CS1", "CS2"),
            List.of(
                new Infomodel.Workplace("WP1", List.of("M1"), List.of("CS1"), List.of()),
                new Infomodel.Workplace("WP2", List.of("M1"), List.of("CS2"), List.of())));
    assertError(
        ConnectorError.WP_NOT_FOR_CS,
        () ->
            new GetCards(ohneCs, registry, cards)
                .execute(
                    new GetCards.Request(
                        new Context("M1", "CS2", "WP1", null), null, null, null, false)));
  }

  @Test
  @DisplayName("TAB_KON_567 checkArguments: SlotId ohne CtId, unbekannter CardType → 4000")
  void checkArguments() {
    assertError(ConnectorError.SYNTAX, () -> slots(null, 1, null, false));
    assertError(ConnectorError.SYNTAX, () -> slots(null, null, "EGK2", false));
    assertEquals(List.of(), slots(null, null, "HBAx", false));
  }

  private static void assertError(ConnectorError expected, Executable call) {
    assertEquals(expected, assertThrows(ConnectorException.class, call).error());
  }
}

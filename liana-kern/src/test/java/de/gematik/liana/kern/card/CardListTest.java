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
package de.gematik.liana.kern.card;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.kern.terminal.CardTerminal;
import de.gematik.liana.kern.terminal.SlotListener;
import de.gematik.liana.kern.terminal.TerminalRegistry;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class CardListTest {

  /** Clock that the test advances instead of waiting. */
  static final class TestClock extends Clock {
    Instant now = Instant.parse("2026-10-08T12:00:00Z");

    void advance(Duration d) {
      now = now.plus(d);
    }

    @Override
    public ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return now;
    }
  }

  /** Terminal without card engine: insertion and removal report the slot events. */
  static final class StubTerminal implements CardTerminal {
    final String id;
    final boolean[] present;
    final List<SlotListener> listeners = new ArrayList<>();

    StubTerminal(String id, int slots) {
      this.id = id;
      this.present = new boolean[slots + 1];
    }

    void insert(int slot) {
      present[slot] = true;
      listeners.forEach(l -> l.slotInUse(id, slot));
    }

    void eject(int slot) {
      present[slot] = false;
      listeners.forEach(l -> l.slotFree(id, slot));
    }

    @Override
    public String id() {
      return id;
    }

    @Override
    public int slots() {
      return present.length - 1;
    }

    @Override
    public void addSlotListener(SlotListener listener) {
      listeners.add(listener);
    }

    @Override
    public boolean cardPresent(int slot) {
      return present[slot];
    }

    @Override
    public byte[] reset(int slot) {
      throw new UnsupportedOperationException();
    }

    @Override
    public byte[] transmit(int slot, byte[] commandApdu) {
      throw new UnsupportedOperationException();
    }
  }

  private final TestClock clock = new TestClock();
  private final StubTerminal kt01 = new StubTerminal("KT-01", 3);
  private final StubTerminal kt02 = new StubTerminal("KT-02", 2);
  private final CardList cards = new CardList(new TerminalRegistry(List.of(kt01, kt02)), clock);
  private final List<CardEvent> events = new ArrayList<>();

  {
    cards.addListener(events::add);
  }

  @Test
  @DisplayName(
      "TIP1-A_4563 / TIP1-A_4562: Stecken legt ein CardObject mit CardHandle an, Ziehen entfernt es")
  void steckenUndZiehen() {
    cards.start();
    assertEquals(List.of(), cards.cards());

    kt01.insert(2);
    CardObject card = cards.card("KT-01", 2).orElseThrow();
    assertEquals("KT-01", card.ctId());
    assertEquals(2, card.slotNo());
    assertEquals(clock.now, card.insertTime());
    assertEquals(card, cards.card(card.cardHandle()).orElseThrow());
    assertEquals(List.of(card), cards.cards());

    kt01.eject(2);
    assertEquals(List.of(), cards.cards());
    assertTrue(cards.card(card.cardHandle()).isEmpty());
    assertTrue(cards.card("KT-01", 2).isEmpty());
  }

  @Test
  @DisplayName(
      "TUC_KON_001: Ziehen und erneut Stecken liefert ein neues CardHandle, das alte bleibt 48 h ungenutzt")
  void neuesHandleNachZiehen() {
    cards.start();
    kt01.insert(1);
    String alt = cards.card("KT-01", 1).orElseThrow().cardHandle();
    kt01.eject(1);
    kt01.insert(1);
    String neu = cards.card("KT-01", 1).orElseThrow().cardHandle();
    assertNotEquals(alt, neu);
    assertTrue(cards.card(alt).isEmpty(), "altes Handle ist ungültig");

    Set<String> vergeben = new HashSet<>(Set.of(alt, neu));
    for (int stunde = 1; stunde <= 49; stunde++) {
      clock.advance(Duration.ofHours(1));
      kt01.eject(1);
      kt01.insert(1);
      kt02.insert(2);
      kt02.eject(2);
      assertTrue(vergeben.add(cards.card("KT-01", 1).orElseThrow().cardHandle()));
      assertTrue(vergeben.add(events.getLast().card().cardHandle()));
    }
    assertTrue(cards.card(alt).isEmpty());
  }

  @Test
  @DisplayName("TUC_KON_001: Handles eines Neustarts kollidieren nicht mit denen des vorigen Laufs")
  void neustart() {
    cards.start();
    kt01.insert(1);
    String vorher = cards.card("KT-01", 1).orElseThrow().cardHandle();

    clock.advance(Duration.ofSeconds(5));
    StubTerminal kt = new StubTerminal("KT-01", 3);
    CardList neu = new CardList(new TerminalRegistry(List.of(kt)), clock);
    neu.start();
    kt.insert(1);
    assertNotEquals(vorher, neu.card("KT-01", 1).orElseThrow().cardHandle());
  }

  @Test
  @DisplayName("TUC_KON_025: start öffnet die bereits gesteckten Karten über TUC_KON_001")
  void startOeffnetGesteckteKarten() {
    kt01.present[1] = true;
    kt02.present[2] = true;
    cards.start();
    assertEquals(
        List.of("KT-01/1", "KT-02/2"),
        cards.cards().stream().map(c -> c.ctId() + "/" + c.slotNo()).toList());
    assertEquals(
        List.of(CardEvent.Topic.INSERTED, CardEvent.Topic.INSERTED),
        events.stream().map(CardEvent::topic).toList());
  }

  @Test
  @DisplayName("CARD/INSERTED und CARD/REMOVED sind im Kern beobachtbar, ohne CETP")
  void ereignisse() {
    cards.start();
    kt02.insert(1);
    CardObject card = cards.card("KT-02", 1).orElseThrow();
    kt02.eject(1);
    kt02.eject(1);

    assertEquals(
        List.of(
            new CardEvent(CardEvent.Topic.INSERTED, card),
            new CardEvent(CardEvent.Topic.REMOVED, card)),
        events);
    assertEquals("CARD/INSERTED", events.get(0).topic().topic());
    assertEquals("CARD/REMOVED", events.get(1).topic().topic());
  }

  @Test
  @DisplayName("TUC_KON_001 Schritt 1: ein vorhandener Eintrag für denselben Slot wird ersetzt")
  void ersetzt() {
    cards.start();
    kt01.insert(3);
    String alt = cards.card("KT-01", 3).orElseThrow().cardHandle();
    kt01.insert(3);
    assertEquals(1, cards.cards().size());
    assertFalse(cards.card(alt).isPresent());
  }
}

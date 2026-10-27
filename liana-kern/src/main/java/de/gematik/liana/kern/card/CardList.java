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

import de.gematik.liana.kern.terminal.CardTerminal;
import de.gematik.liana.kern.terminal.SlotListener;
import de.gematik.liana.kern.terminal.TerminalRegistry;
import java.time.Clock;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/**
 * CM_CARD_LIST: the opened cards of the card service. Cards and CardHandles are created only via
 * slot events of the terminals (TIP1-A_4563, TUC_KON_001) and disappear on removal (TIP1-A_4562);
 * queries only read.
 *
 * <p>CardHandles consist of a prefix encoding the start time of this list and a running counter.
 * Within the process no handle is reused; across a restart the prefix keeps them apart (TUC_KON_001
 * step 2a: do not reassign a handle that became invalid for 48 h).
 */
public final class CardList implements SlotListener {

  private final TerminalRegistry terminals;
  private final Clock clock;
  private final String handlePrefix;
  private long nextHandle = 1;
  private final Map<String, CardObject> cards = new LinkedHashMap<>();
  private final List<Consumer<CardEvent>> listeners = new CopyOnWriteArrayList<>();

  public CardList(TerminalRegistry terminals, Clock clock) {
    this.terminals = terminals;
    this.clock = clock;
    this.handlePrefix = Long.toString(clock.millis(), Character.MAX_RADIX);
  }

  /**
   * TUC_KON_025 „Initialisierung Kartendienst“: registers with all terminals for slot events and
   * opens every card already inserted via TUC_KON_001.
   */
  public void start() {
    terminals.terminals().forEach(terminal -> terminal.addSlotListener(this));
    for (CardTerminal terminal : terminals.terminals()) {
      for (int slot = 1; slot <= terminal.slots(); slot++) {
        if (terminal.cardPresent(slot)) {
          open(terminal.id(), slot);
        }
      }
    }
  }

  /** From now on reports CARD/INSERTED and CARD/REMOVED to {@code listener}. */
  public void addListener(Consumer<CardEvent> listener) {
    listeners.add(listener);
  }

  /** TIP1-A_4563: CT/SLOT_IN_USE opens the card (TUC_KON_001). */
  @Override
  public void slotInUse(String ctId, int slot) {
    open(ctId, slot);
  }

  /** TIP1-A_4562: CT/SLOT_FREE reports CARD/REMOVED and removes the CardObject. */
  @Override
  public void slotFree(String ctId, int slot) {
    CardObject card;
    synchronized (this) {
      card = find(ctId, slot).orElse(null);
      if (card == null) {
        return;
      }
      cards.remove(card.cardHandle());
      notifyAll();
    }
    fire(new CardEvent(CardEvent.Topic.REMOVED, card));
  }

  /** All opened cards in the order of opening. */
  public synchronized List<CardObject> cards() {
    return List.copyOf(cards.values());
  }

  /**
   * The CardObject for {@code cardHandle}; empty if the handle is unknown or has become invalid.
   */
  public synchronized Optional<CardObject> card(String cardHandle) {
    return Optional.ofNullable(cards.get(cardHandle));
  }

  /** The CardObject of the card in {@code ctId}/{@code slot}. */
  public synchronized Optional<CardObject> card(String ctId, int slot) {
    return find(ctId, slot);
  }

  /**
   * Waits at most {@code wait} until the card in {@code ctId}/{@code slot} is opened ({@code
   * opened}, TUC_KON_056 step 4: the event „Karte gesteckt“ has been processed) or removed, and
   * returns the entry afterwards.
   */
  public synchronized Optional<CardObject> await(
      String ctId, int slot, boolean opened, Duration wait) throws InterruptedException {
    long deadline = System.nanoTime() + wait.toNanos();
    for (Optional<CardObject> card = find(ctId, slot); ; card = find(ctId, slot)) {
      long left = deadline - System.nanoTime();
      if (card.isPresent() == opened || left <= 0) {
        return card;
      }
      TimeUnit.NANOSECONDS.timedWait(this, left);
    }
  }

  /**
   * TUC_KON_001 „Karte öffnen“: read card data (2c), replace entry (1), assign handle (2a),
   * CARD/INSERTED (3).
   */
  private void open(String ctId, int slot) {
    CardReader.Reading reading =
        terminals
            .terminal(ctId)
            .map(t -> CardReader.open(t, slot))
            .orElse(
                new CardReader.Reading(CardData.UNKNOWN, "Kartenterminal " + ctId + " unbekannt"));
    CardObject card;
    synchronized (this) {
      find(ctId, slot).ifPresent(old -> cards.remove(old.cardHandle()));
      card =
          new CardObject(
              handlePrefix + "-" + nextHandle++,
              ctId,
              slot,
              clock.instant(),
              reading.data(),
              reading.unknownReason());
      cards.put(card.cardHandle(), card);
      notifyAll();
    }
    fire(new CardEvent(CardEvent.Topic.INSERTED, card));
  }

  private Optional<CardObject> find(String ctId, int slot) {
    return cards.values().stream()
        .filter(c -> c.ctId().equals(ctId) && c.slotNo() == slot)
        .findFirst();
  }

  private void fire(CardEvent event) {
    listeners.forEach(listener -> listener.accept(event));
  }
}

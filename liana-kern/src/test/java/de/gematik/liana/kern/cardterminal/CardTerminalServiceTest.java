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
package de.gematik.liana.kern.cardterminal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.kern.access.Context;
import de.gematik.liana.kern.access.Infomodel;
import de.gematik.liana.kern.card.CardList;
import de.gematik.liana.kern.card.CardLocks;
import de.gematik.liana.kern.card.CardType;
import de.gematik.liana.kern.card.RecordedCards;
import de.gematik.liana.kern.card.RecordedTerminal;
import de.gematik.liana.kern.error.ConnectorException;
import de.gematik.liana.kern.event.SystemLog;
import de.gematik.liana.kern.terminal.CardTerminal;
import de.gematik.liana.kern.terminal.DisplayBusyException;
import de.gematik.liana.kern.terminal.SlotListener;
import de.gematik.liana.kern.terminal.TerminalRegistry;
import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

class CardTerminalServiceTest {

  private static final Context CTX = new Context("M1", "CS1", "WP1", null);

  /**
   * CT with user: {@code user} reacts to REQUEST ICC or EJECT ICC (inserts, removes or does
   * nothing), then the CT reports like SICCT whether a card is inserted or the slot is free. {@link
   * #calls} records slot, display and wait time.
   */
  static final class UserTerminal implements CardTerminal {
    final RecordedCards cards;
    final List<String> calls = new ArrayList<>();
    Function<String, IOException> user = command -> null;

    UserTerminal(RecordedCards cards) {
      this.cards = cards;
    }

    @Override
    public String id() {
      return cards.id();
    }

    @Override
    public int slots() {
      return cards.slots();
    }

    @Override
    public void addSlotListener(SlotListener listener) {
      cards.addSlotListener(listener);
    }

    @Override
    public boolean cardPresent(int slot) {
      return cards.cardPresent(slot);
    }

    @Override
    public byte[] reset(int slot) {
      return cards.reset(slot);
    }

    @Override
    public byte[] transmit(int slot, byte[] commandApdu) {
      return cards.transmit(slot, commandApdu);
    }

    @Override
    public boolean requestCard(int slot, String displayMessage, Duration wait) throws IOException {
      return answer("REQUEST " + slot + " " + displayMessage + " " + wait) || cardPresent(slot);
    }

    @Override
    public boolean ejectCard(int slot, String displayMessage, Duration wait) throws IOException {
      return answer("EJECT " + slot + " " + displayMessage + " " + wait) || !cardPresent(slot);
    }

    private boolean answer(String call) throws IOException {
      calls.add(call);
      IOException failure = user.apply(call);
      if (failure != null) {
        throw failure;
      }
      return false;
    }
  }

  private final RecordedCards recorded = new RecordedCards("KT-01");
  private final UserTerminal kt01 = new UserTerminal(recorded);
  private final RecordedTerminal kt02 =
      new RecordedTerminal("KT-02", 1, RecordedTerminal.EGK_VALID);
  private final TerminalRegistry registry = new TerminalRegistry(List.of(kt01, kt02));
  private final CardList cards = new CardList(registry, Clock.systemUTC());
  private final CardLocks locks = new CardLocks();
  private final SystemLog log = new SystemLog(Clock.systemUTC(), 100);
  private final Infomodel infomodel =
      new Infomodel(
          List.of("M1"),
          List.of("CS1"),
          List.of(
              new Infomodel.Workplace("WP1", List.of("M1"), List.of("CS1"), List.of("KT-01")),
              new Infomodel.Workplace("WP2", List.of("M1"), List.of("CS1"), List.of("KT-02"))));
  private final CardTerminalService service =
      new CardTerminalService(infomodel, registry, cards, locks, log, Duration.ofSeconds(2));

  @BeforeEach
  void start() {
    cards.start();
    recorded.insert(1, RecordedTerminal.EGK_VALID);
  }

  private CardTerminalService.Requested request(
      int slot, String cardType, String message, Long seconds) {
    return service.requestCard(
        new CardTerminalService.Request(
            CTX, new CardTerminalService.Slot("KT-01", slot), cardType, message, seconds));
  }

  private static void assertCode(int code, Executable call) {
    assertEquals(code, assertThrows(ConnectorException.class, call).error().code());
  }

  @Test
  @DisplayName(
      "TUC_KON_056 Schritt 4a: steckt schon eine Karte, liefert RequestCard sie mit AlreadyInserted; das KT "
          + "bekommt REQUEST ICC trotzdem (Anzeige entfällt dort)")
  void schonGesteckt() {
    CardTerminalService.Requested requested = request(1, "EGK", null, null);
    assertTrue(requested.alreadyInserted());
    assertEquals(cards.card("KT-01", 1).orElseThrow(), requested.card());
    assertEquals(
        List.of("REQUEST 1 Bitte \u000BeGK \u000Bin \u000BSLOT 1 \u000Bstecken PT20S"), kt01.calls);
  }

  @Test
  @DisplayName(
      "TUC_KON_056 Schritt 2–4b: der Anwender steckt nach der Aufforderung, RequestCard liefert die neue "
          + "Karte aus CM_CARD_LIST, AlreadyInserted false; DisplayMsg und TimeOut in Sekunden gehen an das KT")
  void gestecktNachAufforderung() {
    kt01.user =
        call -> {
          recorded.insert(2, RecordedTerminal.SMCB_VALID);
          return null;
        };
    CardTerminalService.Requested requested = request(2, null, "Tiger: Bitte Karten stecken", 50L);
    assertFalse(requested.alreadyInserted());
    assertEquals(CardType.SMC_B, requested.card().data().type());
    assertEquals(2, requested.card().slotNo());
    assertEquals(List.of("REQUEST 2 Tiger: Bitte Karten stecken PT50S"), kt01.calls);
  }

  @Test
  @DisplayName(
      "TIP1-A_5408 TAB_KON_727: ohne DisplayMsg die Standardanzeige je Kartentyp, sonst „Karte“")
  void standardanzeige() {
    assertEquals(
        "Bitte \u000BHBA \u000Bin \u000BSLOT 3 \u000Bstecken",
        CardTerminalService.display(true, "HBAx", 3));
    assertEquals(
        "Bitte \u000BSMC-B \u000Baus \u000BSLOT 2 \u000Bentnehmen",
        CardTerminalService.display(false, "SMC-B", 2));
    assertEquals(
        "Bitte \u000BKarte \u000Bin \u000BSLOT 1 \u000Bstecken",
        CardTerminalService.display(true, null, 1));
  }

  @Test
  @DisplayName(
      "TUC_KON_056 Fehlerfälle: niemand steckt → 4202 und CT/ERROR im Systemprotokoll; falscher Kartentyp "
          + "4051; Display belegt 4039; Fehler des KT 4044")
  void anfordernFehler() {
    assertCode(4202, () -> request(2, null, null, 1L));
    SystemLog.Entry error =
        log.entries(null, null).stream()
            .filter(e -> e.topic().equals("CT/ERROR"))
            .findFirst()
            .orElseThrow();
    assertEquals("KT-01", error.parameters().get("CtID"));
    assertEquals("4202", error.parameters().get("Error"));

    assertCode(4051, () -> request(1, "SM-B", null, null));
    kt01.user = call -> new DisplayBusyException("belegt");
    assertCode(4039, () -> request(2, null, null, null));
    kt01.user = call -> new IOException("Verbindung weg");
    assertCode(4044, () -> request(2, null, null, null));
  }

  @Test
  @DisplayName(
      "TAB_KON_717 checkArguments und TUC_KON_000: ohne Slot 4000, CardType SMC-B 4058, unbekannter "
          + "CardType 4000, DisplayMsg über 48 Zeichen 4000; unbekanntes KT 4007, Slot außerhalb 4097, KT eines "
          + "anderen Arbeitsplatzes 4015, Kontext unvollständig 4021")
  void anfordernArgumente() {
    assertCode(
        4000,
        () -> service.requestCard(new CardTerminalService.Request(CTX, null, null, null, null)));
    assertCode(4058, () -> request(1, "SMC-B", null, null));
    assertCode(4000, () -> request(1, "XYZ", null, null));
    assertCode(4000, () -> request(1, null, "x".repeat(49), null));
    assertCode(
        4007,
        () ->
            service.requestCard(
                new CardTerminalService.Request(
                    CTX, new CardTerminalService.Slot("KT-99", 1), null, null, null)));
    assertCode(4097, () -> request(4, null, null, null));
    assertCode(
        4015,
        () ->
            service.requestCard(
                new CardTerminalService.Request(
                    CTX, new CardTerminalService.Slot("KT-02", 1), null, null, null)));
    assertCode(
        4021,
        () ->
            service.requestCard(
                new CardTerminalService.Request(
                    new Context("M1", null, "WP1", null),
                    new CardTerminalService.Slot("KT-01", 1),
                    null,
                    null,
                    null)));
    assertTrue(kt01.calls.isEmpty(), "kein Kommando an das KT: " + kt01.calls);
  }

  @Test
  @DisplayName(
      "TUC_KON_057: EjectCard per CardHandle, der Anwender entnimmt die Karte; Standardanzeige nach dem "
          + "Kartentyp, TimeOut in Millisekunden; danach ist die Karte aus CM_CARD_LIST")
  void auswerfen() {
    String handle = cards.card("KT-01", 1).orElseThrow().cardHandle();
    kt01.user =
        call -> {
          recorded.eject(1);
          return null;
        };
    service.ejectCard(new CardTerminalService.Eject(CTX, handle, null, null, 50_000L));
    assertEquals(
        List.of("EJECT 1 Bitte \u000BeGK \u000Baus \u000BSLOT 1 \u000Bentnehmen PT50S"),
        kt01.calls);
    assertTrue(cards.card(handle).isEmpty());
  }

  @Test
  @DisplayName(
      "TUC_KON_057 Varianten: auch ein nach Buchführung leerer Slot bekommt EJECT ICC, ohne Fehler")
  void auswerfenLeer() {
    service.ejectCard(
        new CardTerminalService.Eject(
            CTX, null, new CardTerminalService.Slot("KT-01", 3), "Tiger-Test ist fertig", null));
    assertEquals(List.of("EJECT 3 Tiger-Test ist fertig PT20S"), kt01.calls);
  }

  @Test
  @DisplayName(
      "TUC_KON_057/TAB_KON_721 Fehlerfälle: Karte bleibt stecken 4203, unbekanntes CardHandle 4101, Karte "
          + "reserviert 4093, weder CardHandle noch Slot 4000")
  void auswerfenFehler() {
    String handle = cards.card("KT-01", 1).orElseThrow().cardHandle();
    assertCode(
        4203,
        () -> service.ejectCard(new CardTerminalService.Eject(CTX, handle, null, null, 100L)));
    assertCode(
        4101,
        () -> service.ejectCard(new CardTerminalService.Eject(CTX, "unbekannt", null, null, null)));
    CardLocks.Lock lock = locks.lock(handle);
    assertCode(
        4093,
        () -> service.ejectCard(new CardTerminalService.Eject(CTX, handle, null, null, null)));
    locks.unlock(lock);
    assertCode(
        4000, () -> service.ejectCard(new CardTerminalService.Eject(CTX, null, null, null, null)));
    assertEquals(1, kt01.calls.size(), "nur der erste Aufruf erreicht das KT: " + kt01.calls);
  }
}

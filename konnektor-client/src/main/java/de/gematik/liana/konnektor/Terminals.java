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

import de.gematik.liana.konnektor.ws.conn.cardterminalservice.v1_1.EjectCard;
import de.gematik.liana.konnektor.ws.conn.cardterminalservice.v1_1.EjectCardResponse;
import de.gematik.liana.konnektor.ws.conn.cardterminalservice.v1_1.RequestCard;
import de.gematik.liana.konnektor.ws.conn.cardterminalservice.v1_1.RequestCardResponse;
import de.gematik.liana.konnektor.ws.conn.cardterminalservice.v1_1.Slot;
import de.gematik.liana.konnektor.ws.conn.eventservice.v7_2.GetCardTerminals;
import de.gematik.liana.konnektor.ws.conn.eventservice.v7_2.GetCardTerminalsResponse;
import java.math.BigInteger;
import java.time.Duration;
import java.util.List;

/**
 * Card terminals (LIANA-135): GetCardTerminals (EventService 7.2), RequestCard and EjectCard
 * (CardTerminalService 1.1, TUC_KON_056/057). {@code TimeOut} is in seconds for RequestCard and in
 * milliseconds for EjectCard (gemSpec_Kon TAB_KON_716 and TAB_KON_719).
 */
public final class Terminals {

  private final Konnektor kon;

  Terminals(Konnektor kon) {
    this.kon = kon;
  }

  /** GetCardTerminals in the Aufrufkontext. */
  public List<CardTerminal> list() {
    GetCardTerminals request = new GetCardTerminals();
    request.setContext(Jaxb.context(kon.context()));
    GetCardTerminalsResponse response =
        kon.invoke(Operation.GET_CARD_TERMINALS, request, GetCardTerminalsResponse.class);
    if (response.getCardTerminals() == null) {
      return List.of();
    }
    return response.getCardTerminals().getCardTerminal().stream().map(CardTerminal::of).toList();
  }

  /**
   * RequestCard: waits up to {@code timeout} for a card in the slot; if one is already inserted, it
   * is returned immediately.
   *
   * @param displayMsg message shown at the card terminal, or {@code null}
   */
  public Card requestCard(String ctId, int slot, Duration timeout, String displayMsg) {
    RequestCard request = new RequestCard();
    request.setContext(Jaxb.context(kon.context()));
    request.setSlot(slot(ctId, slot));
    request.setDisplayMsg(displayMsg);
    request.setTimeOut(BigInteger.valueOf(timeout.toSeconds()));
    RequestCardResponse response =
        kon.invoke(Operation.REQUEST_CARD, request, RequestCardResponse.class);
    if (response.getCard() == null) {
      throw new KonnektorException(
          "RequestCard " + ctId + "/" + slot + ": keine Karte in der Antwort");
    }
    return Card.of(response.getCard());
  }

  /** EjectCard via the CardHandle: waits up to {@code timeout} until the card is pulled. */
  public void ejectCard(String cardHandle, Duration timeout, String displayMsg) {
    EjectCard request = new EjectCard();
    request.setContext(Jaxb.context(kon.context()));
    request.setCardHandle(cardHandle);
    request.setDisplayMsg(displayMsg);
    request.setTimeOut(BigInteger.valueOf(timeout.toMillis()));
    kon.invoke(Operation.EJECT_CARD, request, EjectCardResponse.class);
  }

  /** EjectCard via the slot. */
  public void ejectCard(String ctId, int slot, Duration timeout, String displayMsg) {
    EjectCard request = new EjectCard();
    request.setContext(Jaxb.context(kon.context()));
    request.setSlot(slot(ctId, slot));
    request.setDisplayMsg(displayMsg);
    request.setTimeOut(BigInteger.valueOf(timeout.toMillis()));
    kon.invoke(Operation.EJECT_CARD, request, EjectCardResponse.class);
  }

  private static Slot slot(String ctId, int slot) {
    Slot value = new Slot();
    value.setCtId(ctId);
    value.setSlotId(BigInteger.valueOf(slot));
    return value;
  }
}

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

import de.gematik.liana.kern.access.Context;
import de.gematik.liana.kern.access.Infomodel;
import de.gematik.liana.kern.card.CardAccess;
import de.gematik.liana.kern.card.CardList;
import de.gematik.liana.kern.card.CardObject;
import de.gematik.liana.kern.error.ConnectorError;
import de.gematik.liana.kern.management.OperatingState;
import de.gematik.liana.kern.terminal.CardTerminal;
import de.gematik.liana.kern.terminal.TerminalRegistry;
import java.util.List;

/**
 * TIP1-A_4607 operation GetResourceInformation (TAB_KON_568, flow TAB_KON_569): checkArguments,
 * TUC_KON_000 depending on the resource, TUC_KON_254 „Liefere Ressourcendetails“ (TIP1-A_4602).
 * Returns a card, a CT or the connector with Betriebszustand ({@link OperatingState}).
 */
public final class GetResourceInformation {

  /**
   * Call parameters; {@code ctId}, {@code slotId}, {@code iccsn} and {@code cardHandle} are
   * optional.
   */
  public record Request(
      Context context, String ctId, Integer slotId, String iccsn, String cardHandle) {}

  /** Information about the connector (CONN:Connector). */
  public record Connector(
      OperatingState.Connection vpnTi,
      OperatingState.Connection vpnSis,
      List<OperatingState.ErrorState> errorStates) {}

  /** Exactly one of the fields is set. */
  public record Result(CardObject card, GetCardTerminals.Entry terminal, Connector connector) {}

  private final Infomodel infomodel;
  private final TerminalRegistry terminals;
  private final CardList cards;
  private final CardAccess cardAccess;
  private final GetCardTerminals getCardTerminals;
  private final OperatingState operatingState;

  public GetResourceInformation(
      Infomodel infomodel,
      TerminalRegistry terminals,
      CardList cards,
      CardAccess cardAccess,
      GetCardTerminals getCardTerminals,
      OperatingState operatingState) {
    this.infomodel = infomodel;
    this.terminals = terminals;
    this.cards = cards;
    this.cardAccess = cardAccess;
    this.getCardTerminals = getCardTerminals;
    this.operatingState = operatingState;
  }

  public Result execute(Request request) {
    // TAB_KON_569 step 1: SlotId only with CtId
    if (request.slotId() != null && (request.ctId() == null || request.slotId() < 1)) {
      throw ConnectorError.SYNTAX.exception(
          "SlotId " + request.slotId() + " ohne CtId oder kleiner 1");
    }
    if (request.cardHandle() != null || request.iccsn() != null || request.slotId() != null) {
      return new Result(card(request), null, null);
    }
    if (request.ctId() != null) {
      return new Result(null, terminal(request.context(), request.ctId()), null);
    }
    // TUC_KON_000 with allWorkplaces = true, TUC_KON_254 step 3
    infomodel.checkAccess(request.context(), true);
    synchronized (operatingState) {
      return new Result(
          null,
          null,
          new Connector(
              operatingState.vpnTi(), operatingState.vpnSis(), operatingState.errorStates()));
    }
  }

  /**
   * TUC_KON_254 step 1 (errors 4007, 4097, 4098, 4099, 4101), then TUC_KON_000 with the CardHandle.
   */
  private CardObject card(Request request) {
    CardObject card;
    if (request.cardHandle() != null) {
      card =
          cards
              .card(request.cardHandle())
              .orElseThrow(
                  () -> ConnectorError.INVALID_CARD_HANDLE.exception(request.cardHandle()));
    } else if (request.iccsn() != null) {
      card =
          cards.cards().stream()
              .filter(c -> request.iccsn().equals(c.data().iccsn()))
              .findFirst()
              .orElseThrow(() -> ConnectorError.NO_CARD_FOR_ICCSN.exception(request.iccsn()));
    } else {
      CardTerminal terminal =
          terminals
              .terminal(request.ctId())
              .orElseThrow(() -> ConnectorError.INVALID_CT_ID.exception(request.ctId()));
      if (request.slotId() > terminal.slots()) {
        throw ConnectorError.INVALID_SLOT_ID.exception(request.ctId() + "/" + request.slotId());
      }
      card =
          cards
              .card(request.ctId(), request.slotId())
              .orElseThrow(
                  () ->
                      ConnectorError.NO_CARD_IN_SLOT.exception(
                          request.ctId() + "/" + request.slotId()));
    }
    return cardAccess.card(request.context(), card.cardHandle());
  }

  /** TUC_KON_000 with ctId and allWorkplaces = true, TUC_KON_254 step 2 (error 4007). */
  private GetCardTerminals.Entry terminal(Context context, String ctId) {
    if (terminals.terminal(ctId).isEmpty()) {
      throw ConnectorError.INVALID_CT_ID.exception(ctId);
    }
    return getCardTerminals.execute(context, true).stream()
        .filter(e -> e.info().ctId().equals(ctId))
        .findFirst()
        .orElseThrow(
            () -> ConnectorError.CT_NOT_REACHABLE.exception(ctId + " / " + context.workplaceId()));
  }
}

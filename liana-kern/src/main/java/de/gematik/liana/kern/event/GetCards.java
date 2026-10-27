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
import de.gematik.liana.kern.card.CardList;
import de.gematik.liana.kern.card.CardObject;
import de.gematik.liana.kern.card.CardType;
import de.gematik.liana.kern.error.ConnectorError;
import de.gematik.liana.kern.terminal.TerminalRegistry;
import java.util.List;
import java.util.Set;

/**
 * TIP1-A_4605-03 operation GetCards (TAB_KON_566): checkArguments, TUC_KON_000, TUC_KON_253. Only
 * reads the card list, does not query any card terminals.
 */
public final class GetCards {

  /**
   * Call parameters; {@code ctId}, {@code slotId} and {@code cardType} are optional ({@code null}).
   */
  public record Request(
      Context context, String ctId, Integer slotId, String cardType, boolean mandantWide) {}

  /**
   * Card types GetCards supports as filter (TAB_KON_565), plus the individual types from
   * TAB_KON_500.
   */
  private static final Set<String> SUMMARY_TYPES = Set.of("HBAx", "SM-B");

  private final Infomodel infomodel;
  private final TerminalRegistry terminals;
  private final CardList cards;

  public GetCards(Infomodel infomodel, TerminalRegistry terminals, CardList cards) {
    this.infomodel = infomodel;
    this.terminals = terminals;
    this.cards = cards;
  }

  public List<CardObject> execute(Request request) {
    checkArguments(request);
    Set<String> reachable = infomodel.checkAccess(request.context(), request.mandantWide());
    // TUC_KON_253 (TAB_KON_559)
    if (request.ctId() != null && terminals.terminal(request.ctId()).isEmpty()) {
      throw ConnectorError.INVALID_CT_ID.exception(request.ctId());
    }
    return cards.cards().stream()
        .filter(card -> reachable.contains(card.ctId()))
        .filter(card -> request.ctId() == null || card.ctId().equals(request.ctId()))
        .filter(card -> request.slotId() == null || card.slotNo() == request.slotId())
        .filter(
            card -> request.cardType() == null || card.data().type().matches(request.cardType()))
        .toList();
  }

  private static void checkArguments(Request request) {
    if (request.slotId() != null && (request.ctId() == null || request.slotId() < 1)) {
      throw ConnectorError.SYNTAX.exception(
          "SlotId " + request.slotId() + " ohne CtId oder kleiner 1");
    }
    if (request.cardType() != null
        && CardType.of(request.cardType()).isEmpty()
        && !SUMMARY_TYPES.contains(request.cardType())) {
      throw ConnectorError.SYNTAX.exception("unbekannter CardType " + request.cardType());
    }
  }
}

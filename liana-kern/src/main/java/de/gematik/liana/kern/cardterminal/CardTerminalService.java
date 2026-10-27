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

import de.gematik.liana.kern.access.Context;
import de.gematik.liana.kern.access.Infomodel;
import de.gematik.liana.kern.card.CardList;
import de.gematik.liana.kern.card.CardLocks;
import de.gematik.liana.kern.card.CardObject;
import de.gematik.liana.kern.card.CardType;
import de.gematik.liana.kern.error.ConnectorError;
import de.gematik.liana.kern.error.ConnectorException;
import de.gematik.liana.kern.event.SystemLog;
import de.gematik.liana.kern.terminal.CardTerminal;
import de.gematik.liana.kern.terminal.DisplayBusyException;
import de.gematik.liana.kern.terminal.TerminalRegistry;
import java.io.IOException;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * TIP1-A_5411-02 basic service card terminal service (Basisdienst Kartenterminaldienst,
 * TAB_KON_722): TIP1-A_5412 RequestCard (TAB_KON_716, flow TAB_KON_717) with TUC_KON_056 „Karte
 * anfordern“ (TIP1-A_5409) and TIP1-A_5413 EjectCard (TAB_KON_719, flow TAB_KON_720) with
 * TUC_KON_057 „Karte auswerfen“ (TIP1-A_5410). Displays without caller input per TIP1-A_5408.
 * Errors in the TUCs go to the Systemprotokoll as CT/ERROR (TUC_KON_256).
 */
public final class CardTerminalService {

  /** TAB_KON_716/719: without TimeOut the connector SHOULD wait 20 s. */
  public static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(20);

  /** TAB_KON_716: card types RequestCard accepts as filter; other valid types 4058. */
  private static final Set<String> REQUEST_TYPES = Set.of("EGK", "KVK", "HBAx", "SM-B");

  /**
   * CT:Slot; {@code ctId} and {@code slotId} may be missing ({@code null}, checkArguments 4000).
   */
  public record Slot(String ctId, Integer slotId) {}

  /**
   * Call parameters of RequestCard; {@code cardType}, {@code displayMessage} and {@code
   * timeOutSeconds} are optional. TimeOut in seconds (TAB_KON_716).
   */
  public record Request(
      Context context, Slot slot, String cardType, String displayMessage, Long timeOutSeconds) {}

  /**
   * Return value of RequestCard: the card and whether it was already inserted before the call
   * (CT:AlreadyInserted).
   */
  public record Requested(CardObject card, boolean alreadyInserted) {}

  /**
   * Call parameters of EjectCard: CardHandle or slot (exactly one); {@code displayMessage} and
   * {@code timeOutMillis} are optional. TimeOut in milliseconds (TAB_KON_719).
   */
  public record Eject(
      Context context, String cardHandle, Slot slot, String displayMessage, Long timeOutMillis) {}

  private final Infomodel infomodel;
  private final TerminalRegistry terminals;
  private final CardList cards;
  private final CardLocks locks;
  private final SystemLog log;
  private final Duration cardTimeout;

  /** {@code cardTimeout} (CARD_TIMEOUT_CARD): how long TUC_KON_001 may take after insertion. */
  public CardTerminalService(
      Infomodel infomodel,
      TerminalRegistry terminals,
      CardList cards,
      CardLocks locks,
      SystemLog log,
      Duration cardTimeout) {
    this.infomodel = infomodel;
    this.terminals = terminals;
    this.cards = cards;
    this.locks = locks;
    this.log = log;
    this.cardTimeout = cardTimeout;
  }

  /**
   * TAB_KON_717: checkArguments, TUC_KON_000 (needCardSession = false, allWorkplaces = false),
   * TUC_KON_056.
   */
  public Requested requestCard(Request request) {
    Slot slot = request.slot();
    if (slot == null || blank(slot.ctId()) || slot.slotId() == null || request.context() == null) {
      throw ConnectorError.SYNTAX.exception("RequestCard ohne Slot (CtId, SlotId) oder Context");
    }
    if (request.cardType() != null) {
      if (CardType.of(request.cardType()).isEmpty()
          && !Set.of("HBAx", "SM-B").contains(request.cardType())) {
        throw ConnectorError.SYNTAX.exception("unbekannter CardType " + request.cardType());
      }
      if (!REQUEST_TYPES.contains(request.cardType())) {
        throw ConnectorError.CALL_NOT_ALLOWED.exception(
            "RequestCard für CardType " + request.cardType());
      }
    }
    checkMessage(request.displayMessage());
    checkAccess(request.context(), slot.ctId());
    Duration wait =
        request.timeOutSeconds() == null
            ? DEFAULT_TIMEOUT
            : Duration.ofSeconds(request.timeOutSeconds());
    return reportingCtError(
        slot.ctId(),
        () ->
            tucKon056(
                slot.ctId(), slot.slotId(), request.cardType(), request.displayMessage(), wait));
  }

  /** TAB_KON_720: checkArguments, TUC_KON_000 with the CT of the slot or the card, TUC_KON_057. */
  public void ejectCard(Eject eject) {
    if ((eject.cardHandle() == null) == (eject.slot() == null) || eject.context() == null) {
      throw ConnectorError.SYNTAX.exception(
          "EjectCard braucht genau eins von CardHandle und Slot und den Context");
    }
    if (eject.slot() != null && (blank(eject.slot().ctId()) || eject.slot().slotId() == null)) {
      throw ConnectorError.SYNTAX.exception("EjectCard: Slot ohne CtId oder SlotId");
    }
    checkMessage(eject.displayMessage());
    String ctId;
    int slotId;
    if (eject.cardHandle() != null) {
      infomodel.checkAccess(eject.context(), false);
      CardObject card =
          cards
              .card(eject.cardHandle())
              .orElseThrow(
                  () ->
                      ConnectorError.INVALID_CARD_HANDLE.exception(
                          "CardHandle " + eject.cardHandle()));
      ctId = card.ctId();
      slotId = card.slotNo();
    } else {
      ctId = eject.slot().ctId();
      slotId = eject.slot().slotId();
    }
    checkAccess(eject.context(), ctId);
    Duration wait =
        eject.timeOutMillis() == null ? DEFAULT_TIMEOUT : Duration.ofMillis(eject.timeOutMillis());
    reportingCtError(
        ctId,
        () -> {
          tucKon057(ctId, slotId, eject.displayMessage(), wait);
          return null;
        });
  }

  /** TUC_KON_056 „Karte anfordern“ (TAB_KON_723). */
  private Requested tucKon056(
      String ctId, int slotId, String cardType, String displayMessage, Duration wait) {
    CardTerminal terminal = terminal(ctId, slotId);
    boolean alreadyInserted = cards.card(ctId, slotId).isPresent();
    // step 1: display per TIP1-A_5408; step 2: SICCT REQUEST ICC with display and wait time
    String message = displayMessage != null ? displayMessage : display(true, cardType, slotId);
    boolean present = call(ctId, slotId, () -> terminal.requestCard(slotId, message, wait));
    if (!present) {
      throw ConnectorError.REQUEST_CARD_TIMEOUT.exception(ctId + "/" + slotId + " nach " + wait);
    }
    // step 3/4: the event „Karte gesteckt“ opens the card (TIP1-A_4563, TUC_KON_001)
    CardObject card =
        await(ctId, slotId, true)
            .orElseThrow(
                () ->
                    ConnectorError.CT_ACCESS.exception(
                        ctId
                            + "/"
                            + slotId
                            + ": Karte steckt, ist aber nach CARD_TIMEOUT_CARD nicht in CM_CARD_LIST"));
    // step 5
    if (cardType != null && !card.data().type().matches(cardType)) {
      throw ConnectorError.WRONG_CARD_TYPE.exception(
          ctId + "/" + slotId + ": " + card.data().type().value() + " statt " + cardType);
    }
    return new Requested(card, alreadyInserted);
  }

  /**
   * TUC_KON_057 „Karte auswerfen“ (TAB_KON_725); EJECT ICC goes to the CT even if the bookkeeping
   * shows no card.
   */
  private void tucKon057(String ctId, int slotId, String displayMessage, Duration wait) {
    CardTerminal terminal = terminal(ctId, slotId);
    Optional<CardObject> card = cards.card(ctId, slotId);
    // step 1
    card.ifPresent(c -> locks.checkFree(c.cardHandle()));
    // step 2
    String message =
        displayMessage != null
            ? displayMessage
            : display(false, card.map(c -> c.data().type().value()).orElse(null), slotId);
    // step 3
    boolean removed = call(ctId, slotId, () -> terminal.ejectCard(slotId, message, wait));
    if (!removed) {
      throw ConnectorError.CARD_NOT_REMOVED.exception(ctId + "/" + slotId + " nach " + wait);
    }
    // postcondition: „Karte entfernt“ (TIP1-A_4562) is processed before EjectCard responds
    await(ctId, slotId, false);
  }

  /**
   * TIP1-A_5408 (TAB_KON_727): „Bitte•&lt;Karte&gt;•in|aus•SLOT X•stecken|entnehmen“; „•“ in the
   * tables of gemSpec_Kon is a space, 0x0B the line break of the SICCT display.
   */
  public static String display(boolean request, String cardType, int slot) {
    String card =
        switch (cardType == null ? "" : cardType) {
          case "EGK" -> "eGK";
          case "HBA", "HBAx", "HBA-qSig" -> "HBA";
          case "SMC-B", "SM-B" -> "SMC-B";
          default -> "Karte";
        };
    return String.join(
        " \u000B",
        "Bitte",
        card,
        request ? "in" : "aus",
        "SLOT " + slot,
        request ? "stecken" : "entnehmen");
  }

  /** CT:DisplayMsg at most 48 characters (CardTerminalService.xsd). */
  private static void checkMessage(String message) {
    if (message != null && message.length() > 48) {
      throw ConnectorError.SYNTAX.exception("DisplayMsg länger als 48 Zeichen");
    }
  }

  /** TUC_KON_000 with ctId: context valid and CT accessible from the workplace (4015). */
  private void checkAccess(Context context, String ctId) {
    Set<String> reachable = infomodel.checkAccess(context, false);
    if (terminals.terminal(ctId).isPresent() && !reachable.contains(ctId)) {
      throw ConnectorError.CT_NOT_REACHABLE.exception(ctId + " / " + context.workplaceId());
    }
  }

  /** CTM_CT_LIST(ctId): 4007 unknown, 4097 slot outside CT.SLOTCOUNT, 4222 not connected. */
  private CardTerminal terminal(String ctId, int slotId) {
    CardTerminal terminal =
        terminals.terminal(ctId).orElseThrow(() -> ConnectorError.INVALID_CT_ID.exception(ctId));
    if (!terminal.info().connected()) {
      throw ConnectorError.CT_NOT_CONNECTED.exception(ctId);
    }
    if (slotId < 1 || slotId > terminal.slots()) {
      throw ConnectorError.INVALID_SLOT_ID.exception(
          ctId + "/" + slotId + " außerhalb 1.." + terminal.slots());
    }
    return terminal;
  }

  private Optional<CardObject> await(String ctId, int slotId, boolean opened) {
    try {
      return cards.await(ctId, slotId, opened, cardTimeout);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw ConnectorError.CT_ACCESS.exception(ctId + "/" + slotId + ": unterbrochen").causedBy(e);
    }
  }

  private interface TerminalCall {
    boolean run() throws IOException;
  }

  /** CT errors: display busy 4039, otherwise 4044 (TUC_KON_056/057 error cases step 2 or 3). */
  private static boolean call(String ctId, int slotId, TerminalCall call) {
    try {
      return call.run();
    } catch (DisplayBusyException e) {
      throw ConnectorError.CT_BUSY.exception(e.getMessage()).causedBy(e);
    } catch (IOException | RuntimeException e) {
      throw ConnectorError.CT_ACCESS
          .exception(ctId + "/" + slotId + ": " + e.getMessage())
          .causedBy(e);
    }
  }

  private interface Tuc<T> {
    T run();
  }

  /**
   * TUC_KON_056/057 error cases: TUC_KON_256 with CT/ERROR (CtID, Name, Error, Bedeutung), then
   * abort.
   */
  private <T> T reportingCtError(String ctId, Tuc<T> tuc) {
    try {
      return tuc.run();
    } catch (ConnectorException e) {
      Map<String, String> parameters = new LinkedHashMap<>();
      parameters.put("CtID", ctId);
      parameters.put("Name", terminals.terminal(ctId).map(t -> t.info().name()).orElse(""));
      parameters.put("Error", String.valueOf(e.error().code()));
      parameters.put("Bedeutung", e.error().text());
      log.write(SystemLog.Type.OP, SystemLog.Severity.ERR, "CT/ERROR", parameters);
      throw e;
    }
  }

  private static boolean blank(String value) {
    return value == null || value.isBlank();
  }
}

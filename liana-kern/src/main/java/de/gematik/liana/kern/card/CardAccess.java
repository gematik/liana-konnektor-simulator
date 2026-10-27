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

import de.gematik.liana.kern.access.Context;
import de.gematik.liana.kern.access.Infomodel;
import de.gematik.liana.kern.error.ConnectorError;
import java.util.Set;

/**
 * TUC_KON_000 „Prüfe Zugriffsberechtigung“ with {@code cardHandle}: Aufrufkontext valid (4021 and
 * following), card inserted (4008), card terminal reachable from the workplace (4015), an SMC-B is
 * SM-B_Verwaltet of the mandant (rule R7: 4009, 4013), an HBAx with card session needs a UserId
 * (rule R9: 4003) and must not have a card session of the same Clientsystem for another UserId with
 * elevated security state (R9: 4018). Shared by all operations that address a card via its
 * CardHandle; in addition TUC_KON_026 step 2, the check for a foreign card lock.
 */
public final class CardAccess {

  /**
   * TUC_KON_000 rule R9: whether the HBAx for {@code cardHandle} has a card session with the client
   * system of the Aufrufkontext but a different UserId whose security state is elevated (PIN
   * entered).
   */
  @FunctionalInterface
  public interface ElevatedSessions {
    boolean otherUser(Context context, String cardHandle);
  }

  /** HBAx: HBA-qSig, HBA, ZOD_2.0 (gemSpec_Kon chapter 2). */
  private static final Set<CardType> HBAX =
      Set.of(CardType.HBA_Q_SIG, CardType.HBA, CardType.ZOD_2_0);

  private final Infomodel infomodel;
  private final CardList cards;
  private final CardLocks locks;
  private volatile ElevatedSessions elevated = (context, cardHandle) -> false;

  public CardAccess(Infomodel infomodel, CardList cards, CardLocks locks) {
    this.infomodel = infomodel;
    this.cards = cards;
    this.locks = locks;
  }

  /**
   * The card sessions with elevated security state for rule R9 (4018); without them there are none.
   */
  public void elevatedSessions(ElevatedSessions sessions) {
    elevated = sessions;
  }

  /**
   * The card for {@code cardHandle} if the Aufrufkontext may access it (TUC_KON_000 with
   * needCardSession=false).
   */
  public CardObject card(Context context, String cardHandle) {
    return card(context, cardHandle, false);
  }

  /**
   * TUC_KON_000 with {@code needCardSession}: like {@link #card(Context, String)}, for an HBAx with
   * card session additionally the UserId (rule R9, TAB_KON_514-01: {@code userId <> null},
   * otherwise 4003) and no card session of another UserId with elevated security state (R9,
   * otherwise 4018).
   */
  public CardObject card(Context context, String cardHandle, boolean needCardSession) {
    if (cardHandle == null || cardHandle.isBlank()) {
      throw ConnectorError.SYNTAX.exception("CardHandle fehlt");
    }
    Set<String> reachable = infomodel.checkAccess(context, false);
    CardObject card =
        cards
            .card(cardHandle)
            .orElseThrow(
                () -> ConnectorError.CARD_NOT_INSERTED.exception("CardHandle " + cardHandle));
    if (!reachable.contains(card.ctId())) {
      throw ConnectorError.CT_NOT_REACHABLE.exception(card.ctId() + " / " + context.workplaceId());
    }
    CardType type = card.data().type();
    if (type == CardType.SMC_B) {
      infomodel.checkSmbVerwaltet(context.mandantId(), card.data().iccsn());
    }
    if (needCardSession && HBAX.contains(type)) {
      if (context.userId() == null || context.userId().isBlank()) {
        throw ConnectorError.USER_ID_MISSING.exception("CardHandle " + cardHandle);
      }
      if (elevated.otherUser(context, cardHandle)) {
        throw ConnectorError.HBA_OTHER_USER.exception(
            "CardHandle " + cardHandle + ", Clientsystem " + context.clientSystemId());
      }
    }
    return card;
  }

  /**
   * TUC_KON_000 and TUC_KON_026 „Liefere CardSession“ step 2: the card if the Aufrufkontext may
   * access it and no card session has reserved it (otherwise 4093, A_25895).
   */
  public CardObject cardSession(Context context, String cardHandle) {
    CardObject card = card(context, cardHandle);
    locks.checkFree(card.cardHandle());
    return card;
  }

  /** TUC_KON_026 step 2 for a card already checked per TUC_KON_000. */
  public void checkFree(CardObject card) {
    locks.checkFree(card.cardHandle());
  }
}

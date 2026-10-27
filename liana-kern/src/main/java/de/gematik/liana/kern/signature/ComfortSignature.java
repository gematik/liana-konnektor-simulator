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
package de.gematik.liana.kern.signature;

import de.gematik.liana.kern.access.Context;
import de.gematik.liana.kern.card.AuthState;
import de.gematik.liana.kern.card.CardAccess;
import de.gematik.liana.kern.card.CardList;
import de.gematik.liana.kern.card.CardLocks;
import de.gematik.liana.kern.card.CardObject;
import de.gematik.liana.kern.card.CardSignature;
import de.gematik.liana.kern.card.CardToCard;
import de.gematik.liana.kern.card.CardType;
import de.gematik.liana.kern.card.PinVerification;
import de.gematik.liana.kern.card.TrustedChannels;
import de.gematik.liana.kern.error.ConnectorError;
import de.gematik.liana.kern.error.ConnectorException;
import de.gematik.liana.kern.management.ComfortSettings;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Komfortsignatur (Komfortsignatur, gemSpec_Kon 4.1.8.1.5, LIANA-112.06): CARDSESSION.SIGNMODE per
 * HBA card session (CardHandle, mandant, Clientsystem, UserId) with Komfortsignatur counter
 * (A_19100-01) and timer (A_18686-01).
 *
 * <ul>
 *   <li>ActivateComfortSignature (A_19107-01) with TUC_KON_171 (A_19104-05): PIN.QES in DF.QES,
 *       which stays selected afterwards (A_18597), UserId as UUID per RFC 4122 (A_20073-01, 4272),
 *       not among the last 1,000 (A_20074, 4270);
 *   <li>DeactivateComfortSignature (A_19108) and disabling SAK_COMFORT_SIGNATURE with TUC_KON_172
 *       (A_19105): leave DF.QES, PIN.QES out of CARDSESSION.AUTHSTATE, SIGNMODE = PIN;
 *   <li>GetSignatureMode (A_19109-02) with TUC_KON_173 (A_19106-02);
 *   <li>for SignDocument TUC_KON_170 (A_19103-08) and TUC_KON_158 (A_19102-05): {@link #active},
 *       {@link #start}, {@link #next}, {@link #counted}, {@link #abort}.
 * </ul>
 *
 * <p>TUC_KON_171 verifies the PIN.QES in SE #2 in the remote PIN procedure, TUC_KON_158 signs there
 * in the trusted channel gSMC-K↔HBA (A_19258, {@link TrustedChannels}, LIANA-112.13); if anything
 * is missing for that, the HBA stays in SE #1 and signs with PWD(81) without secure messaging.
 *
 * <p>Deviations: kartos knows no logical channels, all sessions of an HBA share the basic channel;
 * if another operation selects a different DF, the PIN.QES is gone and the next Komfortsignatur
 * ends with 4271. After the timer expires, LIANA resets the security state only at the session's
 * next SignDocument. There is no maximum number of parallel sessions (4278). A session in Comfort
 * mode keeps the HBA's security state elevated: other UserIds of the same Clientsystem get 4018
 * (TUC_KON_000 R9); for ActivateComfortSignature this means CardNeedsReset (TAB_KON_877 step 2).
 * There, TUC_KON_024 replaces TUC_KON_172 for the HBA (reset PIN.QES, the other sessions in PIN
 * mode), without CARD/RESET event.
 */
public final class ComfortSignature {

  /** A_20074: uniqueness of the UserId across this many operations. */
  static final int USER_ID_HISTORY = 1_000;

  /** gemSpec_HBA_ObjSys: signatures per PIN.QES in a logical channel (TUC_KON_173 variant 4b). */
  static final int CARD_MAX = 250;

  private static final String PIN_QES = "PIN.QES";
  private static final Pattern UUID =
      Pattern.compile(
          "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");

  /** TUC_KON_173 sessionInfo. */
  public record SessionInfo(int countRemaining, Duration timeRemaining) {}

  /**
   * TUC_KON_173: comfortSignatureStatus, comfortSignatureMax, comfortSignatureTimer and sessionInfo
   * for Comfort.
   */
  public record Mode(boolean enabled, int max, Duration timer, Optional<SessionInfo> session) {}

  /** A card session of the HBA in Comfort mode, for SignDocument. */
  public record Active(Key key) {}

  /** The card session (TUC_KON_026) of an HBA. */
  record Key(String cardHandle, String mandantId, String clientSystemId, String userId) {
    static Key of(Context context, String cardHandle) {
      return new Key(cardHandle, context.mandantId(), context.clientSystemId(), context.userId());
    }

    Context context() {
      return new Context(mandantId, clientSystemId, null, userId);
    }
  }

  /**
   * A Komfortsignatur session; {@code comfort == false} after TUC_KON_172 (SIGNMODE = PIN), {@code
   * elevated == false} as soon as LIANA has reset the PIN.QES.
   */
  private static final class Session {
    final Instant started;
    int count;
    boolean comfort = true;
    boolean elevated = true;

    Session(Instant started) {
      this.started = started;
    }
  }

  private final CardAccess access;
  private final CardList cards;
  private final CardLocks locks;
  private final AuthState authState;
  private final PinVerification pins;
  private final CardSignature cardSignature;
  private final ComfortSettings settings;
  private final TrustedChannels channels;
  private final Clock clock;

  private final Map<Key, Session> sessions = new HashMap<>();

  /** Signatures since the last PIN.QES per HBA (TUC_KON_173 variant 4b). */
  private final Map<String, Integer> cardCounts = new HashMap<>();

  /** HBA in SE #2 after TUC_KON_171, with its CVC for TUC_KON_158 step 1. */
  private final Map<String, CardToCard.Target> secureEnvironments = new HashMap<>();

  private final ArrayDeque<String> userIds = new ArrayDeque<>();
  private final Set<String> usedUserIds = new HashSet<>();

  public ComfortSignature(
      CardAccess access,
      CardList cards,
      CardLocks locks,
      AuthState authState,
      PinVerification pins,
      CardSignature cardSignature,
      ComfortSettings settings,
      TrustedChannels channels,
      Clock clock) {
    this.access = access;
    this.cards = cards;
    this.locks = locks;
    this.authState = authState;
    this.pins = pins;
    this.cardSignature = cardSignature;
    this.settings = settings;
    this.channels = channels;
    this.clock = clock;
    settings.onDisabled(this::deactivateAll);
    access.elevatedSessions(this::otherUser);
  }

  /**
   * TUC_KON_000 R9 (4018): a session of the same Clientsystem for another UserId holds the PIN.QES.
   */
  private synchronized boolean otherUser(Context context, String cardHandle) {
    return sessions.entrySet().stream()
        .anyMatch(
            entry ->
                entry.getValue().elevated
                    && entry.getKey().cardHandle().equals(cardHandle)
                    && entry.getKey().clientSystemId().equals(context.clientSystemId())
                    && !entry.getKey().userId().equals(context.userId()));
  }

  /**
   * ActivateComfortSignature per TAB_KON_877: TUC_KON_000 with UserId (4018 sets CardNeedsReset),
   * TUC_KON_026, the UserId (4272, 4270), then TUC_KON_171. Returns SIGNMODE.
   */
  public String activate(Context context, String cardHandle) {
    CardObject card;
    boolean cardNeedsReset = false;
    try {
      card = access.card(context, cardHandle, true);
    } catch (ConnectorException e) {
      if (e.error() != ConnectorError.HBA_OTHER_USER) {
        throw e;
      }
      cardNeedsReset = true;
      card = access.card(context, cardHandle);
    }
    access.checkFree(card);
    if (card.data().type() != CardType.HBA) {
      throw ConnectorError.COMFORT_HBA_ONLY.exception(card.data().type().value());
    }
    String userId = context.userId();
    if (!UUID.matcher(userId).matches()) {
      throw ConnectorError.USER_ID_INVALID.exception(
          "UserId keine UUID nach RFC 4122 (A_20073-01)");
    }
    synchronized (this) {
      if (usedUserIds.contains(userId)) {
        throw ConnectorError.USER_ID_USED.exception("A_20074");
      }
    }
    tucKon171(context, card, cardNeedsReset);
    synchronized (this) {
      remember(userId);
      sessions.put(Key.of(context, cardHandle), new Session(clock.instant()));
      cardCounts.put(cardHandle, 0);
    }
    return "COMFORT";
  }

  /**
   * TUC_KON_171 steps 1–7: with {@code cardNeedsReset} first reset the card (step 3, here
   * TUC_KON_172), then PIN.QES with the display „Komfortsignatur aktivieren“ in DF.QES, if possible
   * in SE #2 via the channel gSMC-KT↔HBA (TIP1-A_5012, LIANA-112.13); in the error case LIANA
   * leaves DF.QES (b) and releases the card (c).
   */
  private void tucKon171(Context context, CardObject card, boolean cardNeedsReset) {
    if (!settings.enabled()) {
      throw ConnectorError.COMFORT_DISABLED.exception("SAK_COMFORT_SIGNATURE = Disabled");
    }
    CardLocks.Lock lock = locks.lock(card.cardHandle());
    try {
      if (cardNeedsReset) {
        tucKon172(card);
      }
      Optional<CardToCard.Target> se2 = channels.prepare(card);
      cardSignature.enter(card, CardSignature.Key.QES_E256);
      boolean verified = false;
      try {
        if (se2.isPresent()) {
          channels.environment(card, 2);
        }
        PinVerification.Result result =
            pins.verifyComfort(
                context, card, se2.map(target -> channels.remotePin(card, target)).orElse(null));
        switch (result.pinResult()) {
          case OK -> verified = true;
          case REJECTED -> throw ConnectorError.COMFORT_PIN_REJECTED.exception("PIN.QES");
          case WASBLOCKED, NOWBLOCKED ->
              throw ConnectorError.COMFORT_PIN_BLOCKED.exception("PIN.QES");
          default ->
              throw ConnectorError.ACCESS_CONDITIONS.exception("PIN.QES " + result.pinResult());
        }
        synchronized (this) {
          se2.ifPresentOrElse(
              target -> secureEnvironments.put(card.cardHandle(), target),
              () -> secureEnvironments.remove(card.cardHandle()));
        }
      } finally {
        if (!verified) {
          cardSignature.leave(card);
          authState.notVerified(context, card.cardHandle(), PIN_QES);
        }
      }
    } finally {
      locks.unlock(lock);
    }
  }

  /**
   * DeactivateComfortSignature per TAB_KON_878 with TUC_KON_172 for {@code cardHandles}. Returns
   * the warnings 4265 (CardHandle invalid or not an HBA) and 4266 (no card session, i.e. never in
   * Comfort mode), one each with the comma-separated list.
   */
  public List<ConnectorException> deactivate(List<String> cardHandles) {
    if (cardHandles.isEmpty() || cardHandles.stream().anyMatch(h -> h == null || h.isBlank())) {
      throw ConnectorError.SYNTAX.exception("CardHandle fehlt");
    }
    if (!settings.enabled()) {
      throw ConnectorError.COMFORT_DISABLED.exception("SAK_COMFORT_SIGNATURE = Disabled");
    }
    Set<String> invalid = new LinkedHashSet<>();
    Set<String> noSession = new LinkedHashSet<>();
    for (String cardHandle : cardHandles) {
      Optional<CardObject> card =
          cards.card(cardHandle).filter(c -> c.data().type() == CardType.HBA);
      if (card.isEmpty()) {
        invalid.add(cardHandle);
      } else if (!known(cardHandle)) {
        noSession.add(cardHandle);
      } else {
        tucKon172(card.get());
      }
    }
    List<ConnectorException> warnings = new ArrayList<>();
    if (!invalid.isEmpty()) {
      warnings.add(listed(ConnectorError.COMFORT_CARD_HANDLE_INVALID, invalid));
    }
    if (!noSession.isEmpty()) {
      warnings.add(listed(ConnectorError.COMFORT_NO_CARD_SESSION, noSession));
    }
    return List.copyOf(warnings);
  }

  /**
   * TUC_KON_172 by the administrator (SAK_COMFORT_SIGNATURE = Disabled): all HBAs with a comfort
   * signature session.
   */
  private void deactivateAll() {
    Set<String> cardHandles;
    synchronized (this) {
      cardHandles = new LinkedHashSet<>();
      sessions.forEach(
          (key, session) -> {
            if (session.comfort) {
              cardHandles.add(key.cardHandle());
            }
          });
    }
    cardHandles.forEach(cardHandle -> cards.card(cardHandle).ifPresent(this::tucKon172));
  }

  /**
   * TUC_KON_172 step 5 for all card sessions of the HBA: reset the card's PIN.QES (leave DF.QES),
   * CARDSESSION.AUTHSTATE without PIN.QES, SIGNMODE = PIN, timer stopped.
   */
  private void tucKon172(CardObject card) {
    cardSignature.leave(card);
    List<Key> keys;
    synchronized (this) {
      keys =
          sessions.keySet().stream()
              .filter(key -> key.cardHandle().equals(card.cardHandle()))
              .toList();
      keys.forEach(
          key -> {
            sessions.get(key).comfort = false;
            sessions.get(key).elevated = false;
          });
      cardCounts.remove(card.cardHandle());
      secureEnvironments.remove(card.cardHandle());
    }
    keys.forEach(key -> authState.notVerified(key.context(), card.cardHandle(), PIN_QES));
  }

  /** GetSignatureMode per TAB_KON_882: TUC_KON_000 with UserId, TUC_KON_026, TUC_KON_173 (4269). */
  public Mode mode(Context context, String cardHandle) {
    CardObject card = access.card(context, cardHandle, true);
    access.checkFree(card);
    if (card.data().type() != CardType.HBA) {
      ConnectorError error = ConnectorError.SIGNATURE_MODE_FAILED;
      throw error.exception(
          error.text().replace("<cardHandle>", cardHandle), card.data().type().value());
    }
    Optional<SessionInfo> info;
    synchronized (this) {
      Session session = sessions.get(Key.of(context, cardHandle));
      info =
          session == null || !session.comfort
              ? Optional.empty()
              : Optional.of(
                  new SessionInfo(
                      Math.max(
                          0,
                          Math.min(
                              settings.max() - session.count,
                              CARD_MAX - cardCounts.getOrDefault(cardHandle, 0))),
                      remaining(session)));
    }
    return new Mode(settings.enabled(), settings.max(), settings.timer(), info);
  }

  /** The card session if SIGNMODE = Comfort (TUC_KON_150 or TUC_KON_170). */
  public synchronized Optional<Active> active(Context context, String cardHandle) {
    Key key = Key.of(context, cardHandle);
    Session session = sessions.get(key);
    return session != null && session.comfort ? Optional.of(new Active(key)) : Optional.empty();
  }

  /**
   * The HBA's CVC if TUC_KON_171 brought it into SE #2 (TUC_KON_158 step 1); otherwise empty, SE
   * #1.
   */
  public synchronized Optional<CardToCard.Target> secureEnvironment(CardObject card) {
    return Optional.ofNullable(secureEnvironments.get(card.cardHandle()));
  }

  /**
   * TUC_KON_170 steps 1 and 2: SAK_COMFORT_SIGNATURE (4263), Komfortsignatur timer (4271 after
   * TUC_KON_172).
   */
  public void start(Active active, CardObject card) {
    if (!settings.enabled()) {
      throw ConnectorError.COMFORT_DISABLED.exception("SAK_COMFORT_SIGNATURE = Disabled");
    }
    boolean expired;
    synchronized (this) {
      Session session = session(active);
      expired = remaining(session).isZero();
    }
    if (expired) {
      throw abort(card, "Komfortsignatur-Timer abgelaufen (A_18686-01)");
    }
  }

  /**
   * TUC_KON_158 step 3: Komfortsignatur counter at SAK_COMFORT_SIGNATURE_MAX → 4271 after
   * TUC_KON_172.
   */
  public void next(Active active, CardObject card) {
    boolean exhausted;
    synchronized (this) {
      exhausted = session(active).count >= settings.max();
    }
    if (exhausted) {
      throw abort(card, "SAK_COMFORT_SIGNATURE_MAX erreicht (A_19100-01)");
    }
  }

  /**
   * TUC_KON_158 step 5: counter + 1; at SAK_COMFORT_SIGNATURE_MAX LIANA resets the HBA's security
   * state (A_19100-01); SIGNMODE stays Comfort until {@link #next} reports 4271.
   */
  public void counted(Active active, CardObject card) {
    boolean exhausted;
    synchronized (this) {
      Session session = session(active);
      session.count++;
      cardCounts.merge(card.cardHandle(), 1, Integer::sum);
      exhausted = session.count >= settings.max();
      session.elevated = !exhausted;
    }
    if (exhausted) {
      cardSignature.leave(card);
    }
  }

  /** Error case with 4271 (TUC_KON_170, TUC_KON_158): first TUC_KON_172 for the HBA. */
  public ConnectorException abort(CardObject card, String detail) {
    tucKon172(card);
    return ConnectorError.COMFORT_ABORTED.exception(detail);
  }

  /** The HBA was removed: its card sessions end. */
  public synchronized void removed(String cardHandle) {
    sessions.keySet().removeIf(key -> key.cardHandle().equals(cardHandle));
    cardCounts.remove(cardHandle);
    secureEnvironments.remove(cardHandle);
  }

  private Session session(Active active) {
    Session session = sessions.get(active.key());
    if (session == null) {
      throw ConnectorError.COMFORT_ABORTED.exception("Komfortsignatursession beendet");
    }
    return session;
  }

  private synchronized boolean known(String cardHandle) {
    return sessions.keySet().stream().anyMatch(key -> key.cardHandle().equals(cardHandle));
  }

  private Duration remaining(Session session) {
    Duration left = settings.timer().minus(Duration.between(session.started, clock.instant()));
    return left.isNegative() ? Duration.ZERO : left;
  }

  private void remember(String userId) {
    userIds.addLast(userId);
    usedUserIds.add(userId);
    if (userIds.size() > USER_ID_HISTORY) {
      usedUserIds.remove(userIds.removeFirst());
    }
  }

  private static ConnectorException listed(ConnectorError error, Set<String> cardHandles) {
    String list = String.join(",", cardHandles);
    return error.exception(error.text().replace("<cardHandles>", list), list);
  }
}

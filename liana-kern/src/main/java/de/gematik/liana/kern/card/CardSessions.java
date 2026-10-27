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
import de.gematik.liana.kern.error.ConnectorError;
import de.gematik.liana.kern.terminal.CardTerminal;
import de.gematik.liana.kern.terminal.TerminalRegistry;
import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * Card sessions of the PoPP tunnel: operations StartCardSession (A_25970-01), SecureSendAPDU
 * (A_25822-02) and StopCardSession (A_26022) with TUC_KON_223, TUC_KON_208 and TUC_KON_224.
 *
 * <p>Every step brings its {@code expectedStatusWords} (the {@link ScenarioDecoder} rejects
 * scenarios without them with 4286); they apply literally (TUC_KON_208 step 6a, A_26069-01): an
 * empty list expects no status word, the first APDU of the step yields 4284. A session reserves its
 * card exclusively via {@link CardLocks} (TUC_KON_023, A_25895): a further reservation and every
 * other card access abort with 4093. Every session has an APDU scenario timer (A_25860-01), first
 * {@code CARD_SESSION_TIMEOUT}, after each SecureSendAPDU the TimeSpan of the scenario. {@link
 * #expire()} ends expired sessions; the operations call it themselves, the application additionally
 * on a schedule. If the card is removed, its session ends without reset.
 *
 * <p>There is no lock across all sessions: every session has its own lock, sessions on different
 * cards run side by side. {@link #expire()} skips a session that is currently processing a
 * SecureSendAPDU; its timer is reset by that SecureSendAPDU anyway.
 */
public final class CardSessions {

  /** Return value of SecureSendAPDU; {@code apduNotProcessed}: warning 4284, the loop aborted. */
  public record Result(List<byte[]> responseApdus, long timeSpan, boolean apduNotProcessed) {}

  /**
   * CARD/SESSION/TIMEOUT (A_25860-01, TUC_KON_208 step 7) with the parameters of the event. {@code
   * timer} per the event table of TUC_KON_027: {@link #KONNEKTOR} for CARD_SESSION_TIMEOUT, {@link
   * #POPP} for the TimeSpan of the scenario.
   */
  public record Timeout(String cardType, String sessionId, String timer) {

    public static final String TOPIC = "CARD/SESSION/TIMEOUT";

    /** Connector timer: CARD_SESSION_TIMEOUT until the first SecureSendAPDU (A_25860-01 b). */
    public static final String KONNEKTOR = "Konnektor";

    /**
     * PoPP service timer: TimeSpan of the preceding scenario (A_25860-01 a, TUC_KON_208 step 7).
     */
    public static final String POPP = "PoPP";
  }

  /** A session has started ({@code open}) or ended (TUC_KON_224, timeout, card removed). */
  public record Change(String sessionId, boolean open) {}

  /**
   * A running session for the Admin API (LIANA-149): SessionID, card, expiry of the APDU scenario
   * timer (A_25860-01) and which timer is running ({@link Timeout#KONNEKTOR} or {@link
   * Timeout#POPP}).
   */
  public record OpenSession(
      String sessionId,
      String cardHandle,
      String ctId,
      int slotNo,
      Instant deadline,
      String timer) {}

  private static final HexFormat HEX = HexFormat.of().withUpperCase();

  private final CardAccess access;
  private final CardLocks locks;
  private final TerminalRegistry terminals;
  private final ScenarioDecoder decoder;
  private final Clock clock;
  private final Supplier<Duration> sessionTimeout;
  private final Map<String, Session> sessions = new ConcurrentHashMap<>();
  private final List<Consumer<Timeout>> listeners = new CopyOnWriteArrayList<>();
  private final List<Consumer<Change>> changeListeners = new CopyOnWriteArrayList<>();

  /**
   * A running session with the lock of its card; {@code nextSequence} is the expected
   * sequenceCounter. The fields change only under {@link #busy}; {@code ended} is set as soon as
   * TUC_KON_224 has ended it.
   */
  private static final class Session {
    final String id;
    final CardObject card;
    final CardLocks.Lock lock;
    final ReentrantLock busy = new ReentrantLock();
    long nextSequence;
    // volatile for {@link #open()}, which reads without {@link #busy}
    volatile Instant deadline;
    volatile String timer;
    volatile boolean ended;

    Session(String id, CardObject card, CardLocks.Lock lock, Instant deadline) {
      this.id = id;
      this.card = card;
      this.lock = lock;
      this.deadline = deadline;
      this.timer = Timeout.KONNEKTOR;
    }
  }

  /**
   * {@code sessionTimeout}: CARD_SESSION_TIMEOUT (TAB_KON_554), deadline until the first
   * SecureSendAPDU; read at the start of each session, so a change via the KMS applies to new
   * sessions.
   */
  public CardSessions(
      CardAccess access,
      CardLocks locks,
      TerminalRegistry terminals,
      CardList cards,
      ScenarioDecoder decoder,
      Clock clock,
      Supplier<Duration> sessionTimeout) {
    this.access = access;
    this.locks = locks;
    this.terminals = terminals;
    this.decoder = decoder;
    this.clock = clock;
    this.sessionTimeout = sessionTimeout;
    cards.addListener(
        event -> {
          if (event.topic() == CardEvent.Topic.REMOVED) {
            removed(event.card());
          }
        });
  }

  /** From now on reports CARD/SESSION/TIMEOUT to {@code listener}. */
  public void addListener(Consumer<Timeout> listener) {
    listeners.add(listener);
  }

  /**
   * From now on reports start and end of every session to {@code listener} (Admin API push,
   * LIANA-151).
   */
  public void addChangeListener(Consumer<Change> listener) {
    changeListeners.add(listener);
  }

  /**
   * A_25970-01 StartCardSession (TAB_KON_274): checkArguments, TUC_KON_000 with cardHandle, eGK
   * only (4209), then TUC_KON_223.
   *
   * @return the SessionID (UUID per RFC 4122)
   */
  public String start(Context context, String cardHandle) {
    // TUC_KON_000 with cardHandle of an eGK (rule R5): R3, card inserted (4008), CT reachable from
    // the workplace
    // (4015)
    CardObject card = access.card(context, cardHandle);
    if (card.data().type() != CardType.EGK) {
      String type = card.data().type().value();
      throw ConnectorError.CARD_TYPE_UNSUPPORTED.exception(
          ConnectorError.CARD_TYPE_UNSUPPORTED.text().replace("%CardType%", type),
          cardHandle + " ist " + type);
    }
    expire();
    return startSession(card);
  }

  /**
   * A_25822-02 SecureSendAPDU (TAB_KON_271): check the scenario ({@link ScenarioDecoder}), then
   * TUC_KON_208. Errors from the sequenceCounter check onward end the session (TUC_KON_224).
   */
  public Result secureSend(String signedScenario) {
    if (signedScenario == null || signedScenario.isBlank()) {
      throw ConnectorError.SYNTAX.exception("SignedScenario fehlt");
    }
    Scenario scenario = decoder.decode(signedScenario.strip());
    expire();
    Session session = session(scenario.clientSessionId(), "clientSessionId");
    try {
      if (scenario.sequenceCounter() != session.nextSequence) {
        stopSession(session);
        throw ConnectorError.UNEXPECTED_SEQUENCE.exception(
            "sequenceCounter " + scenario.sequenceCounter() + " statt " + session.nextSequence);
      }
      List<byte[]> responses = new ArrayList<>();
      boolean apduNotProcessed = false;
      for (Scenario.Step step : scenario.steps()) {
        byte[] response = transmit(session, step.commandApdu());
        responses.add(response);
        if (!expected(response, step.expectedStatusWords())) {
          apduNotProcessed = true;
          break;
        }
      }
      session.nextSequence++;
      if (scenario.timeSpan() == 0) {
        stopSession(session);
        fire(session, Timeout.POPP);
      } else {
        session.deadline = clock.instant().plusMillis(scenario.timeSpan());
        session.timer = Timeout.POPP;
      }
      return new Result(List.copyOf(responses), scenario.timeSpan(), apduNotProcessed);
    } finally {
      session.busy.unlock();
    }
  }

  /** A_26022 StopCardSession (TAB_KON_276): checkArguments, TUC_KON_224. */
  public void stop(String sessionId) {
    if (sessionId == null || sessionId.isBlank()) {
      throw ConnectorError.SYNTAX.exception("SessionId fehlt");
    }
    expire();
    Session session = session(sessionId.strip(), "SessionId");
    try {
      stopSession(session);
    } finally {
      session.busy.unlock();
    }
  }

  /**
   * A_25860-01: ends every session whose APDU scenario timer has expired and reports
   * CARD/SESSION/TIMEOUT.
   */
  public void expire() {
    Instant now = clock.instant();
    for (Session session : sessions.values()) {
      if (!session.busy.tryLock()) {
        continue;
      }
      try {
        if (!session.ended && !now.isBefore(session.deadline)) {
          stopSession(session);
          fire(session, session.timer);
        }
      } finally {
        session.busy.unlock();
      }
    }
  }

  /** The running sessions, without those just ended by TUC_KON_224. */
  public List<OpenSession> open() {
    return sessions.values().stream()
        .filter(session -> !session.ended)
        .map(
            session ->
                new OpenSession(
                    session.id,
                    session.card.cardHandle(),
                    session.card.ctId(),
                    session.card.slotNo(),
                    session.deadline,
                    session.timer))
        .toList();
  }

  /** Whether the card {@code cardHandle} is reserved by a card session (A_25895). */
  public boolean locked(String cardHandle) {
    return locks.locked(cardHandle);
  }

  /** The running session {@code id}, locked for the caller; 4288 if it does not exist (anymore). */
  private Session session(String id, String parameter) {
    Session session = sessions.get(id);
    if (session != null) {
      session.busy.lock();
      if (!session.ended) {
        return session;
      }
      session.busy.unlock();
    }
    throw ConnectorError.UNKNOWN_SESSION.exception(parameter + " " + id);
  }

  /**
   * TUC_KON_223 „Starte Kartensitzung“: reserve (TUC_KON_023), reset (TUC_KON_024), SessionID,
   * timer.
   */
  private String startSession(CardObject card) {
    CardLocks.Lock lock = locks.lock(card.cardHandle());
    Session session =
        new Session(
            UUID.randomUUID().toString(), card, lock, clock.instant().plus(sessionTimeout.get()));
    session.busy.lock();
    try {
      sessions.put(session.id, session);
      terminal(card).reset(card.slotNo());
      changed(session.id, true);
      return session.id;
    } catch (IOException | RuntimeException e) {
      end(session);
      throw TerminalErrors.of(card, "Reset", e);
    } finally {
      session.busy.unlock();
    }
  }

  /** TUC_KON_224 „Stoppe Kartensitzung“: remove SessionID, reset card, release lock. */
  private void stopSession(Session session) {
    end(session);
    try {
      terminal(session.card).reset(session.card.slotNo());
    } catch (IOException | RuntimeException e) {
      // card removed or terminal gone: the session has ended anyway
    }
  }

  /** Remove the SessionID and release the card's lock (TUC_KON_023 doLock=false). */
  private void end(Session session) {
    session.ended = true;
    boolean removed = sessions.remove(session.id, session);
    locks.unlock(session.lock);
    if (removed) {
      changed(session.id, false);
    }
  }

  private void changed(String sessionId, boolean open) {
    Change change = new Change(sessionId, open);
    changeListeners.forEach(listener -> listener.accept(change));
  }

  /**
   * TUC_KON_200 „SendeAPDU“ for the reserved card; a terminal error (4044) or timeout (4094) ends
   * the session.
   */
  private byte[] transmit(Session session, byte[] command) {
    try {
      return terminal(session.card).transmit(session.card.slotNo(), command);
    } catch (IOException | RuntimeException e) {
      stopSession(session);
      throw TerminalErrors.of(session.card, HEX.formatHex(command), e);
    }
  }

  private CardTerminal terminal(CardObject card) throws IOException {
    return terminals
        .terminal(card.ctId())
        .orElseThrow(() -> new IOException("Terminal " + card.ctId() + " fehlt"));
  }

  /**
   * Removed card: its session ends without reset; a running SecureSendAPDU fails at the terminal.
   */
  private void removed(CardObject card) {
    sessions.values().stream()
        .filter(s -> s.card.cardHandle().equals(card.cardHandle()))
        .forEach(this::end);
  }

  private void fire(Session session, String timer) {
    Timeout timeout = new Timeout(session.card.data().type().value(), session.id, timer);
    listeners.forEach(listener -> listener.accept(timeout));
  }

  /** Status word (last two bytes) in the list of expected ones, case-insensitive. */
  private static boolean expected(byte[] response, List<String> statusWords) {
    if (response.length < 2) {
      return false;
    }
    String sw = HEX.formatHex(response, response.length - 2, response.length);
    return statusWords.stream().anyMatch(w -> w.toUpperCase(Locale.ROOT).equals(sw));
  }
}

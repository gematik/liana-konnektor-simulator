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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.kern.access.Context;
import de.gematik.liana.kern.access.Infomodel;
import de.gematik.liana.kern.error.ConnectorError;
import de.gematik.liana.kern.error.ConnectorException;
import de.gematik.liana.kern.terminal.TerminalRegistry;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

class CardSessionsTest {

  private static final Context CTX = new Context("M1", "CS1", "WP1", null);
  private static final HexFormat HEX = HexFormat.of().withUpperCase();

  private final ManualClock clock = new ManualClock();
  private final SessionTerminal kt01 = new SessionTerminal("KT-01", 2);
  private final SessionTerminal kt02 = new SessionTerminal("KT-02", 1);
  private final TerminalRegistry registry = new TerminalRegistry(List.of(kt01, kt02));
  private final CardList cards = new CardList(registry, clock);
  private final Infomodel infomodel =
      new Infomodel(
          List.of("M1"),
          List.of("CS1"),
          List.of(new Infomodel.Workplace("WP1", List.of("M1"), List.of("CS1"), List.of("KT-01"))));

  /** Scenarios by their „JWS“; the signature check belongs to the adapter. */
  private final Map<String, Scenario> signed = new HashMap<>();

  private Duration sessionTimeout = Duration.ofSeconds(30);
  private final CardLocks locks = new CardLocks();
  private final CardSessions sessions =
      new CardSessions(
          new CardAccess(infomodel, cards, locks),
          locks,
          registry,
          cards,
          this::decode,
          clock,
          () -> sessionTimeout);
  private final List<CardSessions.Timeout> timeouts = new ArrayList<>();
  private String handle;

  @BeforeEach
  void stecken() {
    cards.start();
    kt01.insert(1);
    kt02.insert(1);
    handle = cards.card("KT-01", 1).orElseThrow().cardHandle();
    sessions.addListener(timeouts::add);
    kt01.answer("00A4040C07D2760001448000", "9000");
    kt01.answer("00B0910000", "EF2B9000");
    kt01.answer("00B0870000", "6A82");
    kt01.scripted = true;
  }

  private Scenario decode(String jws) {
    Scenario scenario = signed.get(jws);
    if (scenario == null) {
      throw ConnectorError.SIGNATURE_INVALID.exception(jws);
    }
    return scenario;
  }

  private String scenario(String sessionId, long counter, long timeSpan, String... stepsAndWords) {
    List<Scenario.Step> steps = new ArrayList<>();
    for (String step : stepsAndWords) {
      String[] parts = step.split(" ");
      steps.add(new Scenario.Step(HEX.parseHex(parts[0]), List.of(parts).subList(1, parts.length)));
    }
    String jws = "jws-" + signed.size();
    signed.put(jws, new Scenario(sessionId, counter, timeSpan, steps));
    return jws;
  }

  private static List<String> hex(CardSessions.Result result) {
    return result.responseApdus().stream().map(HEX::formatHex).toList();
  }

  @Test
  @DisplayName(
      "A_25970-01 / TUC_KON_223: StartCardSession reserviert die eGK, setzt sie zurück und liefert eine UUID")
  void start() {
    int resets = kt01.resets;
    String id = sessions.start(CTX, handle);
    assertEquals(id, UUID.fromString(id).toString());
    assertTrue(sessions.locked(handle));
    assertEquals(resets + 1, kt01.resets);
  }

  @Test
  @DisplayName(
      "A_25860-01 / LIANA-149: open() zeigt laufende Sitzungen mit Karte, Ablauf und Timer; beendete fehlen")
  void offeneSitzungen() {
    String id = sessions.start(CTX, handle);
    Instant started = clock.instant();
    assertEquals(
        List.of(
            new CardSessions.OpenSession(
                id, handle, "KT-01", 1, started.plus(sessionTimeout), "Konnektor")),
        sessions.open());
    sessions.secureSend(scenario(id, 0, 10000, "00B0910000 9000"));
    assertEquals("PoPP", sessions.open().getFirst().timer());
    assertEquals(clock.instant().plusMillis(10000), sessions.open().getFirst().deadline());
    sessions.stop(id);
    assertEquals(List.of(), sessions.open());
  }

  @Test
  @DisplayName(
      "A_25822-02 / TUC_KON_208: SecureSendAPDU schickt die Schritte an die Karte, Antworten in Reihenfolge, TimeSpan zurück")
  void secureSend() {
    String id = sessions.start(CTX, handle);
    var result =
        sessions.secureSend(
            scenario(id, 0, 10000, "00A4040C07D2760001448000 9000", "00B0910000 9000 6281"));
    assertEquals(List.of("9000", "EF2B9000"), hex(result));
    assertEquals(10000, result.timeSpan());
    assertFalse(result.apduNotProcessed());
    assertEquals(List.of("00A4040C07D2760001448000", "00B0910000"), kt01.sent);
  }

  @Test
  @DisplayName(
      "TUC_KON_208 6b: unerwartetes Statuswort bricht die Schleife ab, Warnung 4284, Sitzung läuft weiter")
  void unerwartetesStatuswort() {
    String id = sessions.start(CTX, handle);
    var result =
        sessions.secureSend(scenario(id, 0, 10000, "00B0870000 9000 6281", "00B0910000 9000"));
    assertEquals(List.of("6A82"), hex(result));
    assertTrue(result.apduNotProcessed());
    assertTrue(sessions.locked(handle));
    assertEquals(
        List.of("EF2B9000"), hex(sessions.secureSend(scenario(id, 1, 10000, "00B0910000 9000"))));
  }

  @Test
  @DisplayName(
      "A_26069-01 / TUC_KON_208 6a: expectedStatusWords [] gilt wörtlich, die erste APDU des Schritts ergibt "
          + "4284; keine Vererbung aus dem vorigen Schritt")
  void leereStatuswortliste() {
    String id = sessions.start(CTX, handle);
    var result =
        sessions.secureSend(
            scenario(
                id, 0, 10000, "00A4040C07D2760001448000 9000", "00B0910000", "00B0870000 6A82"));
    assertEquals(List.of("9000", "EF2B9000"), hex(result));
    assertTrue(result.apduNotProcessed());
    assertEquals(List.of("00A4040C07D2760001448000", "00B0910000"), kt01.sent);
  }

  @Test
  @DisplayName(
      "TUC_KON_208: Szenario ohne Schritte (steps: [], minItems 0) → leere Antwortliste, Zähler weiter; "
          + "mit TimeSpan 0 endet die Sitzung")
  void ohneSchritte() {
    String id = sessions.start(CTX, handle);
    var result = sessions.secureSend(scenario(id, 0, 10000));
    assertEquals(List.of(), hex(result));
    assertFalse(result.apduNotProcessed());
    assertEquals(List.of(), kt01.sent);
    assertTrue(sessions.locked(handle));
    assertError(
        ConnectorError.UNEXPECTED_SEQUENCE, () -> sessions.secureSend(scenario(id, 0, 10000)));

    String next = sessions.start(CTX, handle);
    sessions.secureSend(scenario(next, 0, 10000));
    assertEquals(List.of(), hex(sessions.secureSend(scenario(next, 1, 0))));
    assertFalse(sessions.locked(handle));
    assertEquals(List.of(new CardSessions.Timeout("EGK", next, "PoPP")), timeouts);
  }

  @Test
  @DisplayName(
      "TUC_KON_208 7: TimeSpan 0 beendet die Sitzung, CARD/SESSION/TIMEOUT Timer=PoPP, StopCardSession → 4288")
  void letztesSzenario() {
    String id = sessions.start(CTX, handle);
    sessions.secureSend(scenario(id, 0, 0, "00B0910000 9000"));
    assertFalse(sessions.locked(handle));
    assertEquals(List.of(new CardSessions.Timeout("EGK", id, "PoPP")), timeouts);
    assertError(ConnectorError.UNKNOWN_SESSION, () -> sessions.stop(id));
  }

  @Test
  @DisplayName(
      "A_25860-01 a: Folgeaufruf nach Ablauf von TimeSpan → Sitzung beendet, CARD/SESSION/TIMEOUT Timer=PoPP, 4288")
  void timeSpanAbgelaufen() {
    String id = sessions.start(CTX, handle);
    sessions.secureSend(scenario(id, 0, 10000, "00B0910000 9000"));
    clock.advance(Duration.ofMillis(9999));
    sessions.expire();
    assertTrue(sessions.locked(handle));
    clock.advance(Duration.ofMillis(1));
    sessions.expire();
    assertFalse(sessions.locked(handle));
    assertEquals(List.of(new CardSessions.Timeout("EGK", id, "PoPP")), timeouts);
    assertError(
        ConnectorError.UNKNOWN_SESSION,
        () -> sessions.secureSend(scenario(id, 1, 0, "00B0910000")));
    assertError(ConnectorError.UNKNOWN_SESSION, () -> sessions.stop(id));
  }

  @Test
  @DisplayName(
      "A_25860-01 b: kein SecureSendAPDU innerhalb CARD_SESSION_TIMEOUT → Sitzung beendet, Timer=Konnektor, auch ohne expire()-Takt")
  void sessionTimeout() {
    String id = sessions.start(CTX, handle);
    clock.advance(Duration.ofSeconds(30));
    assertError(ConnectorError.UNKNOWN_SESSION, () -> sessions.stop(id));
    assertEquals(List.of(new CardSessions.Timeout("EGK", id, "Konnektor")), timeouts);
  }

  @Test
  @DisplayName(
      "TAB_KON_554: geändertes CARD_SESSION_TIMEOUT gilt für neue Sitzungen, laufende behalten ihre Frist")
  void sessionTimeoutGeaendert() {
    String old = sessions.start(CTX, handle);
    sessionTimeout = Duration.ofSeconds(10);
    clock.advance(Duration.ofSeconds(10));
    assertTrue(sessions.locked(handle), "laufende Sitzung behält 30 s");
    clock.advance(Duration.ofSeconds(20));
    sessions.expire();
    String fresh = sessions.start(CTX, handle);
    clock.advance(Duration.ofSeconds(10));
    sessions.expire();
    assertEquals(
        List.of(
            new CardSessions.Timeout("EGK", old, "Konnektor"),
            new CardSessions.Timeout("EGK", fresh, "Konnektor")),
        timeouts);
  }

  @Test
  @DisplayName(
      "A_25895: zweite StartCardSession auf dieselbe Karte → 4093, nach StopCardSession wieder frei")
  void exklusiv() {
    String id = sessions.start(CTX, handle);
    assertError(ConnectorError.CARD_LOCKED, () -> sessions.start(CTX, handle));
    sessions.stop(id);
    assertFalse(sessions.locked(handle));
    sessions.stop(sessions.start(CTX, handle));
  }

  @Test
  @DisplayName("TUC_KON_208 5: falscher sequenceCounter → 4285 und Sitzung beendet")
  void sequenz() {
    String id = sessions.start(CTX, handle);
    assertError(
        ConnectorError.UNEXPECTED_SEQUENCE,
        () -> sessions.secureSend(scenario(id, 1, 10000, "00B0910000")));
    assertFalse(sessions.locked(handle));
  }

  @Test
  @DisplayName("TUC_KON_208 3 / TUC_KON_224: unbekannte Session → 4288; leere Parameter → 4000")
  void unbekannt() {
    assertError(
        ConnectorError.UNKNOWN_SESSION,
        () -> sessions.secureSend(scenario("nope", 0, 0, "00B0910000")));
    assertError(ConnectorError.UNKNOWN_SESSION, () -> sessions.stop(UUID.randomUUID().toString()));
    assertError(ConnectorError.SYNTAX, () -> sessions.stop(" "));
    assertError(ConnectorError.SYNTAX, () -> sessions.start(CTX, ""));
    assertError(ConnectorError.SYNTAX, () -> sessions.secureSend(null));
  }

  @Test
  @DisplayName(
      "TUC_KON_000 / TAB_KON_277: unbekanntes Handle → 4008, KT nicht am Arbeitsplatz → 4015, Kontext → 4021")
  void zugriff() {
    assertError(ConnectorError.CARD_NOT_INSERTED, () -> sessions.start(CTX, "EGK-24"));
    String kt02Handle = cards.card("KT-02", 1).orElseThrow().cardHandle();
    assertError(ConnectorError.CT_NOT_REACHABLE, () -> sessions.start(CTX, kt02Handle));
    assertError(
        ConnectorError.CONTEXT_INCOMPLETE,
        () -> sessions.start(new Context("M1", "CS1", null, null), handle));
  }

  @Test
  @DisplayName("Karte gezogen: die Sitzung endet, das neue Handle ist frei")
  void gezogen() {
    String id = sessions.start(CTX, handle);
    kt01.eject(1);
    assertError(ConnectorError.UNKNOWN_SESSION, () -> sessions.stop(id));
    kt01.scripted = false;
    kt01.insert(1);
    sessions.start(CTX, cards.card("KT-01", 1).orElseThrow().cardHandle());
  }

  @Test
  @DisplayName(
      "LIANA-151: Beginn und Ende jeder Sitzung melden eine Change, bei StopCardSession (TUC_KON_224), "
          + "Timeout (A_25860-01) und gezogener Karte; ein Fehlstart meldet nichts")
  void aenderungen() {
    List<CardSessions.Change> changes = new ArrayList<>();
    sessions.addChangeListener(changes::add);
    String stopped = sessions.start(CTX, handle);
    sessions.stop(stopped);
    String timedOut = sessions.start(CTX, handle);
    clock.advance(Duration.ofSeconds(30));
    sessions.expire();
    String ejected = sessions.start(CTX, handle);
    kt01.eject(1);
    assertError(ConnectorError.CARD_NOT_INSERTED, () -> sessions.start(CTX, handle));
    assertEquals(
        List.of(
            new CardSessions.Change(stopped, true),
            new CardSessions.Change(stopped, false),
            new CardSessions.Change(timedOut, true),
            new CardSessions.Change(timedOut, false),
            new CardSessions.Change(ejected, true),
            new CardSessions.Change(ejected, false)),
        changes);
  }

  private static void assertError(ConnectorError expected, Executable call) {
    assertEquals(expected, assertThrows(ConnectorException.class, call).error());
  }

  /** Clock that only advances on {@link #advance}. */
  static final class ManualClock extends Clock {
    private Instant now = Instant.parse("2026-10-08T12:00:00Z");

    void advance(Duration duration) {
      now = now.plus(duration);
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

  /**
   * Reads the eGK on insertion as recorded; with {@link #scripted} it answers commands from {@link
   * #answer}.
   */
  static final class SessionTerminal extends RecordedTerminal {
    private final Map<String, String> answers = new HashMap<>();
    final List<String> sent = new ArrayList<>();
    int resets;
    boolean scripted;

    SessionTerminal(String id, int slots) {
      super(id, slots, EGK_VALID);
    }

    void answer(String command, String response) {
      answers.put(command, response);
    }

    @Override
    public byte[] reset(int slot) {
      resets++;
      return super.reset(slot);
    }

    @Override
    public byte[] transmit(int slot, byte[] commandApdu) {
      String command = HEX.formatHex(commandApdu);
      if (scripted && answers.containsKey(command)) {
        sent.add(command);
        return HEX.parseHex(answers.get(command));
      }
      return super.transmit(slot, commandApdu);
    }
  }
}

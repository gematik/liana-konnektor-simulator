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
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.kern.access.Context;
import de.gematik.liana.kern.access.Infomodel;
import de.gematik.liana.kern.error.ConnectorError;
import de.gematik.liana.kern.error.ConnectorException;
import de.gematik.liana.kern.terminal.TerminalRegistry;
import java.time.Duration;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

/**
 * A_25895: a card session (StartCardSession) reserves its card via TUC_KON_023. Every other
 * operation with card access checks the lock in TUC_KON_026 step 2 and aborts with 4093; operations
 * on other cards run unhindered and side by side.
 */
class CardLocksTest {

  private static final Context CTX = new Context("M1", "CS1", "WP1", null);
  private static final HexFormat HEX = HexFormat.of().withUpperCase();

  /** The hash the recorded smcb-valid signs (ExternalAuthenticationTest). */
  private static final byte[] HASH =
      HEX.parseHex("F13A9BEAA8AC0B4D19B58447C85229559C1BE459C8055A83E1A63812354717FE");

  private final CardSessionsTest.ManualClock clock = new CardSessionsTest.ManualClock();
  private final RecordedCards kt01 = new RecordedCards("KT-01");
  private final RecordedCards kt02 = new RecordedCards("KT-02");
  private final TerminalRegistry registry = new TerminalRegistry(List.of(kt01, kt02));
  private final CardList cards = new CardList(registry, clock);
  private final Infomodel infomodel =
      new Infomodel(
          List.of("M1"),
          List.of("CS1"),
          List.of(
              new Infomodel.Workplace(
                  "WP1", List.of("M1"), List.of("CS1"), List.of("KT-01", "KT-02"))));
  private final CardLocks locks = new CardLocks();
  private final CardAccess access = new CardAccess(infomodel, cards, locks);
  private final AuthState authState = new AuthState();
  private final PinVerification pins = new PinVerification(access, registry, authState);
  private final ExternalAuthentication external =
      new ExternalAuthentication(access, registry, authState);
  private final CardCertificates certificates = new CardCertificates(access, registry);
  private final Map<String, Scenario> signed = new HashMap<>();
  private final CardSessions sessions =
      new CardSessions(
          access, locks, registry, cards, this::decode, clock, () -> Duration.ofSeconds(30));
  private String egk;
  private String egk2;
  private String smcb;

  @BeforeEach
  void stecken() {
    cards.start();
    kt01.insert(1, RecordedTerminal.EGK_VALID)
        .insert(2, RecordedTerminal.SMCB_VALID)
        .also(2, RecordedTerminal.SMCB_VALID_SIGN);
    kt02.insert(1, RecordedTerminal.EGK_VALID);
    egk = cards.card("KT-01", 1).orElseThrow().cardHandle();
    smcb = cards.card("KT-01", 2).orElseThrow().cardHandle();
    egk2 = cards.card("KT-02", 1).orElseThrow().cardHandle();
    kt01.sent.values().forEach(List::clear);
  }

  private synchronized Scenario decode(String jws) {
    return signed.get(jws);
  }

  /** A scenario with one APDU that accepts any response (6D00 of the recorded card). */
  private synchronized String scenario(String sessionId, long counter) {
    String jws = "jws-" + signed.size();
    signed.put(
        jws,
        new Scenario(
            sessionId,
            counter,
            10_000,
            List.of(new Scenario.Step(HEX.parseHex("00B0910000"), List.of("9000", "6D00")))));
    return jws;
  }

  @Test
  @DisplayName(
      "A_25895 / TAB_KON_738: VerifyPin auf die eGK einer Kartensitzung → 4093 aus TUC_KON_026, vor der "
          + "Kartentypprüfung (4209); die Karte sieht kein Kommando")
  void verifyPin() {
    sessions.start(CTX, egk);
    assertError(ConnectorError.CARD_LOCKED, () -> pins.verify(CTX, egk, "PIN.CH"));
    assertEquals(List.of(), kt01.sent.get(1));
  }

  @Test
  @DisplayName(
      "A_25895 / TAB_KON_782: ExternalAuthenticate auf die eGK einer Kartensitzung → 4093 aus TUC_KON_026, vor "
          + "der Schlüsselprüfung (4058)")
  void externalAuthenticate() {
    sessions.start(CTX, egk);
    assertError(ConnectorError.CARD_LOCKED, () -> external.sign(CTX, egk, HASH));
    assertEquals(List.of(), kt01.sent.get(1));
  }

  @Test
  @DisplayName(
      "TAB_KON_679: ReadCardCertificate auf die eGK einer Kartensitzung bleibt 4090 – checkArguments weist die "
          + "eGK vor TUC_KON_026 ab")
  void readCardCertificateEgk() {
    sessions.start(CTX, egk);
    assertError(
        ConnectorError.EGK_ACCESS_DENIED,
        () -> certificates.read(CTX, egk, List.of("C.AUT"), null));
  }

  @Test
  @DisplayName(
      "TUC_KON_026 Schritt 2: auf eine fremd reservierte SMC-B brechen VerifyPin, ReadCardCertificate und "
          + "ExternalAuthenticate mit 4093 ab, StartCardSession mit 4209 (nur eGK)")
  void fremdReservierteSmcb() {
    CardLocks.Lock lock = locks.lock(smcb);
    assertError(ConnectorError.CARD_LOCKED, () -> pins.verify(CTX, smcb, "PIN.SMC"));
    assertError(
        ConnectorError.CARD_LOCKED, () -> certificates.read(CTX, smcb, List.of("C.AUT"), null));
    assertError(ConnectorError.CARD_LOCKED, () -> external.sign(CTX, smcb, HASH));
    assertError(ConnectorError.CARD_TYPE_UNSUPPORTED, () -> sessions.start(CTX, smcb));
    assertEquals(List.of(), kt01.sent.get(2));
    locks.unlock(lock);
    assertEquals(PinVerification.PinResult.OK, pins.verify(CTX, smcb, "PIN.SMC").pinResult());
  }

  @Test
  @DisplayName(
      "A_25895: das Lock gilt nur der reservierten Karte – die SMC-B im selben KT bleibt nutzbar")
  void andereKarteFrei() {
    sessions.start(CTX, egk);
    assertEquals(PinVerification.PinResult.OK, pins.verify(CTX, smcb, "PIN.SMC").pinResult());
    external.sign(CTX, smcb, HASH);
    assertEquals(1, certificates.read(CTX, smcb, List.of("C.AUT"), null).size());
  }

  @Test
  @DisplayName(
      "TUC_KON_224: nach StopCardSession ist die eGK frei – VerifyPin erreicht wieder die Kartentypprüfung")
  void freiNachStop() {
    sessions.stop(sessions.start(CTX, egk));
    assertFalse(locks.locked(egk));
    assertError(ConnectorError.CARD_TYPE_UNSUPPORTED, () -> pins.verify(CTX, egk, "PIN.CH"));
    sessions.start(CTX, egk);
  }

  @Test
  @DisplayName("A_25860-01: nach Ablauf des APDU-Szenario-Timers ist die eGK frei")
  void freiNachTimer() {
    sessions.start(CTX, egk);
    clock.advance(Duration.ofSeconds(31));
    sessions.expire();
    assertFalse(locks.locked(egk));
    assertError(ConnectorError.CARD_TYPE_UNSUPPORTED, () -> pins.verify(CTX, egk, "PIN.CH"));
  }

  @Test
  @DisplayName(
      "TUC_KON_023: nach Ziehen ist die Reservierung aufgehoben, die neu gesteckte eGK ist frei")
  void freiNachZiehen() {
    sessions.start(CTX, egk);
    kt01.eject(1);
    assertFalse(locks.locked(egk));
    kt01.insert(1, RecordedTerminal.EGK_VALID);
    String neu = cards.card("KT-01", 1).orElseThrow().cardHandle();
    assertFalse(locks.locked(neu));
    sessions.start(CTX, neu);
  }

  @Test
  @DisplayName(
      "Nebenläufig: zwei SecureSendAPDU auf verschiedenen eGKs stehen gleichzeitig an der Karte")
  void parallelZweiSitzungen() throws Exception {
    String s1 = sessions.start(CTX, egk);
    String s2 = sessions.start(CTX, egk2);
    kt01.hold(1);
    kt02.hold(1);
    var first = CompletableFuture.supplyAsync(() -> sessions.secureSend(scenario(s1, 0)));
    var second = CompletableFuture.supplyAsync(() -> sessions.secureSend(scenario(s2, 0)));
    try {
      assertTrue(kt01.awaitHeld(1), "SecureSendAPDU auf KT-01 erreicht die Karte");
      assertTrue(
          kt02.awaitHeld(1), "SecureSendAPDU auf KT-02 erreicht die Karte, während KT-01 wartet");
    } finally {
      kt01.release(1);
      kt02.release(1);
    }
    assertEquals(1, first.get(5, TimeUnit.SECONDS).responseApdus().size());
    assertEquals(1, second.get(5, TimeUnit.SECONDS).responseApdus().size());
  }

  @Test
  @DisplayName(
      "Nebenläufig: während ein SecureSendAPDU an der eGK hängt, laufen Sitzungen und Operationen auf anderen "
          + "Karten und der Timer-Takt durch")
  void parallelAndereKarten() throws Exception {
    String s1 = sessions.start(CTX, egk);
    kt01.hold(1);
    var held = CompletableFuture.supplyAsync(() -> sessions.secureSend(scenario(s1, 0)));
    try {
      assertTrue(kt01.awaitHeld(1));
      assertTimeoutPreemptively(
          Duration.ofSeconds(2),
          () -> {
            String s2 = sessions.start(CTX, egk2);
            sessions.secureSend(scenario(s2, 0));
            sessions.stop(s2);
            sessions.expire();
            pins.verify(CTX, smcb, "PIN.SMC");
            external.sign(CTX, smcb, HASH);
            certificates.read(CTX, smcb, List.of("C.AUT"), null);
            assertTrue(sessions.locked(egk));
          });
      assertFalse(held.isDone());
    } finally {
      kt01.release(1);
    }
    assertEquals(1, held.get(5, TimeUnit.SECONDS).responseApdus().size());
    sessions.stop(s1);
  }

  private static void assertError(ConnectorError expected, Executable call) {
    assertEquals(expected, assertThrows(ConnectorException.class, call).error());
  }
}

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
import de.gematik.liana.kern.card.PinVerification.PinResult;
import de.gematik.liana.kern.card.PinVerification.PinStatus;
import de.gematik.liana.kern.card.PinVerification.Result;
import de.gematik.liana.kern.card.PinVerification.Status;
import de.gematik.liana.kern.error.ConnectorError;
import de.gematik.liana.kern.error.ConnectorException;
import de.gematik.liana.kern.terminal.PinCommand;
import de.gematik.liana.kern.terminal.PinDialog;
import de.gematik.liana.kern.terminal.PinMismatchException;
import de.gematik.liana.kern.terminal.TerminalRegistry;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

/**
 * VerifyPin (TIP1-A_4587), GetPinStatus (TIP1-A_4589), ChangePin (TIP1-A_4588), UnblockPin
 * (TIP1-A_4590), EnablePin and DisablePin (TIP1-A_5487) against egk-valid (slot 1), smcb-valid
 * (slot 2) and hba-valid (slot 3); the CT simulates the PIN entry.
 */
class PinVerificationTest {

  private static final Context CTX = new Context("M1", "CS1", "WP1", null);

  private final RecordedCards kt01 = new RecordedCards("KT-01");
  private final TerminalRegistry registry = new TerminalRegistry(List.of(kt01));
  private final CardList cards = new CardList(registry, Clock.systemUTC());
  private final Infomodel infomodel =
      new Infomodel(
          List.of("M1"),
          List.of("CS1"),
          List.of(new Infomodel.Workplace("WP1", List.of("M1"), List.of("CS1"), List.of("KT-01"))));
  private final AuthState authState = new AuthState();
  private final PinVerification pins =
      new PinVerification(new CardAccess(infomodel, cards, new CardLocks()), registry, authState);
  private final List<PinEvent> events = new ArrayList<>();
  private String egk;
  private String smcb;
  private String hba;

  @BeforeEach
  void stecken() {
    cards.start();
    kt01.insert(1, RecordedTerminal.EGK_VALID)
        .insert(2, RecordedTerminal.SMCB_VALID)
        .insert(3, RecordedTerminal.HBA_VALID);
    egk = cards.card("KT-01", 1).orElseThrow().cardHandle();
    smcb = cards.card("KT-01", 2).orElseThrow().cardHandle();
    hba = cards.card("KT-01", 3).orElseThrow().cardHandle();
    kt01.sent.get(2).clear();
    kt01.sent.get(3).clear();
    pins.addListener(events::add);
  }

  @Test
  @DisplayName(
      "TIP1-A_4587 / TUC_KON_012: PIN.CH des HBA wird am PIN-Pad eingegeben (VERIFY P2 01, PIN.CH im MF), "
          + "9000 → PinResult OK; Anzeigen nach TAB_KON_090 HBAx/PIN.CH")
  void hbaPinCh() {
    assertEquals(new Result(PinResult.OK, null), pins.verify(CTX, hba, "PIN.CH"));
    assertEquals(List.of("PIN-Pad VERIFY P2=01"), kt01.sent.get(3));
    assertEquals(
        new PinDialog(
            "Eingabe \u000BFreigabe-PIN \u000BHBA\u000FPIN.HBA:",
            "PIN \u000Berfolgreich \u000Bverifiziert!",
            "PIN \u000Bfalsch \u000Boder \u000Bgesperrt!"),
        kt01.pinDialog,
        "TIP1-A_4561-02: Terminalanzeigen nach TAB_KON_090 für HBAx/PIN.CH");
    assertTrue(
        authState.isVerified(CTX, hba, "PIN.CH"), "TUC_KON_012 7e: AUTHSTATE der Kartensitzung");
    assertFalse(authState.isVerified(CTX, hba, "PIN.SMC"));
    assertEquals(
        List.of(new AuthState.Verified(hba, "M1", "CS1", "PIN.CH")),
        authState.verified(),
        "LIANA-149: Admin-Sicht mit PinRef, ohne PIN-Wert");
    kt01.pinAnswer = "63C1";
    assertEquals(new Result(PinResult.REJECTED, 1), pins.verify(CTX, hba, "PIN.CH"));
    assertFalse(authState.isVerified(CTX, hba, "PIN.CH"), "Fehleingabe setzt AUTHSTATE zurück");
    assertEquals(List.of(), authState.verified());
  }

  @Test
  @DisplayName(
      "TIP1-A_4587 / TUC_KON_012: PIN.SMC wird am PIN-Pad des KT eingegeben (VERIFY P2 01), 9000 → PinResult OK")
  void ok() {
    assertEquals(new Result(PinResult.OK, null), pins.verify(CTX, smcb, "PIN.SMC"));
    assertEquals(List.of("PIN-Pad VERIFY P2=01"), kt01.sent.get(2));
    assertEquals(
        new PinDialog(
            "Eingabe \u000BPIN SMC-B \u000BSLOT:2\u000FPIN.SMC:",
            "PIN \u000Berfolgreich \u000Bverifiziert!",
            "PIN \u000Bfalsch \u000Boder \u000Bgesperrt!"),
        kt01.pinDialog,
        "TIP1-A_4561-02: Terminalanzeigen nach TAB_KON_090 für SMC-B/PIN.SMC");
    assertTrue(
        authState.isVerified(CTX, smcb, "PIN.SMC"), "TUC_KON_012 7e: AUTHSTATE der Kartensitzung");
    assertFalse(
        authState.isVerified(new Context("M1", "CS2", "WP1", null), smcb, "PIN.SMC"),
        "andere Kartensitzung (anderes Clientsystem)");
  }

  @Test
  @DisplayName(
      "TUC_KON_012 7c, TAB_KON_738 Schritt 5: 63C2 → REJECTED mit LeftTries 2, 63C0 → NOWBLOCKED, 6983 (schon "
          + "gesperrt, 4063) → WASBLOCKED, 6985 (Transport-PIN, 4065) → TRANSPORT_PIN, sonst ERROR")
  void ergebnisse() {
    pins.verify(CTX, smcb, "PIN.SMC");
    kt01.pinAnswer = "63C2";
    assertEquals(new Result(PinResult.REJECTED, 2), pins.verify(CTX, smcb, "PIN.SMC"));
    assertFalse(authState.isVerified(CTX, smcb, "PIN.SMC"), "Fehleingabe setzt AUTHSTATE zurück");
    kt01.pinAnswer = "63C0";
    assertEquals(new Result(PinResult.NOWBLOCKED, null), pins.verify(CTX, smcb, "PIN.SMC"));
    kt01.pinAnswer = "6983";
    assertEquals(new Result(PinResult.WASBLOCKED, null), pins.verify(CTX, smcb, "PIN.SMC"));
    assertFalse(authState.isVerified(CTX, smcb, "PIN.SMC"));
    kt01.pinAnswer = "6985";
    assertEquals(new Result(PinResult.TRANSPORT_PIN, null), pins.verify(CTX, smcb, "PIN.SMC"));
    kt01.pinAnswer = "6F00";
    assertEquals(new Result(PinResult.ERROR, null), pins.verify(CTX, smcb, "PIN.SMC"));
  }

  @Test
  @DisplayName(
      "TUC_KON_012 Fehlerfälle (7), TAB_KON_089: 6400 (Timeout am PIN-Pad, SICCT §5.19.6) → 4043, 6401 "
          + "(Abbruchtaste) → 4049, (7b) 64A1 (Karte während der Eingabe gezogen) → 4008; erst nach 7e, AUTHSTATE ist "
          + "zurückgesetzt")
  void fehlerzustaende() {
    for (var c :
        List.of(
            List.of("6400", ConnectorError.PIN_TIMEOUT),
            List.of("6401", ConnectorError.PIN_CANCELLED),
            List.of("64A1", ConnectorError.CARD_NOT_INSERTED))) {
      kt01.pinAnswer = "9000";
      pins.verify(CTX, smcb, "PIN.SMC");
      kt01.pinAnswer = (String) c.get(0);
      assertError((ConnectorError) c.get(1), () -> pins.verify(CTX, smcb, "PIN.SMC"));
      assertFalse(
          authState.isVerified(CTX, smcb, "PIN.SMC"),
          c.get(0) + ": TUC_KON_012 7e vor dem Abbruch");
    }
    assertEquals(4043, ConnectorError.PIN_TIMEOUT.code());
    assertEquals(4049, ConnectorError.PIN_CANCELLED.code());
    assertEquals(4008, ConnectorError.CARD_NOT_INSERTED.code());
  }

  @Test
  @DisplayName(
      "TAB_KON_047: eGK → 4209; PinTyp PIN.CH auf SM-B, PIN.SMC auf HBA oder leer → 4000; unbekanntes Handle "
          + "→ 4008")
  void fehler() {
    var e = assertThrows(ConnectorException.class, () -> pins.verify(CTX, egk, "PIN.SMC"));
    assertEquals(ConnectorError.CARD_TYPE_UNSUPPORTED, e.error());
    assertEquals("Kartentyp EGK wird durch diese Operation nicht unterstützt.", e.text());
    assertError(ConnectorError.SYNTAX, () -> pins.verify(CTX, smcb, "PIN.CH"));
    assertError(ConnectorError.SYNTAX, () -> pins.verify(CTX, hba, "PIN.SMC"));
    assertError(ConnectorError.SYNTAX, () -> pins.verify(CTX, smcb, ""));
    assertError(ConnectorError.CARD_NOT_INSERTED, () -> pins.verify(CTX, "SMC-B-99", "PIN.SMC"));
  }

  @Test
  @DisplayName(
      "TUC_KON_012 Schritte 7a und 7d: VerifyPin meldet CARD/PIN/VERIFY_STARTED vor der PIN-Eingabe und "
          + "VERIFY_FINISHED mit dem PinResult, PinRef = PinTyp, PinInputCtID = CtID der Karte")
  void ereignisse() {
    kt01.pinAnswer = "63C2";
    pins.verify(CTX, smcb, "PIN.SMC");
    assertEquals(
        List.of(PinEvent.Topic.VERIFY_STARTED, PinEvent.Topic.VERIFY_FINISHED),
        events.stream().map(PinEvent::topic).toList());
    PinEvent finished = events.get(1);
    assertEquals(smcb, finished.card().cardHandle());
    assertEquals("PIN.SMC", finished.pinRef());
    assertEquals("KT-01", finished.pinInputCtId());
    assertEquals(PinResult.REJECTED, finished.result());
    assertEquals(null, events.get(0).result());
  }

  @Test
  @DisplayName(
      "TUC_KON_012 Fehlerfälle: Schritt 7 läuft ganz durch – Abbruchtaste (6401) liefert VERIFY_FINISHED mit "
          + "Result ERROR vor 4049; Fehler vor Schritt 7 (4209, 4000) melden nichts")
  void ereignisseImFehlerfall() {
    kt01.pinAnswer = "6401";
    assertError(ConnectorError.PIN_CANCELLED, () -> pins.verify(CTX, smcb, "PIN.SMC"));
    assertEquals(
        List.of(PinEvent.Topic.VERIFY_STARTED, PinEvent.Topic.VERIFY_FINISHED),
        events.stream().map(PinEvent::topic).toList());
    assertEquals(PinResult.ERROR, events.get(1).result());
    events.clear();
    assertError(ConnectorError.CARD_TYPE_UNSUPPORTED, () -> pins.verify(CTX, egk, "PIN.SMC"));
    assertError(ConnectorError.SYNTAX, () -> pins.verify(CTX, smcb, "PIN.CH"));
    assertEquals(List.of(), events);
  }

  @Test
  @DisplayName(
      "TIP1-A_4589 / TUC_KON_022 3b: GET PIN STATUS (80 20 00 01) an die SMC-B, 63C3 → VERIFIABLE mit "
          + "LeftTries 3; nach VerifyPin OK steht PIN.SMC in AUTHSTATE → VERIFIED ohne Kartenzugriff (3a)")
  void pinStatusSmcb() {
    kt01.answer(2, "80200001", "63C3");
    assertEquals(new Status(PinStatus.VERIFIABLE, 3), pins.status(CTX, smcb, "PIN.SMC"));
    assertEquals(List.of("80200001"), kt01.sent.get(2));
    pins.verify(CTX, smcb, "PIN.SMC");
    kt01.sent.get(2).clear();
    assertEquals(new Status(PinStatus.VERIFIED, null), pins.status(CTX, smcb, "PIN.SMC"));
    assertEquals(List.of(), kt01.sent.get(2), "TUC_KON_022 3a: kein GET PIN STATUS");
  }

  @Test
  @DisplayName(
      "TIP1-A_4589 / TUC_KON_022 3b am HBA: PIN.CH mit GET PIN STATUS P2 01, 63C2 → VERIFIABLE mit "
          + "LeftTries 2")
  void pinStatusHba() {
    kt01.answer(3, "80200001", "63C2");
    assertEquals(new Status(PinStatus.VERIFIABLE, 2), pins.status(CTX, hba, "PIN.CH"));
    assertEquals(List.of("80200001"), kt01.sent.get(3));
  }

  @Test
  @DisplayName(
      "TUC_KON_022 3b a–f: 9000 → VERIFIABLE ohne LeftTries, 62C1 → TRANSPORT_PIN, 62C7 → EMPTY_PIN, "
          + "63C0 → BLOCKED mit LeftTries 0, 62D0 → DISABLED")
  void pinStatusAbbildung() {
    assertEquals(
        new Status(PinStatus.VERIFIABLE, null), PinVerification.status("9000").orElseThrow());
    assertEquals(
        new Status(PinStatus.TRANSPORT_PIN, null), PinVerification.status("62C1").orElseThrow());
    assertEquals(
        new Status(PinStatus.EMPTY_PIN, null), PinVerification.status("62C7").orElseThrow());
    assertEquals(new Status(PinStatus.BLOCKED, 0), PinVerification.status("63C0").orElseThrow());
    assertEquals(
        new Status(PinStatus.DISABLED, null), PinVerification.status("62D0").orElseThrow());
    assertTrue(PinVerification.status("6A88").isEmpty());
  }

  @Test
  @DisplayName(
      "TAB_KON_549 / TAB_KON_091: Karte kennt die PIN-Referenz nicht (6A88) → 4072, andere Fehlerantwort "
          + "(TUC_KON_022 3b g) → 4001; eGK → 4209; PIN.CH auf SM-B, leerer PinTyp → 4000; unbekanntes Handle → 4008")
  void pinStatusFehler() {
    kt01.answer(2, "80200001", "6A88");
    assertError(ConnectorError.INVALID_PIN_REF, () -> pins.status(CTX, smcb, "PIN.SMC"));
    kt01.answer(2, "80200001", "6F00");
    assertError(ConnectorError.INTERNAL, () -> pins.status(CTX, smcb, "PIN.SMC"));
    assertError(ConnectorError.SYNTAX, () -> pins.status(CTX, egk, "PIN.SMC"));
    assertError(ConnectorError.SYNTAX, () -> pins.status(CTX, smcb, "PIN.CH"));
    assertError(ConnectorError.SYNTAX, () -> pins.status(CTX, smcb, ""));
    assertError(ConnectorError.CARD_NOT_INSERTED, () -> pins.status(CTX, "SMC-B-99", "PIN.SMC"));
    assertEquals(4072, ConnectorError.INVALID_PIN_REF.code());
    assertEquals(4001, ConnectorError.INTERNAL.code());
  }

  private static void assertError(ConnectorError expected, Executable call) {
    assertEquals(expected, assertThrows(ConnectorException.class, call).error());
  }

  private List<String> topics() {
    return events.stream()
        .map(e -> e.topic().topic() + (e.result() == null ? "" : " " + e.result()))
        .toList();
  }

  @Test
  @DisplayName(
      "TIP1-A_4589 / TUC_KON_022 für die eGK-PINs (TAB_KON_051): MRPIN.DPE mit GET PIN STATUS P2 04 → 62D0 "
          + "DISABLED, PIN.AMTS_REP P2 0D; VerifyPin auf der eGK bleibt 4209 (TAB_KON_047: DARF NICHT)")
  void egkPinStatus() {
    kt01.answer(1, "80200004", "62D0");
    kt01.answer(1, "8020000D", "63C3");
    assertEquals(new Status(PinStatus.DISABLED, null), pins.status(CTX, egk, "MRPIN.DPE"));
    assertEquals(new Status(PinStatus.VERIFIABLE, 3), pins.status(CTX, egk, "PIN.AMTS_REP"));
    assertError(ConnectorError.CARD_TYPE_UNSUPPORTED, () -> pins.verify(CTX, egk, "PIN.CH"));
  }

  @Test
  @DisplayName(
      "TIP1-A_4588 / TUC_KON_019: ChangePin PIN.SMC – MODIFY VERIFICATION DATA mit CHANGE REFERENCE DATA P1 00 "
          + "(alte PIN, neue PIN, Wiederholung, Anzeigen nach TAB_KON_090), 9000 → OK; CARD/PIN/CHANGE_STARTED und "
          + "CHANGE_FINISHED mit Result")
  void changeSmcb() {
    kt01.answer(2, "80200001", "63C3");
    assertEquals(new Result(PinResult.OK, null), pins.change(CTX, smcb, "PIN.SMC"));
    PinCommand command = kt01.pinCommands.getLast();
    assertEquals("00240001", java.util.HexFormat.of().withUpperCase().formatHex(command.header()));
    assertEquals(PinCommand.Mode.OLD_NEW, command.mode());
    assertEquals(
        List.of(
            "Eingabe \u000BPIN SMC-B \u000BSLOT:2\u000FPIN.SMC:",
            "Eingabe \u000Bneue \u000BPIN SMC-B \u000BSLOT:2 \u000B(6-8 Ziffern)\u000FPIN.SMC:",
            "Eingabe \u000BPIN.SMC \u000BSLOT:2 \u000Bwiederholen!\u000FPIN.SMC:"),
        command.prompts());
    assertEquals("PIN \u000Berfolgreich \u000Bgeändert!", command.success());
    assertEquals(List.of("CARD/PIN/CHANGE_STARTED", "CARD/PIN/CHANGE_FINISHED OK"), topics());
  }

  @Test
  @DisplayName(
      "TUC_KON_019 Schritt 4 und 7b: PIN.AMTS_REP der eGK – erst TUC_KON_012 mit PIN.CH (VERIFY P2 01), dann "
          + "CHANGE REFERENCE DATA P1 01 nur mit neuer PIN und Wiederholung (Vertreter-PIN); PIN.CH falsch → REJECTED "
          + "ohne Änderung")
  void changeAmtsRep() {
    kt01.answer(1, "8020000D", "63C3");
    assertEquals(new Result(PinResult.OK, null), pins.change(CTX, egk, "PIN.AMTS_REP"));
    assertEquals(
        List.of("PIN-Pad VERIFY P2=01", "PIN-Pad NEW 0024010D"),
        kt01.sent.get(1).stream().filter(c -> c.startsWith("PIN-Pad")).toList());
    assertEquals(
        List.of(
            "Eingabe \u000Bneue \u000BVertreter-PIN \u000B(6-8 Ziffern)\u000FVertr-PIN:",
            "Eingabe \u000Bneue \u000BVertreter-PIN \u000Bwiederholen!\u000FVertr-PIN:"),
        kt01.pinCommands.getLast().prompts());
    assertEquals(
        List.of(
            "CARD/PIN/VERIFY_STARTED",
            "CARD/PIN/VERIFY_FINISHED OK",
            "CARD/PIN/CHANGE_STARTED",
            "CARD/PIN/CHANGE_FINISHED OK"),
        topics());

    kt01.pinCommands.clear();
    kt01.pinAnswer = "63C2";
    assertEquals(new Result(PinResult.REJECTED, 2), pins.change(CTX, egk, "PIN.AMTS_REP"));
    assertEquals(1, kt01.pinCommands.size(), "keine Änderung nach falscher PIN.CH");
  }

  @Test
  @DisplayName(
      "TUC_KON_019 Schritt 3 und 7b: Transport-PIN (62C1) als alte PIN mit Anzeige T-PIN.SMC, Leer-PIN (62C7) "
          + "mit CHANGE REFERENCE DATA P1 01 nur neue PIN; gesperrt (63C0) → WASBLOCKED ohne PIN-Eingabe (TAB_KON_546 "
          + "Schritt 5); falsche alte PIN → REJECTED; ungleiche Wiederholung am KT → 4067")
  void changeVarianten() {
    kt01.answer(2, "80200001", "62C1");
    pins.change(CTX, smcb, "PIN.SMC");
    assertEquals(
        "Eingabe \u000BTransport-\u000BPIN SMC-B \u000BSLOT:2\u000FT-PIN.SMC:",
        kt01.pinCommands.getLast().prompts().getFirst());
    kt01.answer(2, "80200001", "62C7");
    pins.change(CTX, smcb, "PIN.SMC");
    assertEquals("NEW 00240101", kt01.pinCommands.getLast().toString());

    kt01.answer(2, "80200001", "63C0");
    kt01.pinCommands.clear();
    assertEquals(new Result(PinResult.WASBLOCKED, null), pins.change(CTX, smcb, "PIN.SMC"));
    assertTrue(kt01.pinCommands.isEmpty());

    kt01.answer(2, "80200001", "63C3");
    kt01.pinAnswer = "63C2";
    assertEquals(new Result(PinResult.REJECTED, 2), pins.change(CTX, smcb, "PIN.SMC"));
    kt01.pinAnswers.add(new PinMismatchException("PINs nicht identisch"));
    assertError(ConnectorError.PIN_MISMATCH, () -> pins.change(CTX, smcb, "PIN.SMC"));
    assertEquals(4067, ConnectorError.PIN_MISMATCH.code());
  }

  @Test
  @DisplayName(
      "LIANA-127 TUC_KON_019/021 (7b) am eHealth-KT: SICCT MODIFY VERIFICATION DATA (SICCT-Errata 1.0 "
          + "§5.20.6) 6402 ungleiche Wiederholung → 4067, 6400 → 4043, 6401 → 4049, 64A1 → 4008; CHANGE_FINISHED "
          + "mit ERROR vor dem Fehler")
  void modifyVerificationDataStatus() {
    for (var c :
        List.of(
            List.of("6402", ConnectorError.PIN_MISMATCH),
            List.of("6400", ConnectorError.PIN_TIMEOUT),
            List.of("6401", ConnectorError.PIN_CANCELLED),
            List.of("64A1", ConnectorError.CARD_NOT_INSERTED))) {
      kt01.answer(2, "80200001", "63C3");
      kt01.pinAnswer = (String) c.get(0);
      assertError((ConnectorError) c.get(1), () -> pins.change(CTX, smcb, "PIN.SMC"));
      assertEquals("CARD/PIN/CHANGE_FINISHED ERROR", topics().getLast(), (String) c.get(0));
      kt01.answer(2, "80200001", "63C0");
      assertError((ConnectorError) c.get(1), () -> pins.unblock(CTX, smcb, "PIN.SMC", true));
    }
  }

  @Test
  @DisplayName(
      "TIP1-A_4590 / TUC_KON_021: UnblockPin – PIN nicht gesperrt → OK ohne PIN-Eingabe (Schritt 3); gesperrt: "
          + "RESET RETRY COUNTER P1 01 nur PUK bzw. mit SetNewPin P1 00 PUK, neue PIN, Wiederholung; PIN.AMTS_REP nach "
          + "PIN.CH mit P1 02; falsche PUK → REJECTED, gesperrte PUK (6983, 4064) → WASBLOCKED; CHANGE_* auch hier")
  void unblock() {
    kt01.answer(2, "80200001", "63C3");
    assertEquals(new Result(PinResult.OK, null), pins.unblock(CTX, smcb, "PIN.SMC", false));
    assertTrue(kt01.pinCommands.isEmpty());

    kt01.answer(2, "80200001", "63C0");
    assertEquals(new Result(PinResult.OK, null), pins.unblock(CTX, smcb, "PIN.SMC", false));
    assertEquals("ONE 002C0101", kt01.pinCommands.getLast().toString());
    assertEquals(
        List.of("Eingabe \u000BPUK SMC-B \u000BSLOT:2\u000FPUK.SMC:"),
        kt01.pinCommands.getLast().prompts());
    assertEquals("PIN \u000Berfolgreich \u000Bentsperrt!", kt01.pinCommands.getLast().success());
    pins.unblock(CTX, smcb, "PIN.SMC", true);
    assertEquals("OLD_NEW 002C0001", kt01.pinCommands.getLast().toString());

    kt01.answer(1, "8020000D", "63C0");
    pins.unblock(CTX, egk, "PIN.AMTS_REP", false);
    assertEquals("NEW 002C020D", kt01.pinCommands.getLast().toString());

    kt01.pinAnswer = "63C9";
    assertEquals(new Result(PinResult.REJECTED, 9), pins.unblock(CTX, smcb, "PIN.SMC", false));
    kt01.pinAnswer = "6983";
    assertEquals(new Result(PinResult.WASBLOCKED, null), pins.unblock(CTX, smcb, "PIN.SMC", false));
    assertTrue(topics().contains("CARD/PIN/CHANGE_FINISHED WASBLOCKED"));
  }

  @Test
  @DisplayName(
      "TIP1-A_5487 / TUC_KON_027: DisablePin MRPIN.DPE – PERFORM VERIFICATION mit DISABLE VERIFICATION "
          + "REQUIREMENT P1 00 P2 04, Anzeige „PIN-Schutz Pers.Erklärungen abschalten“ (TAB_KON_090/838), "
          + "CARD/PIN/DISABLE_*; EnablePin MRPIN.AMTS mit ENABLE P2 0C und ENABLE_*")
  void protect() {
    assertEquals(new Result(PinResult.OK, null), pins.protect(CTX, egk, "MRPIN.DPE", false));
    assertEquals("ONE 00260004", kt01.pinCommands.getLast().toString());
    assertEquals(
        List.of("PIN-Schutz \u000BPers.Erklärungen \u000Babschalten\u000FPIN.eGK:"),
        kt01.pinCommands.getLast().prompts());
    assertEquals(new Result(PinResult.OK, null), pins.protect(CTX, egk, "MRPIN.AMTS", true));
    assertEquals("ONE 0028000C", kt01.pinCommands.getLast().toString());
    assertEquals(
        List.of(
            "CARD/PIN/DISABLE_STARTED",
            "CARD/PIN/DISABLE_FINISHED",
            "CARD/PIN/ENABLE_STARTED",
            "CARD/PIN/ENABLE_FINISHED"),
        topics());
  }

  @Test
  @DisplayName(
      "TUC_KON_027 Fehlerfälle: falsche PIN → REJECTED, gesperrt → WASBLOCKED; 6982 (PIN nicht abschaltbar) "
          + "→ 4085, 6A88 (MRPIN.AMTS auf eGK G2.0) → 4072; SM-B → 4209, MRPIN.OSE → 4000")
  void protectFehler() {
    kt01.pinAnswer = "63C1";
    assertEquals(new Result(PinResult.REJECTED, 1), pins.protect(CTX, egk, "MRPIN.NFD", false));
    kt01.pinAnswer = "6983";
    assertEquals(
        new Result(PinResult.WASBLOCKED, null), pins.protect(CTX, egk, "MRPIN.NFD", false));
    kt01.pinAnswer = "6982";
    assertError(ConnectorError.ACCESS_CONDITIONS, () -> pins.protect(CTX, egk, "MRPIN.GDD", false));
    kt01.pinAnswer = "6A88";
    assertError(ConnectorError.INVALID_PIN_REF, () -> pins.protect(CTX, egk, "MRPIN.AMTS", true));
    assertError(
        ConnectorError.CARD_TYPE_UNSUPPORTED, () -> pins.protect(CTX, smcb, "PIN.SMC", true));
    assertError(ConnectorError.SYNTAX, () -> pins.protect(CTX, egk, "MRPIN.OSE", true));
    assertEquals(4085, ConnectorError.ACCESS_CONDITIONS.code());
  }
}

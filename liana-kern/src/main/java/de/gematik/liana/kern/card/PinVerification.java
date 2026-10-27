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
import de.gematik.liana.kern.terminal.PinCommand;
import de.gematik.liana.kern.terminal.PinDialog;
import de.gematik.liana.kern.terminal.SecureChannel;
import de.gematik.liana.kern.terminal.TerminalRegistry;
import java.io.IOException;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeSet;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
 * PIN operations of the CardService on the card terminal's PIN pad ({@link
 * CardTerminal#pinCommand}), with the terminal displays from TAB_KON_090 (TIP1-A_4561-02); the
 * status word of the card or of the CT yields the PinResult.
 *
 * <ul>
 *   <li>VerifyPin (TIP1-A_4587, TAB_KON_047/738) with TUC_KON_012 „PIN verifizieren“,
 *       verificationType Mandatorisch, events CARD/PIN/VERIFY_STARTED and VERIFY_FINISHED;
 *   <li>GetPinStatus (TIP1-A_4589, TAB_KON_051/548) with TUC_KON_022 „Liefere PIN-Status“
 *       (TIP1-A_4570);
 *   <li>ChangePin (TIP1-A_4588, TAB_KON_049/546) with TUC_KON_019 „PIN ändern“ and UnblockPin
 *       (TIP1-A_4590, TAB_KON_053/550) with TUC_KON_021 „PIN entsperren“ (TIP1-A_4569-02), both
 *       with CARD/PIN/CHANGE_*;
 *   <li>EnablePin and DisablePin (TIP1-A_5487, TAB_KON_242/243, TAB_KON_245/246) with TUC_KON_027
 *       „PIN-Schutz ein-/ausschalten“ (TIP1-A_5486), events ENABLE_* or DISABLE_*.
 * </ul>
 *
 * <p>PIN references ({@link #reference}): SM-B PIN.SMC, HBAx PIN.CH, eGK all PINs from the MF
 * (gemSpec_eGK_ObjSys_G2.1 5.3.9). PIN.QES of the HBA (DF.QES) is checked only by SignDocument
 * ({@link #verifyQes}); VerifyPin does not know it until gemSpec_HBA_ObjSys is available; likewise
 * MRPIN.DPE_READ of the eGK G2.0. Whether an eGK is G2.0 or G2.1 is decided by the card: MRPIN.AMTS
 * is missing on G2.0, it answers 6A88 → 4072 (TUC_KON_027 (4)). There is no remote PIN entry: the
 * PIN is entered at the card's CT (PinInputCtID = CtID); card-to-card for eGK G1+ is omitted, LIANA
 * only knows eGK from G2 (TIP1-A_4988-03).
 */
public final class PinVerification {

  /** PinResult from CardServiceCommon. */
  public enum PinResult {
    OK,
    REJECTED,
    ERROR,
    WASBLOCKED,
    NOWBLOCKED,
    TRANSPORT_PIN
  }

  /**
   * Result of VerifyPin, ChangePin, UnblockPin, EnablePin and DisablePin; {@code leftTries} only
   * for REJECTED.
   */
  public record Result(PinResult pinResult, Integer leftTries) {}

  /**
   * PinStatusEnum from CardService v8.2.1 (TAB_KON_051; TUC_KON_022 writes VERIFYABLE, the schema
   * VERIFIABLE).
   */
  public enum PinStatus {
    VERIFIED,
    TRANSPORT_PIN,
    EMPTY_PIN,
    BLOCKED,
    VERIFIABLE,
    DISABLED
  }

  /**
   * Result of GetPinStatus; {@code leftTries} for VERIFIABLE with 63Cx and for BLOCKED (TUC_KON_022
   * 3b d, e).
   */
  public record Status(PinStatus pinStatus, Integer leftTries) {}

  /** The operations with their allowed PinTyp (TAB_KON_047, 049, 051, 053, 242, 245). */
  enum Operation {
    VERIFY,
    STATUS,
    CHANGE,
    UNBLOCK,
    PROTECT
  }

  /** eGK PINs, all global in the MF (gemSpec_eGK_ObjSys_G2.1 5.3.9): P2 = pwdIdentifier. */
  private static final Map<String, Integer> EGK =
      Map.of(
          "PIN.CH",
          0x01,
          "MRPIN.NFD",
          0x03,
          "MRPIN.DPE",
          0x04,
          "MRPIN.GDD",
          0x05,
          "MRPIN.NFD_READ",
          0x07,
          "MRPIN.OSE",
          0x09,
          "MRPIN.AMTS",
          0x0C,
          "PIN.AMTS_REP",
          0x0D);

  /**
   * TAB_KON_242/245: enabling/disabling PIN protection only for these MRPINs (MRPIN.AMTS from
   * G2.1).
   */
  private static final Map<String, Integer> PROTECTABLE =
      Map.of("MRPIN.NFD", 0x03, "MRPIN.DPE", 0x04, "MRPIN.GDD", 0x05, "MRPIN.AMTS", 0x0C);

  /** TAB_KON_838: ANW per MRPIN in the displays of TUC_KON_027. */
  private static final Map<String, String> ANW =
      Map.of(
          "MRPIN.NFD",
          "Notfalldaten",
          "MRPIN.DPE",
          "Pers.Erklärungen",
          "MRPIN.AMTS",
          "Medikationsdaten",
          "MRPIN.GDD",
          "PIN GDD");

  /**
   * PIN.CH of the eGK and the HBA, PIN.SMC of the SM-B: pwdIdentifier '01' in the MF (images,
   * gemSpec_SMC-B_ObjSys 5.3.9).
   */
  private static final int PIN_01 = 0x01;

  /**
   * PIN.QES of the HBA: pwdIdentifier '01' in DF.QES, DF-specific '81' (images, gemSpec_HBA_ObjSys
   * is missing).
   */
  private static final int PIN_QES = 0x81;

  private static final HexFormat HEX = HexFormat.of().withUpperCase();

  private final CardAccess access;
  private final TerminalRegistry terminals;
  private final AuthState authState;
  private final List<Consumer<PinEvent>> listeners = new CopyOnWriteArrayList<>();

  public PinVerification(CardAccess access, TerminalRegistry terminals, AuthState authState) {
    this.access = access;
    this.terminals = terminals;
    this.authState = authState;
  }

  /** {@code listener} receives from now on the PIN events from TUC_KON_012, 019, 021 and 027. */
  public void addListener(Consumer<PinEvent> listener) {
    listeners.add(listener);
  }

  /** TAB_KON_738. */
  public Result verify(Context context, String cardHandle, String pinTyp) {
    requirePinTyp(pinTyp);
    // TAB_KON_738 steps 2 and 3: TUC_KON_000, TUC_KON_026 (4093 while a card session is running,
    // A_25895)
    CardObject card = access.cardSession(context, cardHandle);
    int reference = reference(card, pinTyp, Operation.VERIFY);
    return tucKon012(context, card, pinTyp, reference);
  }

  /**
   * TUC_KON_012 for PIN.QES from TUC_KON_150 step 6 (verificationType Mandatorisch, step 3: without
   * looking at AUTHSTATE), display with the Jobnummer. The caller has selected DF.QES and reserves
   * the card; a wrong entry is not an error (REJECTED), the card then refuses the signature.
   */
  public Result verifyQes(Context context, CardObject card, String jobNumber) {
    return verifyQes(context, card, jobNumber, null);
  }

  /**
   * Like {@link #verifyQes(Context, CardObject, String)}, with {@code channel} in the remote PIN
   * procedure (TIP1-A_5012, PIN.QES in SE #2, LIANA-112.13); {@code null} without trusted channel.
   */
  public Result verifyQes(
      Context context, CardObject card, String jobNumber, SecureChannel channel) {
    PinCommand command = PinCommand.verify(PIN_QES, PinDialog.pinQes(jobNumber));
    return tucKon012(
        context, card, "PIN.QES", channel == null ? command : command.withChannel(channel));
  }

  /**
   * TUC_KON_012 for PIN.QES from TUC_KON_171 step 4 (enable Komfortsignatur, Mandatorisch), display
   * „Komfortsignatur aktivieren“ (TAB_KON_090); otherwise like {@link #verifyQes}, with {@code
   * channel} in SE #2.
   */
  public Result verifyComfort(Context context, CardObject card, SecureChannel channel) {
    PinCommand command = PinCommand.verify(PIN_QES, PinDialog.comfortQes());
    return tucKon012(
        context, card, "PIN.QES", channel == null ? command : command.withChannel(channel));
  }

  /**
   * TUC_KON_012 step 7 (verificationType Mandatorisch): atomic with eventing and recording of the
   * result; error states abort only after 7e.
   */
  private Result tucKon012(Context context, CardObject card, String pinTyp, int reference) {
    return tucKon012(context, card, pinTyp, PinCommand.verify(reference, verifyDialog(card)));
  }

  private Result tucKon012(Context context, CardObject card, String pinTyp, PinCommand command) {
    publish(new PinEvent(PinEvent.Topic.VERIFY_STARTED, card, pinTyp, card.ctId(), null));
    Outcome outcome = run(card, command);
    publish(
        new PinEvent(
            PinEvent.Topic.VERIFY_FINISHED,
            card,
            pinTyp,
            card.ctId(),
            outcome.result().pinResult()));
    // TUC_KON_012 7e
    if (outcome.result().pinResult() == PinResult.OK) {
      authState.verified(context, card.cardHandle(), pinTyp);
    } else {
      authState.notVerified(context, card.cardHandle(), pinTyp);
    }
    outcome.fail(card, "PIN-Eingabe", Map.of());
    return outcome.result();
  }

  /**
   * TAB_KON_548: checkArguments, TUC_KON_000, TUC_KON_026, then TUC_KON_022. If PinTyp is verified
   * in CARDSESSION.AUTHSTATE, the status is VERIFIED without card access (3a), otherwise GET PIN
   * STATUS decides (3b).
   */
  public Status status(Context context, String cardHandle, String pinTyp) {
    requirePinTyp(pinTyp);
    CardObject card = access.cardSession(context, cardHandle);
    return tucKon022(context, card, pinTyp, reference(card, pinTyp, Operation.STATUS));
  }

  private Status tucKon022(Context context, CardObject card, String pinTyp, int reference) {
    if (authState.isVerified(context, card.cardHandle(), pinTyp)) {
      return new Status(PinStatus.VERIFIED, null);
    }
    byte[] response;
    try {
      response = terminal(card).transmit(card.slotNo(), getPinStatus(reference));
    } catch (IOException e) {
      throw TerminalErrors.of(card, "GET PIN STATUS", e);
    }
    String statusWord = HEX.formatHex(response);
    return status(statusWord)
        .orElseThrow(
            () ->
                ("6A88".equals(statusWord)
                        ? ConnectorError.INVALID_PIN_REF
                        : ConnectorError.INTERNAL)
                    .exception(
                        card.ctId()
                            + "/"
                            + card.slotNo()
                            + " GET PIN STATUS "
                            + pinTyp
                            + " → "
                            + statusWord));
  }

  /**
   * TAB_KON_546 with TUC_KON_019: step 3 blocked PIN → WASBLOCKED (4063, TAB_KON_546 step 5); step
   * 4 for PIN.AMTS_REP first TUC_KON_012 with PIN.CH. Step 7b: CHANGE REFERENCE DATA P1 '00' with
   * old secret (PIN or transport PIN) and new PIN, for an empty PIN and PIN.AMTS_REP P1 '01' with
   * the new PIN only; 7e: REJECTED and BLOCKED remove PinRef from AUTHSTATE.
   */
  public Result change(Context context, String cardHandle, String pinTyp) {
    requirePinTyp(pinTyp);
    CardObject card = access.cardSession(context, cardHandle);
    int reference = reference(card, pinTyp, Operation.CHANGE);
    PinStatus status = tucKon022(context, card, pinTyp, reference).pinStatus();
    if (status == PinStatus.BLOCKED) {
      return new Result(PinResult.WASBLOCKED, null);
    }
    boolean amtsRep = pinTyp.equals("PIN.AMTS_REP");
    if (amtsRep) {
      Result pinCh = tucKon012(context, card, "PIN.CH", PIN_01);
      if (pinCh.pinResult() != PinResult.OK) {
        return pinCh;
      }
    }
    PinCommand command =
        amtsRep || status == PinStatus.EMPTY_PIN
            ? newPin(card, pinTyp, 0x24, 0x01, reference)
            : oldNew(
                card,
                pinTyp,
                0x24,
                0x00,
                reference,
                status == PinStatus.TRANSPORT_PIN ? transportPrompt(card) : changePrompt(card),
                PinCommand.CHANGED,
                PinDialog.WRONG);
    Result result = changeOrUnblock(card, pinTyp, command, "PIN ändern");
    if (result.pinResult() == PinResult.REJECTED || result.pinResult() == PinResult.NOWBLOCKED) {
      authState.notVerified(context, card.cardHandle(), pinTyp);
    }
    return result;
  }

  /**
   * TAB_KON_550 with TUC_KON_021: step 3 PIN neither blocked nor transport-protected → OK without
   * PIN entry; step 4 for PIN.AMTS_REP setNewPin and TUC_KON_012 with PIN.CH, then RESET RETRY
   * COUNTER P1 '02' (new PIN only). Otherwise step 7b RESET RETRY COUNTER P1 '00' (PUK and new PIN,
   * MODIFY VERIFICATION DATA) or P1 '01' (PUK only, PERFORM VERIFICATION). Blocked PUK (6983,
   * TUC_KON_021 4064) → WASBLOCKED (TAB_KON_550 step 5).
   */
  public Result unblock(Context context, String cardHandle, String pinTyp, boolean setNewPin) {
    requirePinTyp(pinTyp);
    CardObject card = access.cardSession(context, cardHandle);
    int reference = reference(card, pinTyp, Operation.UNBLOCK);
    PinStatus status = tucKon022(context, card, pinTyp, reference).pinStatus();
    if (status != PinStatus.BLOCKED && status != PinStatus.TRANSPORT_PIN) {
      return new Result(PinResult.OK, null);
    }
    PinCommand command;
    if (pinTyp.equals("PIN.AMTS_REP")) {
      Result pinCh = tucKon012(context, card, "PIN.CH", PIN_01);
      if (pinCh.pinResult() != PinResult.OK) {
        return pinCh;
      }
      command = newPin(card, pinTyp, 0x2C, 0x02, reference);
    } else if (setNewPin) {
      command =
          oldNew(
              card,
              pinTyp,
              0x2C,
              0x00,
              reference,
              pukPrompt(card),
              PinCommand.UNBLOCKED,
              PinCommand.WRONG_PUK);
    } else {
      command =
          new PinCommand(
              new byte[] {0x00, 0x2C, 0x01, (byte) reference},
              PinCommand.Mode.ONE,
              List.of(pukPrompt(card)),
              PinCommand.UNBLOCKED,
              PinCommand.WRONG_PUK,
              PinCommand.MISMATCH_TEXT);
    }
    return changeOrUnblock(card, pinTyp, command, "PIN entsperren");
  }

  /**
   * TUC_KON_019/021 step 7: atomic with CARD/PIN/CHANGE_STARTED and CHANGE_FINISHED (both TUCs).
   */
  private Result changeOrUnblock(CardObject card, String pinTyp, PinCommand command, String what) {
    publish(new PinEvent(PinEvent.Topic.CHANGE_STARTED, card, pinTyp, card.ctId(), null));
    Outcome outcome = run(card, command);
    publish(
        new PinEvent(
            PinEvent.Topic.CHANGE_FINISHED,
            card,
            pinTyp,
            card.ctId(),
            outcome.result().pinResult()));
    outcome.fail(card, what, Map.of());
    return outcome.result();
  }

  /**
   * TAB_KON_243/246 with TUC_KON_027: eGK only (otherwise 4209) and MRPIN.NFD, DPE, GDD, AMTS
   * (otherwise 4000); step 5b PERFORM VERIFICATION with ENABLE or DISABLE VERIFICATION REQUIREMENT,
   * P1 '00' (entry of PIN.CH), display with ANW per TAB_KON_838. Errors (5): 6A88 → 4072, 6982 (PIN
   * cannot be disabled) → 4085; blocked PIN → WASBLOCKED, blocked by this entry → NOWBLOCKED
   * (TAB_KON_243/246 step 5).
   */
  public Result protect(Context context, String cardHandle, String pinTyp, boolean enable) {
    requirePinTyp(pinTyp);
    CardObject card = access.cardSession(context, cardHandle);
    int reference = reference(card, pinTyp, Operation.PROTECT);
    String prompt =
        "PIN-Schutz \u000B"
            + ANW.get(pinTyp)
            + " \u000B"
            + (enable ? "einschalten" : "abschalten")
            + "\u000FPIN.eGK:";
    PinCommand command =
        PinCommand.one(
            enable ? 0x28 : 0x26,
            0x00,
            reference,
            new PinDialog(prompt, PinDialog.VERIFIED, PinDialog.WRONG));
    publish(
        new PinEvent(
            enable ? PinEvent.Topic.ENABLE_STARTED : PinEvent.Topic.DISABLE_STARTED,
            card,
            pinTyp,
            card.ctId(),
            null));
    Outcome outcome = run(card, command);
    publish(
        new PinEvent(
            enable ? PinEvent.Topic.ENABLE_FINISHED : PinEvent.Topic.DISABLE_FINISHED,
            card,
            pinTyp,
            card.ctId(),
            null));
    outcome.fail(
        card,
        enable ? "PIN-Schutz einschalten" : "PIN-Schutz abschalten",
        Map.of("6982", ConnectorError.ACCESS_CONDITIONS));
    return outcome.result();
  }

  /**
   * Response of the CT to a PIN operation: status word or IO error, from which the PinResult
   * follows.
   */
  private record Outcome(String statusWord, IOException failure) {

    Result result() {
      return statusWord == null
          ? new Result(PinResult.ERROR, null)
          : PinVerification.result(statusWord);
    }

    /**
     * Error states after recording the result: IO error at the CT, then {@code extra} and {@link
     * #error}.
     */
    void fail(CardObject card, String what, Map<String, ConnectorError> extra) {
      if (failure != null) {
        throw TerminalErrors.of(card, what, failure);
      }
      Optional.ofNullable(extra.get(statusWord))
          .or(() -> error(statusWord))
          .ifPresent(
              error -> {
                throw error.exception(
                    card.ctId() + "/" + card.slotNo() + " " + what + " " + statusWord);
              });
    }
  }

  private Outcome run(CardObject card, PinCommand command) {
    CardTerminal terminal = terminal(card);
    try {
      return new Outcome(HEX.formatHex(terminal.pinCommand(card.slotNo(), command)), null);
    } catch (IOException e) {
      return new Outcome(null, e);
    }
  }

  /** New PIN with repetition, without old secret ({@link PinCommand.Mode#NEW}). */
  private static PinCommand newPin(CardObject card, String pinTyp, int ins, int p1, int reference) {
    return new PinCommand(
        new byte[] {0x00, (byte) ins, (byte) p1, (byte) reference},
        PinCommand.Mode.NEW,
        List.of(newPrompt(card, pinTyp), repeatPrompt(card, pinTyp)),
        PinCommand.CHANGED,
        PinDialog.WRONG,
        PinCommand.MISMATCH_TEXT);
  }

  /** Old secret ({@code first}), new PIN and repetition ({@link PinCommand.Mode#OLD_NEW}). */
  private static PinCommand oldNew(
      CardObject card,
      String pinTyp,
      int ins,
      int p1,
      int reference,
      String first,
      String success,
      String failure) {
    return new PinCommand(
        new byte[] {0x00, (byte) ins, (byte) p1, (byte) reference},
        PinCommand.Mode.OLD_NEW,
        List.of(first, newPrompt(card, pinTyp), repeatPrompt(card, pinTyp)),
        success,
        failure,
        PinCommand.MISMATCH_TEXT);
  }

  /**
   * TAB_KON_090 PIN entry: SMC-B PIN.SMC, HBAx PIN.CH, eGK „Sonstige“ with empty ANW (VerifyPin:
   * appName „“).
   */
  static PinDialog verifyDialog(CardObject card) {
    return switch (kind(card)) {
      case SMC_B -> PinDialog.pinSmc(card.slotNo());
      case HBA -> PinDialog.pinCh();
      case EGK ->
          new PinDialog("PIN \u000Bfür \u000B\u000FPIN.eGK:", PinDialog.VERIFIED, PinDialog.WRONG);
    };
  }

  /**
   * TAB_KON_090 old PIN when changing; Versicherten-PIN of the eGK with ANW „Änderung“ (TUC_KON_019
   * 7b).
   */
  private static String changePrompt(CardObject card) {
    return kind(card) == Kind.EGK
        ? "PIN \u000Bfür \u000BÄnderung\u000FPIN.eGK:"
        : verifyDialog(card).prompt();
  }

  /** TAB_KON_090 „Eingabe einer Transport-PIN“. */
  private static String transportPrompt(CardObject card) {
    return switch (kind(card)) {
      case EGK -> "Eingabe \u000BTransport-\u000BVersicherten-PIN\u000FT-PIN.eGK:";
      case HBA -> "Eingabe \u000BTransport-\u000BPIN \u000BHBA\u000FT-PIN.HBA:";
      case SMC_B ->
          "Eingabe \u000BTransport-\u000BPIN SMC-B \u000BSLOT:"
              + card.slotNo()
              + "\u000FT-PIN.SMC:";
    };
  }

  /** TAB_KON_090 „PUK-Eingabe“. */
  private static String pukPrompt(CardObject card) {
    return switch (kind(card)) {
      case EGK -> "Eingabe \u000BVersicherten-\u000BPUK\u000FPUK.eGK:";
      case HBA -> "Eingabe \u000BFreigabe-PUK \u000BHBA\u000FPUK.HBA:";
      case SMC_B -> "Eingabe \u000BPUK SMC-B \u000BSLOT:" + card.slotNo() + "\u000FPUK.SMC:";
    };
  }

  /** TAB_KON_090 „Eingabe einer neuen PIN“. */
  private static String newPrompt(CardObject card, String pinTyp) {
    return switch (kind(card)) {
      case EGK ->
          pinTyp.equals("PIN.AMTS_REP")
              ? "Eingabe \u000Bneue \u000BVertreter-PIN \u000B(6-8 Ziffern)\u000FVertr-PIN:"
              : "Eingabe \u000Bneue \u000BVersicherten-\u000BPIN \u000B(6-8 Ziffern)\u000FPIN.eGK:";
      case HBA ->
          "Eingabe \u000Bneue \u000BFreigabe-PIN \u000BHBA \u000B(6-8 Ziffern)\u000FPIN.HBA:";
      case SMC_B ->
          "Eingabe \u000Bneue \u000BPIN SMC-B \u000BSLOT:"
              + card.slotNo()
              + " \u000B(6-8 Ziffern)\u000FPIN.SMC:";
    };
  }

  /** TAB_KON_090 „Wiederholung einer neuen PIN“. */
  private static String repeatPrompt(CardObject card, String pinTyp) {
    return switch (kind(card)) {
      case EGK ->
          pinTyp.equals("PIN.AMTS_REP")
              ? "Eingabe \u000Bneue \u000BVertreter-PIN \u000Bwiederholen!\u000FVertr-PIN:"
              : "Eingabe \u000BVersicherten-\u000BPIN \u000Bwiederholen!\u000FPIN.eGK:";
      case HBA -> "Eingabe \u000Bfür HBA \u000Bwiederholen!\u000FPIN.HBA:";
      case SMC_B ->
          "Eingabe \u000BPIN.SMC \u000BSLOT:" + card.slotNo() + " \u000Bwiederholen!\u000FPIN.SMC:";
    };
  }

  private enum Kind {
    EGK,
    HBA,
    SMC_B
  }

  private static Kind kind(CardObject card) {
    CardType type = card.data().type();
    return type == CardType.EGK ? Kind.EGK : type == CardType.SMC_B ? Kind.SMC_B : Kind.HBA;
  }

  /**
   * TUC_KON_022 3b: 9000 → VERIFIABLE (verified, but not in this card session), 62C1 →
   * TRANSPORT_PIN, 62C7 → EMPTY_PIN, 63Cx → VERIFIABLE with x tries, 63C0 → BLOCKED with 0, 62D0 →
   * DISABLED; any other response is a card error (empty).
   */
  static Optional<Status> status(String statusWord) {
    return Optional.ofNullable(
        switch (statusWord) {
          case "9000" -> new Status(PinStatus.VERIFIABLE, null);
          case "62C1" -> new Status(PinStatus.TRANSPORT_PIN, null);
          case "62C7" -> new Status(PinStatus.EMPTY_PIN, null);
          case "62D0" -> new Status(PinStatus.DISABLED, null);
          case "63C0" -> new Status(PinStatus.BLOCKED, 0);
          default ->
              statusWord.startsWith("63C")
                  ? new Status(PinStatus.VERIFIABLE, Integer.parseInt(statusWord.substring(3), 16))
                  : null;
        });
  }

  /** GET PIN STATUS (gemSpec_COS): CLA 80, INS 20, P1 00, P2 = password reference, without data. */
  static byte[] getPinStatus(int pinReference) {
    return new byte[] {(byte) 0x80, 0x20, 0x00, (byte) pinReference};
  }

  private static void requirePinTyp(String pinTyp) {
    if (pinTyp == null || pinTyp.isBlank()) {
      throw ConnectorError.SYNTAX.exception("PinTyp fehlt");
    }
  }

  /**
   * Card type and PinTyp of the operation (TAB_KON_047, 049, 051, 053, 242, 245): VerifyPin only
   * SM-B and HBAx (the eGK MUST NOT, TAB_KON_047), EnablePin/DisablePin only eGK; other cards →
   * 4209, another PinTyp → 4000. Returns the PIN reference.
   */
  static int reference(CardObject card, String pinTyp, Operation operation) {
    CardType type = card.data().type();
    Map<String, Integer> references;
    if (type == CardType.SMC_B && operation != Operation.PROTECT) {
      references = Map.of("PIN.SMC", PIN_01);
    } else if (type.matches("HBAx") && operation != Operation.PROTECT) {
      references = Map.of("PIN.CH", PIN_01);
    } else if (type == CardType.EGK && operation == Operation.PROTECT) {
      references = PROTECTABLE;
    } else if (type == CardType.EGK && operation != Operation.VERIFY) {
      references = EGK;
    } else {
      throw ConnectorError.CARD_TYPE_UNSUPPORTED.exception(
          ConnectorError.CARD_TYPE_UNSUPPORTED.text().replace("%CardType%", type.value()),
          card.cardHandle() + " ist " + type.value());
    }
    Integer reference = references.get(pinTyp);
    if (reference == null) {
      throw ConnectorError.SYNTAX.exception(
          "PinTyp "
              + pinTyp
              + " für "
              + type.value()
              + " nicht unterstützt, "
              + "nur "
              + new TreeSet<>(references.keySet()));
    }
    return reference;
  }

  private CardTerminal terminal(CardObject card) {
    return terminals
        .terminal(card.ctId())
        .orElseThrow(() -> ConnectorError.CT_ACCESS.exception(card.ctId()));
  }

  private void publish(PinEvent event) {
    listeners.forEach(listener -> listener.accept(event));
  }

  /**
   * Error cases (7) of the PIN TUCs, TAB_KON_089/093/193: {@code 6400} (no or incomplete entry in
   * time, [SICCT] §5.19.6) → 4043, {@code 6401} (cancel key) → 4049; TUC_KON_019/021 (7b) {@code
   * 6402} (non-matching repetition of the new PIN at the CT, SICCT errata 1.0 §5.20.6) → 4067; (7b)
   * {@code 64A1} (no card in the slot, the card was removed during entry) → 4008, {@code 6A88}
   * (reference unknown) → 4072. Wrong entries are not errors (REJECTED, NOWBLOCKED); the blocked
   * PIN or PUK (4063, 4064) and the transport PIN (4065) are caught by the operations in step 5 as
   * WASBLOCKED or TRANSPORT_PIN.
   */
  static Optional<ConnectorError> error(String statusWord) {
    return Optional.ofNullable(
        switch (statusWord) {
          case "6400" -> ConnectorError.PIN_TIMEOUT;
          case "6401" -> ConnectorError.PIN_CANCELLED;
          case "6402" -> ConnectorError.PIN_MISMATCH;
          case "64A1" -> ConnectorError.CARD_NOT_INSERTED;
          case "6A88" -> ConnectorError.INVALID_PIN_REF;
          default -> null;
        });
  }

  /**
   * TUC_KON_012/019/021/027 step 7c or 5c with step 5 of the operations: 9000 → OK, 63CX (X &gt; 0)
   * → REJECTED with X tries, blocked by this entry (63C0, BLOCKED) → NOWBLOCKED, already blocked
   * before (6983, gemSpec_COS; 4063 or 4064) → WASBLOCKED, transport or empty PIN (6985; 4065) →
   * TRANSPORT_PIN; everything else, including cancel and timeout at the terminal, is ERROR.
   */
  static Result result(String statusWord) {
    return switch (statusWord) {
      case "9000" -> new Result(PinResult.OK, null);
      case "63C0" -> new Result(PinResult.NOWBLOCKED, null);
      case "6983" -> new Result(PinResult.WASBLOCKED, null);
      case "6985" -> new Result(PinResult.TRANSPORT_PIN, null);
      default ->
          statusWord.startsWith("63C")
              ? new Result(PinResult.REJECTED, Integer.parseInt(statusWord.substring(3), 16))
              : new Result(PinResult.ERROR, null);
    };
  }
}

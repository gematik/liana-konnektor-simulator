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
package de.gematik.liana.kern.terminal;

import java.util.HexFormat;
import java.util.List;

/**
 * A PIN operation on the card terminal's PIN pad (LIANA-109): the card command {@code header} (CLA
 * INS P1 P2), into which the CT inserts the entered secrets as format-2 PIN blocks, and the
 * displays per TAB_KON_090. The secrets never leave the CT.
 *
 * <ul>
 *   <li>{@link Mode#ONE}: one secret, SICCT PERFORM VERIFICATION ([SICCT] §5.19) – VERIFY,
 *       ENABLE/DISABLE VERIFICATION REQUIREMENT with P1 '00', RESET RETRY COUNTER with P1 '01' (PUK
 *       only);
 *   <li>{@link Mode#OLD_NEW}: old secret (PIN, transport PIN or PUK), new PIN and its repetition,
 *       SICCT MODIFY VERIFICATION DATA (§5.20) – CHANGE REFERENCE DATA P1 '00', RESET RETRY COUNTER
 *       P1 '00';
 *   <li>{@link Mode#NEW}: new PIN and its repetition, MODIFY VERIFICATION DATA with only one PIN
 *       block – CHANGE REFERENCE DATA P1 '01', RESET RETRY COUNTER P1 '02' (PIN.AMTS_REP after
 *       PIN.CH).
 * </ul>
 *
 * <p>{@code prompts} per input in the order of the query, {@code success} and {@code failure} after
 * the card command, {@code mismatch} on a non-matching repetition ({@link PinMismatchException}).
 *
 * <p>With {@code channel}, the card command goes in the trusted channel between the CT's gSMC-KT
 * and the card, the PIN encrypted with its session key (remote PIN procedure TIP1-A_5012 steps 3
 * and 4, LIANA-112.13); otherwise {@code null}.
 */
public record PinCommand(
    byte[] header,
    Mode mode,
    List<String> prompts,
    String success,
    String failure,
    String mismatch,
    SecureChannel channel) {

  public enum Mode {
    ONE(1),
    OLD_NEW(3),
    NEW(2);

    private final int inputs;

    Mode(int inputs) {
      this.inputs = inputs;
    }

    /** How many inputs the user makes. */
    public int inputs() {
      return inputs;
    }

    /** How many PIN blocks the card command carries. */
    public int blocks() {
      return this == OLD_NEW ? 2 : 1;
    }
  }

  /** TAB_KON_090 „Ungleichheit bei der Wiederholung der Eingabe der neuen PIN“, all cards. */
  public static final String MISMATCH_TEXT = "PINs \u000Bnicht \u000Bidentisch! \u000BAbbruch!";

  /** TAB_KON_090 „Erfolgreiche PIN-Änderung“, all cards. */
  public static final String CHANGED = "PIN \u000Berfolgreich \u000Bgeändert!";

  /** TAB_KON_090 „Erfolgreiche PUK-Eingabe“, all cards. */
  public static final String UNBLOCKED = "PIN \u000Berfolgreich \u000Bentsperrt!";

  /** TAB_KON_090 „Fehlerhafte PUK-Eingabe“, all cards. */
  public static final String WRONG_PUK = "PUK \u000Bfalsch \u000Boder \u000Bgesperrt!";

  public PinCommand {
    if (header.length != 4) {
      throw new IllegalArgumentException("Kartenkommando: CLA INS P1 P2 erwartet");
    }
    if (prompts.size() != mode.inputs()) {
      throw new IllegalArgumentException(
          mode + ": " + mode.inputs() + " Anzeigen erwartet, nicht " + prompts.size());
    }
    header = header.clone();
    prompts = List.copyOf(prompts);
  }

  /** Without trusted channel. */
  public PinCommand(
      byte[] header,
      Mode mode,
      List<String> prompts,
      String success,
      String failure,
      String mismatch) {
    this(header, mode, prompts, success, failure, mismatch, null);
  }

  /**
   * The same command in the trusted channel {@code channel} (remote PIN procedure, TIP1-A_5012).
   */
  public PinCommand withChannel(SecureChannel channel) {
    return new PinCommand(header, mode, prompts, success, failure, mismatch, channel);
  }

  /** VERIFY {@code 00 20 00 <pinReference>} with the displays of {@code dialog}. */
  public static PinCommand verify(int pinReference, PinDialog dialog) {
    return one(0x20, 0x00, pinReference, dialog);
  }

  /**
   * One secret: command {@code 00 <ins> <p1> <pinReference>}, e.g. DISABLE VERIFICATION REQUIREMENT
   * {@code 26}.
   */
  public static PinCommand one(int ins, int p1, int pinReference, PinDialog dialog) {
    return new PinCommand(
        new byte[] {0x00, (byte) ins, (byte) p1, (byte) pinReference},
        Mode.ONE,
        List.of(dialog.prompt()),
        dialog.success(),
        dialog.failure(),
        MISMATCH_TEXT);
  }

  @Override
  public byte[] header() {
    return header.clone();
  }

  /**
   * The card command with placeholders as it appears on the wire to the CT (Lc = 8 per PIN block).
   */
  public String template() {
    return HexFormat.of().withUpperCase().formatHex(header)
        + "%02X".formatted(8 * mode.blocks())
        + "FF".repeat(8 * mode.blocks());
  }

  @Override
  public boolean equals(Object other) {
    return other instanceof PinCommand c
        && java.util.Arrays.equals(header, c.header)
        && mode == c.mode
        && prompts.equals(c.prompts)
        && success.equals(c.success)
        && failure.equals(c.failure)
        && mismatch.equals(c.mismatch)
        && java.util.Objects.equals(channel, c.channel);
  }

  @Override
  public int hashCode() {
    return java.util.Objects.hash(
        java.util.Arrays.hashCode(header), mode, prompts, success, failure, mismatch, channel);
  }

  @Override
  public String toString() {
    return mode
        + " "
        + HexFormat.of().withUpperCase().formatHex(header)
        + (channel == null ? "" : " (SM)");
  }
}

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
package de.gematik.liana.adapter.fake;

import java.util.Locale;

/**
 * A PIN input at the PIN pad of the fake KT (LIANA-68), set via the Admin API or the Robot,
 * volatile like the {@link Fault faults} (decision-4). The template is the PIN script of {@code
 * kartos terminal} 0.8.0 ({@code /api/v1/tui/script}, decision-11): the same {@code outcome} values
 * {@code correct}, {@code wrong}, {@code digits}, {@code cancel}, {@code timeout}; plus {@code
 * puk}, {@code transport} and {@code incomplete}, which kartos does not know (yet). What the user
 * types is decided only by the card (gemSpec_COS VERIFY); what the user does at the terminal is
 * answered by the KT itself ([SICCT] §5.19.6):
 *
 * <ul>
 *   <li>{@link Outcome#CORRECT}, {@link Outcome#DIGITS}, {@link Outcome#WRONG}, {@link
 *       Outcome#PUK}, {@link Outcome#TRANSPORT}: digits with confirm key, VERIFY to the card (9000,
 *       63Cx, 6983, 6985 …);
 *   <li>{@link Outcome#CANCEL}: cancel key, {@code 6401}, the card sees no command;
 *   <li>{@link Outcome#TIMEOUT}: no input in time, {@code 6400} immediately, without waiting for
 *       the time;
 *   <li>{@link Outcome#INCOMPLETE}: digits without confirmation; the KT waits until the timeout
 *       ({@code 6400}) or until the card is removed ({@code 64A1}).
 * </ul>
 *
 * <p>{@code pin} only with {@link Outcome#DIGITS}: 4 to 12 digits.
 */
public record PinInput(Outcome outcome, String pin) {

  public enum Outcome {
    /** The configured PIN of the KT ({@code pin}, default 123456). */
    CORRECT("correct"),
    /** The configured PIN with every digit changed (like kartos). */
    WRONG("wrong"),
    /** The digits from {@code pin}. */
    DIGITS("digits"),
    CANCEL("cancel"),
    TIMEOUT("timeout"),
    /** The PUK of the KT ({@code puk}). */
    PUK("puk"),
    /** The transport PIN of the KT ({@code transport-pin}). */
    TRANSPORT("transport"),
    INCOMPLETE("incomplete");

    private final String value;

    Outcome(String value) {
      this.value = value;
    }

    public String value() {
      return value;
    }

    public static Outcome of(String value) {
      for (Outcome outcome : values()) {
        if (outcome.value.equals(value == null ? null : value.toLowerCase(Locale.ROOT))) {
          return outcome;
        }
      }
      throw new IllegalArgumentException(
          "PIN-Eingabe '"
              + value
              + "' unbekannt, erwartet correct, wrong, digits, "
              + "cancel, timeout, puk, transport oder incomplete");
    }
  }

  public PinInput {
    if (outcome == null) {
      throw new IllegalArgumentException("PIN-Eingabe ohne outcome");
    }
    if (outcome == Outcome.DIGITS ? pin == null || !pin.matches("[0-9]{4,12}") : pin != null) {
      throw new IllegalArgumentException(
          outcome == Outcome.DIGITS
              ? "PIN-Eingabe digits: pin aus 4 bis 12 Ziffern erwartet"
              : "PIN-Eingabe " + outcome.value() + ": pin nur bei digits");
    }
  }

  public static PinInput of(Outcome outcome) {
    return new PinInput(outcome, null);
  }

  /** Without the digits, as kartos never returns or logs them. */
  @Override
  public String toString() {
    return outcome.value();
  }
}

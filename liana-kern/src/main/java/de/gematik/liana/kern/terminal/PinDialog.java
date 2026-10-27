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

/**
 * The terminal displays of a PIN entry (TIP1-A_4561-02, TAB_KON_090): prompt with PIN prompt,
 * message after successful and after failed entry. {@code 0x0B} marks allowed line breaks, {@code
 * 0x0F} separates message and PIN prompt ([SICCT] §5.6.1).
 */
public record PinDialog(String prompt, String success, String failure) {

  /** TAB_KON_090 „Erfolgreiche PIN-Eingabe“, all cards. */
  public static final String VERIFIED = "PIN \u000Berfolgreich \u000Bverifiziert!";

  /** TAB_KON_090 „Fehlerhafte PIN-Eingabe“, all cards. */
  public static final String WRONG = "PIN \u000Bfalsch \u000Boder \u000Bgesperrt!";

  /** TAB_KON_090 HBAx/PIN.CH: „Eingabe•0x0BFreigabe-PIN•0x0BHBA 0x0FPIN.HBA:“. */
  public static PinDialog pinCh() {
    return new PinDialog("Eingabe \u000BFreigabe-PIN \u000BHBA\u000FPIN.HBA:", VERIFIED, WRONG);
  }

  /**
   * TAB_KON_090 HBA/PIN.QES (trigger signature): „#UVW-XYZ•0x0BEingabe•0x0BSignaturPIN•0x0BHBA
   * 0x0FPIN.QES:“, the placeholder #UVW-XYZ is the Jobnummer.
   */
  public static PinDialog pinQes(String jobNumber) {
    return new PinDialog(
        jobNumber + " \u000BEingabe \u000BSignaturPIN \u000BHBA\u000FPIN.QES:", VERIFIED, WRONG);
  }

  /**
   * TAB_KON_090 HBA/PIN.QES (activate Komfortsignatur): „Komfortsignatur•0x0Baktivieren•0x0BHBA
   * 0x0FPIN.QES:“.
   */
  public static PinDialog comfortQes() {
    return new PinDialog(
        "Komfortsignatur \u000Baktivieren \u000BHBA\u000FPIN.QES:", VERIFIED, WRONG);
  }

  /** TAB_KON_090 SMC-B/PIN.SMC: „Eingabe•0x0BPIN•SMC-B•0x0BSLOT:X 0x0FPIN.SMC:“. */
  public static PinDialog pinSmc(int slot) {
    return new PinDialog(
        "Eingabe \u000BPIN SMC-B \u000BSLOT:" + slot + "\u000FPIN.SMC:", VERIFIED, WRONG);
  }
}

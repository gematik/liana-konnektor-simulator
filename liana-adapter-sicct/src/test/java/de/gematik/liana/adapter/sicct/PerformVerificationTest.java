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
package de.gematik.liana.adapter.sicct;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.kern.terminal.PinCommand;
import de.gematik.liana.kern.terminal.PinDialog;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Encoding of SICCT PERFORM VERIFICATION (SICCT 1.2.3 §5.19, gemSpec_KT 3.7.5) for VerifyPin
 * PIN.SMC.
 */
class PerformVerificationTest {

  static final HexFormat HEX = HexFormat.of().withUpperCase();

  private static List<Tlv> data(byte[] apdu) throws java.io.IOException {
    assertEquals(apdu.length - 5, apdu[4] & 0xFF, "Lc");
    return Tlv.parse(Arrays.copyOfRange(apdu, 5, apdu.length));
  }

  private static String text(Tlv tlv) {
    return new String(tlv.value(), StandardCharsets.US_ASCII);
  }

  @Test
  @DisplayName(
      "SICCT §5.19.3: CLA 80, INS 18, P1 = Slot (Direct Coding), P2 = D0 (Standard-Keypad mit "
          + "Bestätigungstaste), kein Le; CMD DO 52 mit Steuerbyte 02, Einfügeposition 06 und VERIFY 00 20 00 01 08")
  void kommando() throws Exception {
    byte[] apdu = SicctTerminal.performVerification(2, 0x01, PinDialog.pinSmc(2));
    assertEquals("801802D0", HEX.formatHex(apdu, 0, 4));
    List<Tlv> dos = data(apdu);
    assertEquals(List.of(0x50, 0x50, 0x50, 0x52), dos.stream().map(Tlv::tag).toList());
    assertEquals("0206002000010" + "8FFFFFFFFFFFFFFFF", HEX.formatHex(dos.get(3).value()));
  }

  @Test
  @DisplayName(
      "TIP1-A_3083 / TIP1-A_4561-02: die APPL DOs tragen in der Reihenfolge aus §5.19.2 die Anzeigen aus "
          + "TAB_KON_090 – Aufforderung mit Prompt nach 0x0F, Erfolg, Fehler; TIP1-A_3084/3085: Nachricht höchstens 48, "
          + "Prompt höchstens 10 Zeichen; kein WT DO, das KT wartet 30 s (TIP1-A_3086)")
  void anzeigen() throws Exception {
    List<Tlv> dos = data(SicctTerminal.performVerification(3, 0x01, PinDialog.pinSmc(3)));
    assertEquals("Eingabe \u000BPIN SMC-B \u000BSLOT:3\u000FPIN.SMC:", text(dos.get(0)));
    assertEquals("PIN \u000Berfolgreich \u000Bverifiziert!", text(dos.get(1)));
    assertEquals("PIN \u000Bfalsch \u000Boder \u000Bgesperrt!", text(dos.get(2)));
    for (Tlv appl : dos.subList(0, 3)) {
      String[] parts = text(appl).split("\u000F");
      assertTrue(parts[0].replace("\u000B", "").length() <= 48, text(appl));
      assertTrue(parts.length == 1 || parts[1].length() <= 10, text(appl));
    }
    assertTrue(dos.stream().noneMatch(d -> d.tag() == 0x80), "WT DO");
  }

  @Test
  @DisplayName(
      "LIANA-109 TUC_KON_027 5b: DisablePin MRPIN.DPE als PERFORM VERIFICATION mit DISABLE VERIFICATION "
          + "REQUIREMENT 00 26 00 04 im CMD DO; Anzeigen nach ISO 646-DE (TAB_KON_090: ä → '{')")
  void pinSchutz() throws Exception {
    PinCommand disable =
        PinCommand.one(
            0x26,
            0x00,
            0x04,
            new PinDialog(
                "PIN-Schutz \u000BPers.Erklärungen \u000Babschalten\u000FPIN.eGK:",
                PinDialog.VERIFIED,
                PinDialog.WRONG));
    List<Tlv> dos = data(SicctTerminal.performVerification(1, disable));
    assertEquals("0206002600040" + "8FFFFFFFFFFFFFFFF", HEX.formatHex(dos.get(3).value()));
    assertEquals(
        "PIN-Schutz \u000BPers.Erkl{rungen \u000Babschalten\u000FPIN.eGK:", text(dos.get(0)));
    assertEquals(
        "[\\]{|}~@", new String(SicctTerminal.display("ÄÖÜäöüß§"), StandardCharsets.US_ASCII));
  }
}

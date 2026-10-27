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

import de.gematik.liana.kern.terminal.PinCommand;
import de.gematik.liana.kern.terminal.PinDialog;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Encoding of SICCT MODIFY VERIFICATION DATA (SICCT 1.2.3 §5.20.3, §5.5.10.23) for ChangePin and
 * UnblockPin (TUC_KON_019/021 7b, LIANA-127). The SICCT Errata 1.0 announce a call example for
 * §5.20 but do not contain one; the test checks against the command structure from §5.20.3 and the
 * CMD DO from §5.5.10.23.
 */
class ModifyVerificationDataTest {

  static final HexFormat HEX = HexFormat.of().withUpperCase();
  static final String OLD = "Eingabe \u000BPIN SMC-B \u000BSLOT:2\u000FPIN.SMC:";
  static final String NEW =
      "Eingabe \u000Bneue \u000BPIN SMC-B \u000BSLOT:2 \u000B(6-8 Ziffern)\u000FPIN.SMC:";
  static final String REPEAT = "Wiederholung \u000Bneue \u000BPIN SMC-B \u000BSLOT:2\u000FPIN.SMC:";

  /** Data field after short or extended Lc (SICCT §5.20.3), without Le (gemSpec_KT A_25230). */
  private static List<Tlv> data(byte[] apdu) throws java.io.IOException {
    int offset = apdu[4] == 0 ? 7 : 5;
    int lc = apdu[4] == 0 ? ((apdu[5] & 0xFF) << 8) | (apdu[6] & 0xFF) : apdu[4] & 0xFF;
    assertEquals(apdu.length - offset, lc, "Lc, kein Le");
    return Tlv.parse(Arrays.copyOfRange(apdu, offset, apdu.length));
  }

  private static List<String> texts(List<Tlv> dos) {
    return dos.stream()
        .filter(d -> d.tag() == 0x50)
        .map(d -> new String(d.value(), StandardCharsets.US_ASCII))
        .toList();
  }

  private static PinCommand oldNew(String header, String success, String failure) {
    return new PinCommand(
        HEX.parseHex(header),
        PinCommand.Mode.OLD_NEW,
        List.of(OLD, NEW, REPEAT),
        success,
        failure,
        PinCommand.MISMATCH_TEXT);
  }

  private static PinCommand newPin(String header) {
    return new PinCommand(
        HEX.parseHex(header),
        PinCommand.Mode.NEW,
        List.of(NEW, REPEAT),
        PinCommand.CHANGED,
        PinDialog.WRONG,
        PinCommand.MISMATCH_TEXT);
  }

  @Test
  @DisplayName(
      "TUC_KON_019 7b ChangePin PIN.SMC: 80 19, P1 = Slot (Direct Coding), P2 = D0, erweitertes Lc ab "
          + "256 Byte Daten, kein Le; CMD DO 52 mit "
          + "Steuerbyte 02 (Format-2-PIN-Block), Einfügepositionen 06 und 0E, CHANGE REFERENCE DATA 00 24 00 01 10 mit "
          + "zwei Platzhalterblöcken (SICCT §5.20.3, §5.5.10.23)")
  void changePin() throws Exception {
    byte[] apdu =
        SicctTerminal.modifyVerificationData(
            2, oldNew("00240001", PinCommand.CHANGED, PinDialog.WRONG));
    assertEquals("801902D0", HEX.formatHex(apdu, 0, 4));
    assertEquals("000107", HEX.formatHex(apdu, 4, 7), "erweitertes Lc, 263 Byte Daten");
    List<Tlv> dos = data(apdu);
    assertEquals(
        List.of(0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x52), dos.stream().map(Tlv::tag).toList());
    assertEquals("02060E" + "0024000110" + "FF".repeat(16), HEX.formatHex(dos.getLast().value()));
  }

  @Test
  @DisplayName(
      "TAB_KON_090 auf den Plätzen der Standardtexte aus SICCT §5.20.2: alte PIN (4), Erfolg (5), Fehler (6), "
          + "neue PIN (7), Wiederholung (8), ungleiche Wiederholung (9); Umlaute nach ISO 646-DE")
  void anzeigen() throws Exception {
    List<Tlv> dos =
        data(
            SicctTerminal.modifyVerificationData(
                2, oldNew("00240001", PinCommand.CHANGED, PinDialog.WRONG)));
    assertEquals(
        List.of(
            OLD,
            "PIN \u000Berfolgreich \u000Bge{ndert!",
            "PIN \u000Bfalsch \u000Boder \u000Bgesperrt!",
            NEW,
            REPEAT,
            "PINs \u000Bnicht \u000Bidentisch! \u000BAbbruch!"),
        texts(dos));
  }

  @Test
  @DisplayName(
      "TUC_KON_021 7b UnblockPin mit SetNewPin: ebenfalls 80 19 (SICCT kennt kein eigenes Entsperrkommando, "
          + "gemSpec_KT A_24111), RESET RETRY COUNTER 00 2C 00 01 10 im CMD DO, Anzeigen PUK-Eingabe und „PIN erfolgreich "
          + "entsperrt!“")
  void unblockPin() throws Exception {
    byte[] apdu =
        SicctTerminal.modifyVerificationData(
            3, oldNew("002C0001", PinCommand.UNBLOCKED, PinCommand.WRONG_PUK));
    assertEquals("801903D0", HEX.formatHex(apdu, 0, 4));
    List<Tlv> dos = data(apdu);
    assertEquals("02060E" + "002C000110" + "FF".repeat(16), HEX.formatHex(dos.getLast().value()));
    assertEquals("PIN \u000Berfolgreich \u000Bentsperrt!", texts(dos).get(1));
    assertEquals("PUK \u000Bfalsch \u000Boder \u000Bgesperrt!", texts(dos).get(2));
  }

  @Test
  @DisplayName(
      "TUC_KON_019 7b Leer-PIN (CHANGE REFERENCE DATA P1 01) und PIN.AMTS_REP (RESET RETRY COUNTER P1 02): "
          + "Null-PIN-Verfahren aus SICCT §5.20.2 – 1. Einfügeposition 00, 2. Einfügeposition 06, ein Platzhalterblock, "
          + "die 1. Anzeige als leeres APPL DO")
  void nullPin() throws Exception {
    List<Tlv> dos = data(SicctTerminal.modifyVerificationData(1, newPin("00240101")));
    assertEquals("020006" + "0024010108" + "FF".repeat(8), HEX.formatHex(dos.getLast().value()));
    assertEquals(
        List.of(
            "",
            "PIN \u000Berfolgreich \u000Bge{ndert!",
            "PIN \u000Bfalsch \u000Boder \u000Bgesperrt!",
            NEW,
            REPEAT,
            "PINs \u000Bnicht \u000Bidentisch! \u000BAbbruch!"),
        texts(dos));
    assertEquals("5000", HEX.formatHex(dos.getFirst().encode()));

    List<Tlv> amts = data(SicctTerminal.modifyVerificationData(1, newPin("002C020D")));
    assertEquals("020006" + "002C020D08" + "FF".repeat(8), HEX.formatHex(amts.getLast().value()));
  }

  @Test
  @DisplayName(
      "LIANA-126/127 Deviation KARTOS_MODIFY_VERIFICATION_DATA: kartos-Format – Ändern 80 19, Entsperren 80 1A, "
          + "nur neue PIN 80 18; PinFormat-DO 5F2F (BCD/Format 2, 8 Byte, Länge Nibble 1, Ziffern ab Nibble 2, 4–12) "
          + "und das Kartenkommando ohne Steuerbyte im DO 52; Anzeigen mit SLOT:n")
  void kartos() throws Exception {
    byte[] change =
        SicctTerminal.kartosModify(2, oldNew("00240001", PinCommand.CHANGED, PinDialog.WRONG));
    assertEquals("801902D0", HEX.formatHex(change, 0, 4));
    List<Tlv> dos = data(change);
    assertEquals(List.of(0x50, 0x50, 0x50, 0x5F2F, 0x52), dos.stream().map(Tlv::tag).toList());
    assertEquals("02080102040C", HEX.formatHex(dos.get(3).value()));
    assertEquals("0024000110" + "FF".repeat(16), HEX.formatHex(dos.getLast().value()));
    assertEquals(OLD, texts(dos).getFirst());

    byte[] unblock =
        SicctTerminal.kartosModify(
            2, oldNew("002C0001", PinCommand.UNBLOCKED, PinCommand.WRONG_PUK));
    assertEquals("801A02D0", HEX.formatHex(unblock, 0, 4));
    assertEquals("002C000110" + "FF".repeat(16), HEX.formatHex(data(unblock).getLast().value()));

    byte[] leer = SicctTerminal.kartosModify(2, newPin("00240101"));
    assertEquals("801802D0", HEX.formatHex(leer, 0, 4));
    assertEquals("0024010108" + "FF".repeat(8), HEX.formatHex(data(leer).getLast().value()));
    assertEquals(NEW, texts(data(leer)).getFirst());
  }
}

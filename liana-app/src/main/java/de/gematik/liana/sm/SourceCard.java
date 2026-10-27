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
package de.gematik.liana.sm;

import static de.gematik.liana.sm.Apdus.WRONG_DATA;
import static de.gematik.liana.sm.Apdus.apdu;
import static de.gematik.liana.sm.Apdus.fields;
import static de.gematik.liana.sm.Apdus.isOk;
import static de.gematik.liana.sm.Apdus.status;
import static de.gematik.liana.sm.Apdus.tlv;
import static de.gematik.liana.sm.Apdus.withLe;

import de.gematik.liana.kern.terminal.CardTerminal;
import java.io.IOException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

/**
 * LIANA as source card in C2C with elcSessionkey4SM (gemSpec_COS 15.4, TUC_KON_005
 * „gegenseitig+TC“): the target card imports the source card's CVC chain (MSE SET DST, PSO VERIFY
 * CERTIFICATE, 14.8.7), then MSE SET AT with its private key and GENERAL AUTHENTICATE in two steps;
 * both sides derive the session keys. LIANA performs the source card's computation with the key
 * from its image ({@link TerminalIdentity}). Hop B of the terminated PoPP channel (LIANA-28) and
 * the channels to the HBA (LIANA-112.13).
 */
final class SourceCard {

  private static final HexFormat HEX = HexFormat.of().withUpperCase();

  /** '6A 88': the key for the CAR is missing on the card (TUC_KON_005 variant 9). */
  private static final byte[] KEY_NOT_FOUND = {0x6A, (byte) 0x88};

  /** A step failed at the card; {@code status} is its status word. */
  static final class Failed extends Exception {
    final byte[] status;

    Failed(String message, byte[] status) {
      super(message);
      this.status = status;
    }
  }

  private SourceCard() {}

  /**
   * Imports the first chain from {@code chains} whose first certificate the card can verify ('6A
   * 88' on MSE SET DST: the next one), sends {@code setAt} (MSE SET AT with algId elcSessionkey4SM)
   * and GENERAL AUTHENTICATE as {@code identity}. {@code targetStatic} is the public key from the
   * target card's CVC.
   */
  static SecureMessaging.Session authenticate(
      CardTerminal terminal,
      int slot,
      TerminalIdentity identity,
      List<List<Cvc>> chains,
      byte[] setAt,
      byte[] targetStatic)
      throws IOException, Failed {
    importChain(terminal, slot, chains);
    expectOk(terminal, slot, setAt, "MSE SET AT");
    ElcSessionkey4Sm.KeyPair ephemeral = ElcSessionkey4Sm.ephemeral();
    byte[] step1 =
        terminal.transmit(
            slot,
            withLe(apdu(0x10, 0x86, 0x00, 0x00, tlv(0x7C, tlv(0xC3, identity.endEntity().chr())))));
    if (!isOk(step1)) {
      throw new Failed(
          "GENERAL AUTHENTICATE Schritt 1: " + HEX.formatHex(status(step1)), status(step1));
    }
    byte[] cardEphemeral =
        fields(fields(Arrays.copyOf(step1, step1.length - 2)).getOrDefault(0x7C, new byte[0]))
            .get(0x85);
    if (cardEphemeral == null) {
      throw new Failed(
          "GENERAL AUTHENTICATE Schritt 1 ohne ephemeren Schlüssel der Karte", WRONG_DATA);
    }
    expectOk(
        terminal,
        slot,
        withLe(apdu(0x00, 0x86, 0x00, 0x00, tlv(0x7C, tlv(0x85, ephemeral.point())))),
        "GENERAL AUTHENTICATE Schritt 2");
    return ElcSessionkey4Sm.asTerminal(identity.key(), ephemeral, targetStatic, cardEphemeral);
  }

  private static void importChain(CardTerminal terminal, int slot, List<List<Cvc>> chains)
      throws IOException, Failed {
    if (chains.isEmpty()) {
      throw new Failed("keine CVC-Kette zur Zielkarte", KEY_NOT_FOUND);
    }
    for (int i = 0; i < chains.size(); i++) {
      List<Cvc> chain = chains.get(i);
      boolean last = i == chains.size() - 1;
      Cvc first = chain.getFirst();
      byte[] response = terminal.transmit(slot, setDst(first));
      if (Arrays.equals(status(response), KEY_NOT_FOUND) && !last) {
        continue;
      }
      if (!isOk(response)) {
        throw new Failed(
            "MSE SET DST " + HEX.formatHex(first.car()) + ": " + HEX.formatHex(status(response)),
            status(response));
      }
      for (int j = 0; j < chain.size(); j++) {
        Cvc cvc = chain.get(j);
        if (j > 0) {
          expectOk(terminal, slot, setDst(cvc), "MSE SET DST " + HEX.formatHex(cvc.car()));
        }
        expectOk(
            terminal,
            slot,
            apdu(0x00, 0x2A, 0x00, 0xBE, cvc.content()),
            "PSO VERIFY CERTIFICATE " + cvc);
      }
      return;
    }
  }

  /**
   * MSE SET DST with the verification key of the CAR of {@code cvc} (gemSpec_COS 14.8.7, CosT_6fc).
   */
  private static byte[] setDst(Cvc cvc) {
    return apdu(0x00, 0x22, 0x81, 0xB6, tlv(0x83, cvc.car()));
  }

  private static void expectOk(CardTerminal terminal, int slot, byte[] command, String what)
      throws IOException, Failed {
    byte[] response = terminal.transmit(slot, command);
    if (!isOk(response)) {
      throw new Failed(what + ": " + HEX.formatHex(status(response)), status(response));
    }
  }
}

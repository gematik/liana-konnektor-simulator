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

import de.gematik.liana.kern.error.ConnectorError;
import de.gematik.liana.kern.terminal.CardTerminal;
import de.gematik.liana.kern.terminal.SecureChannel;
import de.gematik.liana.kern.terminal.TerminalRegistry;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.HexFormat;

/**
 * TUC_KON_218 „Signiere“ in DF.ESIGN or DF.QES: SELECT of the DF, MSE SET DST (key, algorithm), PSO
 * COMPUTE DIGITAL SIGNATURE over a SHA-256 hash. With an ECC key (signECDSA) the card returns (r,
 * s) per BSI TR-03111 5.2.1, the signature is returned as ECDSA-Sig-Value (TR-03111 5.2.2, DER);
 * with PrK.HP.QES.R2048 of the HBA G2.0 (signPSS, gemSpec_COS G2_N088.600.a: RSASSA-PSS with
 * SHA-256, MGF1, salt 32) the signature value itself.
 *
 * <p>LIANA does not use the other R2048 keys of the G2.0 cards (AUT, OSIG) or signPKCS1_V1_5.
 */
public final class CardSignature {

  /** Private keys per TAB_KON_784 and TAB_KON_900, per keyIdentifier in DF.ESIGN. */
  public enum Key {
    /** PrK.HCI.AUT.E256 of the SM-B or PrK.HP.AUT.E256 of the HBAx (TAB_KON_784). */
    AUT_E256(DF_ESIGN, 0x06, SIGN_ECDSA),
    /** PrK.HCI.OSIG.E256 of the SM-B (TAB_KON_900, nonQES). */
    OSIG_E256(DF_ESIGN, 0x07, SIGN_ECDSA),
    /**
     * PrK.HP.QES.E256 of the HBA from G2.1 in DF.QES (TAB_KON_900, QES); keyIdentifier from the
     * images (gemSpec_HBA_ObjSys is missing), released by PWD(81), the PIN.QES.
     */
    QES_E256(DF_QES, 0x06, SIGN_ECDSA),
    /**
     * PrK.HP.QES.R2048 of the HBA G2.0 in DF.QES (TAB_KON_900, QES), keyIdentifier from the images,
     * PWD(81).
     */
    QES_R2048(DF_QES, 0x04, SIGN_PSS);

    private final String df;
    private final int keyIdentifier;
    private final int algorithm;

    Key(String df, int keyIdentifier, int algorithm) {
      this.df = df;
      this.keyIdentifier = keyIdentifier;
      this.algorithm = algorithm;
    }

    /** Whether the key is an RSA key (signPSS), otherwise ECC. */
    public boolean rsa() {
      return algorithm == SIGN_PSS;
    }
  }

  /** algorithmIdentifier signECDSA (gemSpec_COS CosT_7a2). */
  private static final int SIGN_ECDSA = 0x00;

  /** algorithmIdentifier signPSS (gemSpec_COS CosT_7a2). */
  private static final int SIGN_PSS = 0x05;

  private static final HexFormat HEX = HexFormat.of().withUpperCase();
  private static final String DF_ESIGN = "A000000167455349474E";
  private static final String DF_QES = "D27600006601";
  private static final String SELECT_AID = "00A4040C";

  /** SELECT MF without data (gemSpec_COS 14.2.6.1). */
  private static final String SELECT_MF = "00A4000C";

  /** MSE SET DST: key reference '84' (keyIdentifier | '80', private in the DF), algorithm '80'. */
  private static final String MSE_SET_DST = "002241B6068401%02X8001%02X";

  private static final String PSO_CDS = "002A9E9A";

  private final TerminalRegistry terminals;

  public CardSignature(TerminalRegistry terminals) {
    this.terminals = terminals;
  }

  /**
   * Signs {@code hash} (32 bytes) with {@code key} on {@code card}. The PIN that releases the key
   * is checked by the caller (TUC_KON_218 step 3); if the card denies access (6982), 4085 follows.
   */
  public byte[] sign(CardObject card, Key key, byte[] hash) {
    return sign(card, key, hash, null);
  }

  /**
   * Like {@link #sign(CardObject, Key, byte[])}, with {@code channel} in the trusted channel (SE
   * #2, TUC_KON_154 step 2, TUC_KON_158 step 4, LIANA-112.13): without SELECT, MSE SET DST and PSO
   * CDS secured; the DF is already selected, a command without secure messaging would end the
   * channel.
   */
  public byte[] sign(CardObject card, Key key, byte[] hash, SecureChannel channel) {
    CardTerminal terminal = terminal(card);
    try {
      if (channel == null) {
        select(terminal, card, key);
      }
      expect(
          transmit(
              terminal,
              card,
              channel,
              HEX.parseHex(MSE_SET_DST.formatted(0x80 | key.keyIdentifier, key.algorithm))),
          "MSE SET DST");
      byte[] response =
          transmit(
              terminal,
              card,
              channel,
              HEX.parseHex(
                  PSO_CDS + HEX.toHexDigits((byte) hash.length) + HEX.formatHex(hash) + "00"));
      expect(response, "PSO COMPUTE DIGITAL SIGNATURE");
      byte[] signature = Arrays.copyOf(response, response.length - 2);
      return key.rsa() ? signature : ecdsaSigValue(signature);
    } catch (IOException e) {
      throw TerminalErrors.of(card, "Kartenzugriff", e);
    }
  }

  /**
   * Selects the DF of {@code key} so that a subsequent PIN check sets its DF-specific password
   * (TUC_KON_150 step 6 in DF.QES). Selecting the same DF again in {@link #sign} leaves the
   * security state in place.
   */
  public void enter(CardObject card, Key key) {
    CardTerminal terminal = terminal(card);
    try {
      select(terminal, card, key);
    } catch (IOException e) {
      throw TerminalErrors.of(card, "Kartenzugriff", e);
    }
  }

  /**
   * TUC_KON_150 step 8: leaves the DF (SELECT MF); the card thereby clears the DF-specific security
   * states, e.g. that of the PIN.QES (gemSpec_COS). Also runs in the error case (a) and reports no
   * error itself: if the card is removed or the CT gone, there is no state left to reset.
   */
  public void leave(CardObject card) {
    terminals
        .terminal(card.ctId())
        .ifPresent(
            terminal -> {
              try {
                terminal.transmit(card.slotNo(), HEX.parseHex(SELECT_MF));
              } catch (IOException | RuntimeException e) {
                // nothing to reset
              }
            });
  }

  private static byte[] transmit(
      CardTerminal terminal, CardObject card, SecureChannel channel, byte[] command)
      throws IOException {
    return channel == null
        ? terminal.transmit(card.slotNo(), command)
        : channel.transmit(terminal, card.slotNo(), command);
  }

  private CardTerminal terminal(CardObject card) {
    return terminals
        .terminal(card.ctId())
        .orElseThrow(() -> ConnectorError.CT_ACCESS.exception(card.ctId()));
  }

  private static void select(CardTerminal terminal, CardObject card, Key key) throws IOException {
    expect(
        terminal.transmit(
            card.slotNo(),
            HEX.parseHex(SELECT_AID + HEX.toHexDigits((byte) (key.df.length() / 2)) + key.df)),
        "SELECT " + key.df);
  }

  private static void expect(byte[] response, String command) {
    int n = response.length;
    String sw = n < 2 ? "" : HEX.formatHex(response, n - 2, n);
    if (sw.equals("6982")) {
      throw ConnectorError.ACCESS_CONDITIONS.exception(command + ": " + sw);
    }
    if (!sw.equals("9000")) {
      throw ConnectorError.CT_ACCESS.exception(command + ": " + sw);
    }
  }

  /** ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER } from (r, s) of equal length. */
  static byte[] ecdsaSigValue(byte[] plain) {
    if (plain.length == 0 || plain.length % 2 != 0) {
      throw ConnectorError.CT_ACCESS.exception("Signatur der Karte hat " + plain.length + " Byte");
    }
    int half = plain.length / 2;
    byte[] r = new BigInteger(1, Arrays.copyOfRange(plain, 0, half)).toByteArray();
    byte[] s = new BigInteger(1, Arrays.copyOfRange(plain, half, plain.length)).toByteArray();
    ByteArrayOutputStream content = new ByteArrayOutputStream();
    content.write(0x02);
    content.write(r.length);
    content.writeBytes(r);
    content.write(0x02);
    content.write(s.length);
    content.writeBytes(s);
    ByteArrayOutputStream sequence = new ByteArrayOutputStream();
    sequence.write(0x30);
    sequence.write(content.size());
    sequence.writeBytes(content.toByteArray());
    return sequence.toByteArray();
  }
}

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
import de.gematik.liana.kern.terminal.TerminalRegistry;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.regex.Pattern;
import javax.naming.ldap.Rdn;

/**
 * Accesses of the Fachmodule to the eGK: TUC_KON_018 „eGK-Sperrung prüfen“ and TUC_KON_202
 * „LeseDatei“ for the files in DF.HCA (gemSpec_eGK_ObjSys 5.4). The check for a foreign card lock
 * (TUC_KON_018 step 2) is done by the caller that reserves the card.
 */
public final class EgkFiles {

  /** DF.HCA, EF.PD, EF.VD and EF.StatusVD (Tab_eGK_ObjSys_037, 042, 040): SFI 01, 02 and 0C. */
  public static final int EF_PD = 0x01;

  public static final int EF_VD = 0x02;
  public static final int EF_STATUS_VD = 0x0C;

  private static final HexFormat HEX = HexFormat.of().withUpperCase();
  private static final Pattern PROVIDER_ID = Pattern.compile("[0-9]{9}");
  private static final String SELECT_DF_HCA = "00A4040C06D27600000102";
  private static final String SELECT_DF_ESIGN = "00A4040C0AA000000167455349474E";

  /**
   * EF.C.CH.AUT.E256 (SFI 04) or EF.C.CH.AUT.R2048 (SFI 01) in DF.ESIGN, extended length as in the
   * CardReader.
   */
  private static final String READ_C_CH_AUT_E256 = "00B08400000000";

  private static final String READ_C_CH_AUT_R2048 = "00B08100000000";

  /**
   * Result of TUC_KON_018 with checkHcaOnly=false: DF.HCA blocked and, if not, why C.CH.AUT is
   * invalid offline ({@code null} if valid). LIANA does not determine the revocation status (OCSP);
   * it cannot be determined. In addition the ProviderID from C.CH.AUT for locating the specialist
   * service ([gemSpec_FM_VSDM] 4.3.3, TUC_KON_034), {@code null} without a readable certificate or
   * without an OU of nine digits.
   */
  public record Blocking(boolean hcaBlocked, String autOfflineInvalid, String providerId) {

    /** Step 7: card blocked. */
    public boolean blocked() {
      return hcaBlocked || autOfflineInvalid != null;
    }
  }

  private final TerminalRegistry terminals;
  private final CertificateCheck certificates;

  public EgkFiles(TerminalRegistry terminals, CertificateCheck certificates) {
    this.terminals = terminals;
    this.certificates = certificates;
  }

  /**
   * TUC_KON_018 steps 3–7: DF.HCA is blocked if SELECT does not return 9000 (a deactivated DF
   * reports 6283). From G2.1, C.CH.AUT is the ECC certificate, for G2.0 the RSA certificate (step
   * 5); as in the {@link CardReader}, the ECC certificate applies if the card has one. If both are
   * missing, C.CH.AUT is invalid.
   */
  public Blocking checkBlocking(CardObject egk) {
    CardTerminal terminal = terminal(egk);
    try {
      boolean hcaBlocked = !ok(terminal.transmit(egk.slotNo(), HEX.parseHex(SELECT_DF_HCA)));
      if (!ok(terminal.transmit(egk.slotNo(), HEX.parseHex(SELECT_DF_ESIGN)))) {
        return new Blocking(hcaBlocked, "DF.ESIGN nicht wählbar", null);
      }
      byte[] der = data(terminal.transmit(egk.slotNo(), HEX.parseHex(READ_C_CH_AUT_E256)));
      if (der == null) {
        der = data(terminal.transmit(egk.slotNo(), HEX.parseHex(READ_C_CH_AUT_R2048)));
      }
      if (der == null) {
        return new Blocking(hcaBlocked, "kein C.CH.AUT in DF.ESIGN", null);
      }
      return new Blocking(hcaBlocked, certificates.offlineInvalid(der), providerId(der));
    } catch (IOException e) {
      throw TerminalErrors.of(egk, "eGK-Sperrung prüfen", e);
    }
  }

  /**
   * TUC_KON_202 for a file in DF.HCA: select DF.HCA, read the whole file via SFI (extended length).
   * {@code null} if DF.HCA or the file is not readable.
   */
  public byte[] readHca(CardObject egk, int sfi) {
    CardTerminal terminal = terminal(egk);
    try {
      if (!ok(terminal.transmit(egk.slotNo(), HEX.parseHex(SELECT_DF_HCA)))) {
        return null;
      }
      return data(
          terminal.transmit(
              egk.slotNo(),
              HEX.parseHex("00B0" + HEX.toHexDigits((byte) (0x80 | sfi)) + "00000000")));
    } catch (IOException e) {
      throw TerminalErrors.of(egk, "LeseDatei", e);
    }
  }

  /**
   * The OU attribute with nine digits in the subject of C.CH.AUT (besides the one with the
   * unchangeable part of the KVNR).
   */
  static String providerId(byte[] der) {
    X509Certificate certificate = CardReader.certificate(der);
    if (certificate == null) {
      return null;
    }
    for (Rdn rdn : CardReader.subject(certificate).getRdns()) {
      if (rdn.getType().equalsIgnoreCase("OU")
          && PROVIDER_ID.matcher(String.valueOf(rdn.getValue())).matches()) {
        return String.valueOf(rdn.getValue());
      }
    }
    return null;
  }

  private CardTerminal terminal(CardObject card) {
    return terminals
        .terminal(card.ctId())
        .orElseThrow(() -> ConnectorError.CT_ACCESS.exception(card.ctId()));
  }

  private static boolean ok(byte[] response) {
    int n = response.length;
    return n == 2 && response[0] == (byte) 0x90 && response[1] == 0x00;
  }

  /** Data of a READ BINARY response with 9000, otherwise {@code null}. */
  private static byte[] data(byte[] response) {
    int n = response.length;
    if (n < 2 || response[n - 2] != (byte) 0x90 || response[n - 1] != 0x00) {
      return null;
    }
    return Arrays.copyOf(response, n - 2);
  }
}

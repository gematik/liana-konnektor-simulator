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
import de.gematik.liana.kern.terminal.TerminalRegistry;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/**
 * ReadCardCertificate (TIP1-A_4700-03, TAB_KON_678/679) with TUC_KON_216 „LeseZertifikat“: X.509
 * certificates of an SM-B or an HBAx. The file is determined by TAB_KON_858, the SFIs by
 * gemSpec_SMC-B_ObjSys 5.4.2 or the HBA object system 4.7.1 (image hba-valid; gemSpec_HBA_ObjSys is
 * not in the repo).
 *
 * <p>Crypt defaults to ECC, also for SMC-B G2.0, which LIANA does not distinguish from G2.1.
 */
public final class CardCertificates {

  private static final HexFormat HEX = HexFormat.of().withUpperCase();
  private static final String DF_ESIGN = "A000000167455349474E";
  private static final String DF_QES = "D27600006601";
  private static final List<String> CRYPT = List.of("RSA", "ECC");

  /** Certificate file: DF (AID) and SFI per Crypt. */
  private record File(String df, int rsa, int ecc) {}

  /** TAB_KON_858 for SM-B: CertRef → SFI in DF.ESIGN per Crypt (RSA, ECC). */
  private static final Map<String, File> SMC_B =
      Map.of(
          "C.AUT", new File(DF_ESIGN, 0x01, 0x06),
          "C.ENC", new File(DF_ESIGN, 0x02, 0x05),
          "C.SIG", new File(DF_ESIGN, 0x10, 0x07));

  /**
   * TAB_KON_858 for HBA: C.HP.AUT and C.HP.ENC in DF.ESIGN, C.HP.QES in DF.QES (AID D27600006601),
   * per Crypt (RSA, ECC).
   */
  private static final Map<String, File> HBA =
      Map.of(
          "C.AUT", new File(DF_ESIGN, 0x01, 0x06),
          "C.ENC", new File(DF_ESIGN, 0x02, 0x05),
          "C.QES", new File(DF_QES, 0x10, 0x06));

  /**
   * C.SMKT.AUT of the gSMC-KT in DF.KT (AID D27600014400): RSA SFI 01, ECC SFI 04 (image
   * gsmckt-root6, LIANA-188).
   */
  private static final File SMC_KT_AUT = new File("D27600014400", 0x01, 0x04);

  /** A certificate read (DER) for the requested reference. */
  public record Certificate(String certRef, byte[] der) {}

  private final CardAccess access;
  private final TerminalRegistry terminals;

  public CardCertificates(CardAccess access, TerminalRegistry terminals) {
    this.access = access;
    this.terminals = terminals;
  }

  /** TAB_KON_679; {@code crypt} is {@code null} for the default. */
  public List<Certificate> read(
      Context context, String cardHandle, List<String> certRefs, String crypt) {
    if (certRefs == null || certRefs.isEmpty() || (crypt != null && !CRYPT.contains(crypt))) {
      throw ConnectorError.SYNTAX.exception("CertRefList leer oder Crypt '" + crypt + "'");
    }
    CardObject card = access.card(context, cardHandle);
    if (card.data().type() == CardType.EGK) {
      throw ConnectorError.EGK_ACCESS_DENIED.exception(cardHandle);
    }
    // TAB_KON_679 step 3: TUC_KON_026 (4093 on a foreign card lock, A_25895)
    access.checkFree(card);
    String effective = crypt == null ? "ECC" : crypt;
    List<Certificate> result = new ArrayList<>();
    for (String certRef : certRefs) {
      result.add(new Certificate(certRef, read(card, certRef, effective)));
    }
    return List.copyOf(result);
  }

  /**
   * TUC_KON_216 for a card already checked per TUC_KON_000: the certificate {@code certRef}
   * (TAB_KON_858) for {@code crypt} (RSA, ECC) as DER.
   */
  public byte[] read(CardObject card, String certRef, String crypt) {
    Map<String, File> files =
        card.data().type() == CardType.SMC_B
            ? SMC_B
            : card.data().type().matches("HBAx") ? HBA : Map.of();
    File file = files.get(certRef);
    if (file == null) {
      throw ConnectorError.INVALID_CERT_REF.exception(
          certRef + " für " + card.data().type().value());
    }
    byte[] der = readCertificate(card, file.df(), crypt.equals("RSA") ? file.rsa() : file.ecc());
    if (der == null) {
      // TUC_KON_216 warning 4256 → 4258
      throw ConnectorError.CERT_NOT_ON_CARD.exception(
          ConnectorError.CERT_NOT_ON_CARD
              .text()
              .replace("<$Crypt>", crypt)
              .replace("<cardHandle>", card.cardHandle()),
          certRef);
    }
    return der;
  }

  /**
   * TUC_KON_033 step 1: the AUT certificate of a card already checked per TUC_KON_000 for {@code
   * crypt} (RSA, ECC) as DER: for the HBAx C.HP.AUT, for the SM-B C.HCI.AUT, for the gSMC-KT
   * C.SMKT.AUT; {@code null} if the card has none (warning 4257).
   */
  public byte[] aut(CardObject card, String crypt) {
    File file =
        card.data().type() == CardType.SMC_KT
            ? SMC_KT_AUT
            : card.data().type() == CardType.SMC_B
                ? SMC_B.get("C.AUT")
                : card.data().type().matches("HBAx") ? HBA.get("C.AUT") : null;
    if (file == null) {
      throw ConnectorError.CALL_NOT_ALLOWED.exception(
          card.data().type().value() + " " + card.cardHandle());
    }
    return readCertificate(card, file.df(), crypt.equals("RSA") ? file.rsa() : file.ecc());
  }

  /** TUC_KON_216: select the DF, read the file via SFI; {@code null} if it is missing or empty. */
  private byte[] readCertificate(CardObject card, String df, int sfi) {
    CardTerminal terminal =
        terminals
            .terminal(card.ctId())
            .orElseThrow(() -> ConnectorError.CT_ACCESS.exception(card.ctId()));
    try {
      byte[] select =
          terminal.transmit(
              card.slotNo(),
              HEX.parseHex("00A4040C" + HEX.toHexDigits((byte) (df.length() / 2)) + df));
      if (!ok(select)) {
        return null;
      }
      byte[] response =
          terminal.transmit(
              card.slotNo(),
              HEX.parseHex("00B0" + HEX.toHexDigits((byte) (0x80 | sfi)) + "00000000"));
      return ok(response) && response.length > 2
          ? Arrays.copyOf(response, response.length - 2)
          : null;
    } catch (IOException e) {
      throw TerminalErrors.of(card, "Kartenzugriff", e);
    }
  }

  private static boolean ok(byte[] response) {
    int n = response.length;
    return n >= 2 && response[n - 2] == (byte) 0x90 && response[n - 1] == 0x00;
  }
}

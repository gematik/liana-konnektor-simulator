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
import java.io.IOException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * QES in SE #2 of the HBA via trusted channels (LIANA-112.13): TUC_KON_154 (TIP1-A_4651-03) and
 * TUC_KON_158 (A_19102-05, A_19258) send the DTBS in the secure channel gSMC-K↔HBA ({@link
 * CardToCard.Source#GSMC_K}); PSO CDS with PrK.HP.QES.E256 requires AND{PWD(81),
 * SMMAC(cvc_FlagList_TI:…01), SMCMDENC, SMRSPENC} there. The HBA verifies the PIN.QES in SE #2 only
 * under SMMAC(cvc_FlagList_TI:…02), i.e. in the remote PIN procedure (TIP1-A_5012) via the CT's
 * gSMC-KT ({@link CardToCard.Source#GSMC_KT}); MSE RESTORE clears a previously verified PIN.QES
 * (gemSpec_COS G2_N104.200.c).
 *
 * <p>Flow in DF.QES: {@link #environment} SE #2, {@link #remotePin} and PIN.QES in the channel,
 * {@link #signing} and PSO CDS in the channel. LIANA computes the C2C in DF.QES; {@link #prepare}
 * reads the HBA's CVC beforehand in the MF and keeps it for the card session (TUC_KON_154 security
 * requirements). SELECT MF on leaving resets DF.QES to SE #1 (G2_N048.200.b.4).
 *
 * <p>If a prerequisite is missing (gSMC-K image, gSMC-KT of the CT, PIN entry in the channel at the
 * CT, CVC on the HBA), LIANA signs as before in SE #1 without secure messaging (single signature
 * mode) and writes the reason to the log.
 */
public final class TrustedChannels {

  private static final System.Logger LOG = System.getLogger(TrustedChannels.class.getName());
  private static final HexFormat HEX = HexFormat.of().withUpperCase();

  /** SELECT MF without data (gemSpec_COS 14.2.6.1). */
  private static final String SELECT_MF = "00A4000C";

  /**
   * READ BINARY of EF.C.HPC.AUTD_SUK_CVC.E256 via SFI 09 in the MF (images; gemSpec_HBA_ObjSys is
   * missing), Le extended.
   */
  private static final String READ_SUK_CVC = "00B08900000000";

  /**
   * PrK.HPC.AUTD_SUK_CVC.E256 in the MF, keyIdentifier 09 (global, without '80'), as in the PoPP
   * service's MSE SET AT.
   */
  private static final int SUK_KEY = 0x09;

  /** MSE RESTORE (gemSpec_COS CosT_6fc, A_16946) with seNo. */
  private static final String MSE_RESTORE = "0022F3%02X";

  private final TerminalRegistry terminals;
  private final CardToCard c2c;
  private final Map<String, CardToCard.Target> cvcs = new ConcurrentHashMap<>();

  public TrustedChannels(TerminalRegistry terminals, CardToCard c2c) {
    this.terminals = terminals;
    this.c2c = c2c;
  }

  /**
   * Before DF.QES: whether the HBA {@code card} can sign in SE #2. For this it reads
   * EF.C.HPC.AUTD_SUK_CVC.E256 once per card session (SELECT MF). Empty means SE #1 without secure
   * messaging.
   */
  public Optional<CardToCard.Target> prepare(CardObject card) {
    CardTerminal terminal = terminal(card);
    StringBuilder why = new StringBuilder();
    if (!c2c.available(CardToCard.Source.GSMC_K, card.ctId(), why)
        || !c2c.available(CardToCard.Source.GSMC_KT, card.ctId(), why)) {
      return fallback(card, why.toString());
    }
    if (!terminal.securePinEntry()) {
      return fallback(
          card, card.ctId() + ": keine PIN-Eingabe im Trusted Channel (Remote-PIN, TIP1-A_5012)");
    }
    CardToCard.Target cached = cvcs.get(card.cardHandle());
    if (cached != null) {
      return Optional.of(cached);
    }
    try {
      ok(terminal.transmit(card.slotNo(), HEX.parseHex(SELECT_MF)), "SELECT MF");
      byte[] response = terminal.transmit(card.slotNo(), HEX.parseHex(READ_SUK_CVC));
      if (!isOk(response) || response.length <= 2) {
        return fallback(card, "EF.C.HPC.AUTD_SUK_CVC.E256 nicht lesbar (" + status(response) + ")");
      }
      CardToCard.Target target =
          new CardToCard.Target(Arrays.copyOf(response, response.length - 2), SUK_KEY);
      cvcs.put(card.cardHandle(), target);
      return Optional.of(target);
    } catch (IOException e) {
      throw TerminalErrors.of(card, "Kartenzugriff", e);
    }
  }

  /** In DF.QES: MSE RESTORE with {@code se} (1 or 2). */
  public void environment(CardObject card, int se) {
    try {
      ok(
          terminal(card).transmit(card.slotNo(), HEX.parseHex(MSE_RESTORE.formatted(se))),
          "MSE RESTORE " + se);
    } catch (IOException e) {
      throw TerminalErrors.of(card, "Kartenzugriff", e);
    }
  }

  /** TIP1-A_5012 step 1: trusted channel gSMC-KT↔HBA for the PIN.QES in SE #2. */
  public SecureChannel remotePin(CardObject card, CardToCard.Target target) {
    return authenticate(card, CardToCard.Source.GSMC_KT, target);
  }

  /** TUC_KON_154 or TUC_KON_158 step 1: trusted channel gSMC-K↔HBA for PSO CDS in SE #2. */
  public SecureChannel signing(CardObject card, CardToCard.Target target) {
    return authenticate(card, CardToCard.Source.GSMC_K, target);
  }

  private SecureChannel authenticate(
      CardObject card, CardToCard.Source source, CardToCard.Target target) {
    try {
      return c2c.authenticate(source, terminal(card), card.slotNo(), target);
    } catch (IOException e) {
      throw TerminalErrors.of(card, "TUC_KON_005", e);
    }
  }

  private static Optional<CardToCard.Target> fallback(CardObject card, String why) {
    LOG.log(
        System.Logger.Level.WARNING,
        "{0}/{1}: QES im SE #1 ohne Secure Messaging, {2} (LIANA-112.13)",
        card.ctId(),
        card.slotNo(),
        why);
    return Optional.empty();
  }

  private CardTerminal terminal(CardObject card) {
    return terminals
        .terminal(card.ctId())
        .orElseThrow(() -> ConnectorError.CT_ACCESS.exception(card.ctId()));
  }

  private static void ok(byte[] response, String command) {
    if (!isOk(response)) {
      throw ConnectorError.CT_ACCESS.exception(command + ": " + status(response));
    }
  }

  private static boolean isOk(byte[] response) {
    int n = response.length;
    return n >= 2 && response[n - 2] == (byte) 0x90 && response[n - 1] == 0x00;
  }

  private static String status(byte[] response) {
    int n = response.length;
    return n < 2 ? "" : HEX.formatHex(response, n - 2, n);
  }
}

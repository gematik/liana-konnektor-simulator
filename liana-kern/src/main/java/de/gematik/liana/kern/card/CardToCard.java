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

import de.gematik.liana.kern.terminal.CardTerminal;
import de.gematik.liana.kern.terminal.SecureChannel;
import java.io.IOException;

/**
 * Port: TUC_KON_005 „Card-to-Card authentisieren“ (TIP1-A_4572) with authMode „gegenseitig+TC“
 * (TAB_KON_673, gemSpec_COS 15.4 elcSessionkey4SM) to the HBA as target card (LIANA-112.13). LIANA
 * computes the source card itself, with the keys from its image; the target card receives the
 * source card's CVC chain via PSO VERIFY CERTIFICATE, via cross CV certificates from the TSL if it
 * lacks the root (variant 9, '6A 88').
 */
public interface CardToCard {

  /** Source card and sKeyRef per TAB_KON_674. */
  enum Source {
    /** gSMC-K of the connector with SAK.AUTD_CVC.E256: DTBS transfer for QES. */
    GSMC_K,
    /** gSMC-KT of the card terminal with SMC.AUTD_RPS_CVC.E256: remote PIN. */
    GSMC_KT
  }

  /**
   * The target card: its end-entity CVC (HPC.AUTD_SUK_CVC.E256, CHR and public key) and the key
   * reference of the associated private key for MSE SET AT (tKeyRef).
   */
  record Target(byte[] cvc, int keyReference) {
    public Target {
      cvc = cvc.clone();
    }

    @Override
    public byte[] cvc() {
      return cvc.clone();
    }
  }

  /**
   * Whether LIANA has the source card {@code source} (gSMC-K image or the gSMC-KT of the CT {@code
   * ctId}); otherwise {@code why} gives the reason. Checks nothing on the target card.
   */
  boolean available(Source source, String ctId, StringBuilder why);

  /**
   * Establishes the trusted channel from {@code source} to the card in {@code slot} of {@code
   * terminal}. The current folder of the card stays as it is (TUC_KON_154: do not leave DF.QES).
   * Errors end with 4056, 4057 or 4048 (TAB_KON_535).
   */
  SecureChannel authenticate(Source source, CardTerminal terminal, int slot, Target target)
      throws IOException;
}

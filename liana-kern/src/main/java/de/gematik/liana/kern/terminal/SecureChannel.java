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

import java.io.IOException;

/**
 * Port: a trusted channel to a card per TUC_KON_005 „gegenseitig+TC“ (gemSpec_COS 15.4
 * elcSessionkey4SM, secure messaging per 13.2/13.3, LIANA-112.13). Every command goes to the card
 * with MAC and encrypted command data (SMMAC, SMCMDENC); the response comes back unwrapped. A
 * command without secure messaging to the same card ends the channel on the card (gemSpec_COS
 * G2_N031.600.a.1).
 */
public interface SecureChannel {

  /**
   * Sends the plaintext APDU {@code command} secured via {@code terminal} to the card in {@code
   * slot} and returns the response in plaintext including the status word. A response without valid
   * secure messaging ends the channel; if it is only a status word, it is returned unchanged,
   * otherwise {@link IOException}.
   */
  byte[] transmit(CardTerminal terminal, int slot, byte[] command) throws IOException;
}

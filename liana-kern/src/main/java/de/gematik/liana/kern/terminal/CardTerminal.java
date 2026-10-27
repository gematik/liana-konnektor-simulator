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
import java.time.Duration;

/**
 * Port: the connector's only view of a card terminal (decision-3). Adapters: in phase 0/1 the fake
 * terminal ({@code liana-adapter-fake-terminal}), from phase 2 SICCT. Slots are numbered from 1.
 */
public interface CardTerminal {

  /** CT.CTID */
  String id();

  /** Number of slots (CT.SLOTCOUNT). */
  int slots();

  /**
   * From now on reports every insertion and removal to {@code listener} (CT/SLOT_IN_USE,
   * CT/SLOT_FREE), including the replacement of a card as removal and insertion. The terminal does
   * not report cards already inserted.
   */
  void addSlotListener(SlotListener listener);

  /**
   * State of the CT for GetCardTerminals (TAB_KON_563), without querying the CT; default: values of
   * a fake CT ({@link CardTerminalInfo#fake}). Wrappers pass through the result of the wrapped CT.
   */
  default CardTerminalInfo info() {
    return CardTerminalInfo.fake(id(), slots());
  }

  /** Whether a card is inserted in {@code slot}. */
  boolean cardPresent(int slot);

  /** Resets the card in {@code slot} and returns its ATR. */
  byte[] reset(int slot) throws IOException;

  /**
   * Sends a command APDU to the card in {@code slot} and returns the response APDU including the
   * status word.
   */
  byte[] transmit(int slot, byte[] commandApdu) throws IOException;

  /**
   * PIN entry on the terminal's PIN pad and VERIFY to the card in {@code slot} (SICCT PERFORM
   * VERIFICATION, TUC_KON_012 7b): {@code pinReference} is P2 of the VERIFY command, {@code dialog}
   * the displays per TAB_KON_090. Returns the status word of the card (9000, 63Cx, 6983 …) or of
   * the terminal (6400 timeout, 6401 cancel, [SICCT] §5.19.6). The PIN itself never leaves the
   * terminal.
   */
  default byte[] verifyPin(int slot, int pinReference, PinDialog dialog) throws IOException {
    return pinCommand(slot, PinCommand.verify(pinReference, dialog));
  }

  /**
   * PIN operation on the terminal's PIN pad (LIANA-109): the user enters the secrets of {@code
   * command}, the terminal inserts them into the card command and sends it to the card in {@code
   * slot} (SICCT PERFORM VERIFICATION or MODIFY VERIFICATION DATA). Returns the status word of the
   * card or of the terminal (6400 timeout, 6401 cancel, 64A1 no card, [SICCT] §5.19.6/§5.20.6); a
   * non-matching repetition of the new PIN reports {@link PinMismatchException}.
   */
  default byte[] pinCommand(int slot, PinCommand command) throws IOException {
    throw new IOException(id() + ": kein PIN-Pad");
  }

  /**
   * Whether {@link #pinCommand} can send a command with {@link PinCommand#channel()} in the trusted
   * channel (remote PIN procedure TIP1-A_5012, LIANA-112.13): the fake terminal, whose gSMC-KT is
   * LIANA itself. An eHealth CT encrypts the PIN with its own gSMC-KT; LIANA does not implement
   * that. Wrappers pass the value through.
   */
  default boolean securePinEntry() {
    return false;
  }

  /**
   * TUC_KON_056 step 2 (SICCT REQUEST ICC, §5.13): prompts the user with {@code displayMessage} to
   * insert a card into {@code slot} and waits at most {@code wait} for it. If a card is already
   * inserted, nothing is displayed. Returns whether a card is inserted afterwards; {@code false}
   * means timeout (SICCT {@code 6200}). Default: a CT without display and user that only checks the
   * slot.
   */
  default boolean requestCard(int slot, String displayMessage, Duration wait) throws IOException {
    return cardPresent(slot);
  }

  /**
   * TUC_KON_057 step 3 (SICCT EJECT ICC, §5.14, Delivery: Mechanical Throw out): deactivates the
   * card in {@code slot}, prompts with {@code displayMessage} to remove it and waits at most {@code
   * wait}. An empty slot displays nothing. Returns whether the slot is free afterwards; {@code
   * false} means deactivated but not removed (SICCT {@code 6200}). Default: like {@link
   * #requestCard}, only checks the slot.
   */
  default boolean ejectCard(int slot, String displayMessage, Duration wait) throws IOException {
    return !cardPresent(slot);
  }
}

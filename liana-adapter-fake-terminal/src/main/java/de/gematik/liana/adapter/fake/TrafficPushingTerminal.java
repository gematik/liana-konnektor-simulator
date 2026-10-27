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
package de.gematik.liana.adapter.fake;

import de.gematik.liana.kern.terminal.CardTerminal;
import de.gematik.liana.kern.terminal.CardTerminalInfo;
import de.gematik.liana.kern.terminal.PinCommand;
import de.gematik.liana.kern.terminal.SlotListener;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;

/**
 * Card terminal that additionally reports every APDU to a Tiger proxy ({@link TrafficPush}).
 * Everything else goes unchanged to the actual terminal; if the APDU fails at the card, nothing is
 * reported.
 */
public final class TrafficPushingTerminal implements CardTerminal {

  private final CardTerminal terminal;
  private final TrafficPush push;

  public TrafficPushingTerminal(CardTerminal terminal, TrafficPush push) {
    this.terminal = terminal;
    this.push = push;
  }

  @Override
  public String id() {
    return terminal.id();
  }

  @Override
  public int slots() {
    return terminal.slots();
  }

  @Override
  public CardTerminalInfo info() {
    return terminal.info();
  }

  @Override
  public void addSlotListener(SlotListener listener) {
    terminal.addSlotListener(listener);
  }

  @Override
  public boolean cardPresent(int slot) {
    return terminal.cardPresent(slot);
  }

  @Override
  public byte[] reset(int slot) throws IOException {
    return terminal.reset(slot);
  }

  /**
   * Reported is the card command of the PIN operation (VERIFY, CHANGE REFERENCE DATA …) with masked
   * PIN blocks: the secrets do not belong in the Tiger log.
   */
  @Override
  public byte[] pinCommand(int slot, PinCommand command) throws IOException {
    Instant sent = Instant.now();
    byte[] response = terminal.pinCommand(slot, command);
    byte[] masked =
        HexFormat.of()
            .parseHex(
                HexFormat.of().formatHex(command.header())
                    + String.format("%02X", 8 * command.mode().blocks())
                    + "2FFFFFFFFFFFFFFF".repeat(command.mode().blocks()));
    push.apdu(terminal.id(), slot, masked, sent, response, Instant.now());
    return response;
  }

  @Override
  public boolean securePinEntry() {
    return terminal.securePinEntry();
  }

  @Override
  public boolean requestCard(int slot, String displayMessage, Duration wait) throws IOException {
    return terminal.requestCard(slot, displayMessage, wait);
  }

  @Override
  public boolean ejectCard(int slot, String displayMessage, Duration wait) throws IOException {
    return terminal.ejectCard(slot, displayMessage, wait);
  }

  @Override
  public byte[] transmit(int slot, byte[] commandApdu) throws IOException {
    Instant sent = Instant.now();
    byte[] response = terminal.transmit(slot, commandApdu);
    push.apdu(terminal.id(), slot, commandApdu, sent, response, Instant.now());
    return response;
  }
}

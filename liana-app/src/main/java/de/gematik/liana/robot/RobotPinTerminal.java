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
package de.gematik.liana.robot;

import de.gematik.liana.adapter.fake.PinInput;
import de.gematik.liana.kern.terminal.CardTerminal;
import de.gematik.liana.kern.terminal.CardTerminalInfo;
import de.gematik.liana.kern.terminal.PinCommand;
import de.gematik.liana.kern.terminal.SlotListener;
import java.io.IOException;
import java.time.Duration;

/**
 * An eHealth CT via kartos as robot terminal with a waiting PIN pad ({@code liana.robot.await-pin},
 * LIANA-112.15): before the PIN command one input of the robot per display, like the fake CT in
 * mode await. The first input goes into the PIN script of kartos; if cancel, timeout or an
 * incomplete input ends it, that one applies and LIANA waits for no further one. Only then does
 * PERFORM VERIFICATION or MODIFY VERIFICATION DATA go to the CT. If no input arrives in time or the
 * card is removed, the wrapper responds like the CT ({@code 6400} or {@code 64A1}, [SICCT]
 * §5.19.6), without a command to the CT. After the command it clears the PIN script of kartos so
 * that no input is left over for the next one. Everything else it passes through.
 */
final class RobotPinTerminal implements CardTerminal {

  private static final byte[] SW_TIMEOUT = {0x64, 0x00};
  private static final byte[] SW_NO_CARD = {0x64, (byte) 0xA1};

  private final CardTerminal terminal;
  private final KartosRobots.Kt robot;

  RobotPinTerminal(CardTerminal terminal, KartosRobots.Kt robot) {
    this.terminal = terminal;
    this.robot = robot;
  }

  @Override
  public byte[] pinCommand(int slot, PinCommand command) throws IOException {
    PinInput first = null;
    for (int i = 0; i < command.prompts().size(); i++) {
      PinInput input = robot.await(terminal, slot);
      if (input == null) {
        return (terminal.cardPresent(slot) ? SW_TIMEOUT : SW_NO_CARD).clone();
      }
      boolean aborts =
          switch (input.outcome()) {
            case CANCEL, TIMEOUT, INCOMPLETE -> true;
            default -> false;
          };
      if (first == null || aborts) {
        first = input;
      }
      if (aborts) {
        break;
      }
    }
    robot.script(slot, first);
    if (command.mode() != PinCommand.Mode.ONE) {
      // SicctTerminal repeats MODIFY VERIFICATION DATA after 6700 in the form kartos understands
      // (KARTOS_MODIFY_VERIFICATION_DATA); kartos consumes the input on the first attempt as well
      robot.script(slot, first);
    }
    try {
      return terminal.pinCommand(slot, command);
    } finally {
      robot.clearScript();
    }
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

  @Override
  public byte[] transmit(int slot, byte[] commandApdu) throws IOException {
    return terminal.transmit(slot, commandApdu);
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
}

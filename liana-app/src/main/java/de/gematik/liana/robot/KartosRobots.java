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

import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.liana.adapter.fake.PinInput;
import de.gematik.liana.config.LianaConfig;
import de.gematik.liana.kern.terminal.CardTerminal;
import jakarta.inject.Singleton;
import java.io.InterruptedIOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import org.jboss.logging.Logger;

/**
 * Robot terminals that are eHealth CTs (LIANA-112.15): {@code kartos terminal} via SICCT, cards and
 * PIN pad via its control interface ({@code infrastructure.terminals.<KT>.control}, {@link
 * KartosControl}). With {@code liana.robot.await-pin} the PIN pad waits for the robot's input as
 * with the fake CT: {@link RobotPinTerminal} holds PERFORM VERIFICATION or MODIFY VERIFICATION DATA
 * until there is one input per display, puts the first one (on cancel or timeout that one) into the
 * PIN script of kartos and then sends the SICCT command; kartos enters the PIN itself. Without the
 * switch every input goes straight into the PIN script, for the next PIN command.
 *
 * <p>Mapping to the PIN script of kartos: {@code puk} and {@code transport} as {@code digits} with
 * the PUK or transport PIN of the CT ({@code infrastructure.terminals.<KT>.puk}, {@code
 * transport-pin}); kartos does not know {@code incomplete}, the CT would run into the timeout:
 * {@code timeout}. kartos enters the new PIN for MODIFY VERIFICATION DATA itself ({@code
 * TERMINAL_AUTO_PIN_MODIFY}).
 */
@Singleton
public class KartosRobots {

  private static final Logger LOG = Logger.getLogger(KartosRobots.class);

  /** How long the PIN pad waits for the input, like the fake CT (gemSpec_KT TIP1-A_3086). */
  static final Duration PIN_TIMEOUT = Duration.ofSeconds(30);

  private final Map<String, Kt> terminals = new LinkedHashMap<>();
  private final boolean awaitPin;

  KartosRobots(LianaConfig config, ObjectMapper json) {
    this.awaitPin = config.robot().awaitPin();
    if (config.robot().port().isEmpty()) {
      return;
    }
    for (String id : config.robot().terminals()) {
      LianaConfig.Terminal kt = config.infrastructure().terminals().get(id);
      if (kt != null && kt.type() == LianaConfig.Type.SICCT && kt.control().isPresent()) {
        KartosControl control = new KartosControl(kt.control().get(), json);
        terminals.put(id, new Kt(id, control, kt.puk(), kt.transportPin()));
        LOG.infof(
            "Robot-Terminal %s: kartos terminal, Steuerschnittstelle %s%s",
            id, control.base(), awaitPin ? ", PIN-Pad wartet auf den Robot" : "");
      }
    }
  }

  /** The robot terminal {@code ctId} if it is a kartos terminal. */
  Optional<Kt> terminal(String ctId) {
    return Optional.ofNullable(terminals.get(ctId));
  }

  /**
   * {@code terminal} with the waiting PIN pad if it is a robot terminal via kartos; otherwise
   * unchanged.
   */
  public CardTerminal wrap(CardTerminal terminal) {
    Kt kt = terminals.get(terminal.id());
    return kt == null || !awaitPin ? terminal : new RobotPinTerminal(terminal, kt);
  }

  /** Admin reset: forgets inputs that no PIN command has taken yet. */
  void reset() {
    terminals.values().forEach(Kt::reset);
  }

  /** A kartos terminal as robot terminal. */
  final class Kt {

    private final String id;
    private final KartosControl control;
    private final String puk;
    private final String transportPin;
    private final Deque<PinInput> inputs = new ArrayDeque<>();

    Kt(String id, KartosControl control, String puk, String transportPin) {
      this.id = id;
      this.control = control;
      this.puk = puk;
      this.transportPin = transportPin;
    }

    void insert(int slot, String iccsn, Path image) {
      control.insert(slot, iccsn, image);
    }

    void eject(int slot) {
      control.eject(slot);
    }

    /**
     * Input of the robot: to the waiting PIN pad, without {@code await-pin} straight into the PIN
     * script of kartos.
     */
    synchronized void enterPin(PinInput input) {
      if (!awaitPin) {
        script(null, input);
        return;
      }
      inputs.add(input);
      notifyAll();
    }

    /**
     * Next input of the robot for the PIN command at {@code slot}; {@code null} if {@link
     * #PIN_TIMEOUT} expires or the card is removed.
     */
    synchronized PinInput await(CardTerminal terminal, int slot) throws InterruptedIOException {
      long deadline = System.nanoTime() + PIN_TIMEOUT.toNanos();
      try {
        while (inputs.isEmpty()) {
          long left = deadline - System.nanoTime();
          if (left <= 0 || !terminal.cardPresent(slot)) {
            return null;
          }
          TimeUnit.NANOSECONDS.timedWait(this, Math.min(left, TimeUnit.MILLISECONDS.toNanos(200)));
        }
        return inputs.removeFirst();
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new InterruptedIOException(
            id + "/" + slot + ": Warten auf die PIN-Eingabe abgebrochen");
      }
    }

    /**
     * Puts {@code input} into the PIN script of kartos, for {@code slot} or ({@code null}) for any
     * slot.
     */
    void script(Integer slot, PinInput input) {
      LOG.infof(
          "Robot: PIN-Eingabe %s an %s%s (PIN-Script von kartos)",
          input, id, slot == null ? "" : "/" + slot);
      switch (input.outcome()) {
        case CORRECT -> control.script(slot, "correct", null);
        case WRONG -> control.script(slot, "wrong", null);
        case DIGITS -> control.script(slot, "digits", input.pin());
        case PUK -> control.script(slot, "digits", puk);
        case TRANSPORT -> control.script(slot, "digits", transportPin);
        case CANCEL -> control.script(slot, "cancel", null);
        case TIMEOUT, INCOMPLETE -> control.script(slot, "timeout", null);
      }
    }

    /** Clears the PIN script of kartos. */
    void clearScript() {
      control.clearScript();
    }

    private synchronized void reset() {
      inputs.clear();
    }
  }
}

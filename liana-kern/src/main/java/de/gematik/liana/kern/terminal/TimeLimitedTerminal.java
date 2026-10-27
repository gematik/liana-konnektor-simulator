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
import java.io.InterruptedIOException;
import java.time.Duration;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Supplier;

/**
 * CARD_TIMEOUT_CARD (TAB_KON_554): „Maximale Zeit, die ein Aufruf einer Kartenoperation dauern
 * darf, bevor der Aufruf abgebrochen wird.“ Every reset and every APDU to {@code terminal} runs at
 * most that long; then the call is interrupted and fails with {@link CardTimeoutException}, the
 * card TUCs report 4094 (TUC_KON_200 error cases).
 *
 * <p>PIN entry ({@link #pinCommand}) is exempt: it waits for the user, so the PIN entry timeout
 * applies (TUC_KON_012, 4043), not the card access. Likewise requesting and ejecting a card ({@link
 * #requestCard}, {@link #ejectCard}): there the caller's wait time applies (TUC_KON_056/057).
 */
public final class TimeLimitedTerminal implements CardTerminal {

  private static final ExecutorService CALLS = Executors.newVirtualThreadPerTaskExecutor();

  private interface Call {
    byte[] run() throws IOException;
  }

  private final CardTerminal terminal;
  private final Supplier<Duration> cardTimeout;

  public TimeLimitedTerminal(CardTerminal terminal, Duration cardTimeout) {
    this(terminal, () -> cardTimeout);
    if (cardTimeout.isNegative() || cardTimeout.isZero()) {
      throw new IllegalArgumentException("CARD_TIMEOUT_CARD muss positiv sein, ist " + cardTimeout);
    }
  }

  /** {@code cardTimeout} returns CARD_TIMEOUT_CARD per command, e.g. from the KMS parameters. */
  public TimeLimitedTerminal(CardTerminal terminal, Supplier<Duration> cardTimeout) {
    this.terminal = terminal;
    this.cardTimeout = cardTimeout;
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
    return limited(slot, "Reset", () -> terminal.reset(slot));
  }

  @Override
  public byte[] transmit(int slot, byte[] commandApdu) throws IOException {
    return limited(slot, "APDU", () -> terminal.transmit(slot, commandApdu));
  }

  @Override
  public byte[] pinCommand(int slot, PinCommand command) throws IOException {
    return terminal.pinCommand(slot, command);
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

  private byte[] limited(int slot, String what, Call call) throws IOException {
    Duration timeout = cardTimeout.get();
    Future<byte[]> future = CALLS.submit(call::run);
    try {
      return future.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
    } catch (TimeoutException e) {
      future.cancel(true);
      throw new CardTimeoutException(
          id()
              + "/"
              + slot
              + ": "
              + what
              + " ohne Antwort nach CARD_TIMEOUT_CARD "
              + timeout.toMillis()
              + " ms");
    } catch (InterruptedException e) {
      future.cancel(true);
      Thread.currentThread().interrupt();
      throw new InterruptedIOException(id() + "/" + slot + ": " + what + " unterbrochen");
    } catch (ExecutionException e) {
      switch (e.getCause()) {
        case IOException io -> throw io;
        case RuntimeException runtime -> throw runtime;
        case Error error -> throw error;
        default -> throw new IOException(e.getCause());
      }
    }
  }
}

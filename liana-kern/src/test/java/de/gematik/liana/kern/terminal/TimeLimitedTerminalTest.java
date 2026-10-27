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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class TimeLimitedTerminalTest {

  /** Terminal whose card needs {@code delay} per call; remembers whether a call was interrupted. */
  static final class SlowTerminal implements CardTerminal {
    volatile Duration delay = Duration.ZERO;
    final CountDownLatch interrupted = new CountDownLatch(1);

    @Override
    public String id() {
      return "KT-01";
    }

    @Override
    public int slots() {
      return 1;
    }

    @Override
    public void addSlotListener(SlotListener listener) {}

    @Override
    public boolean cardPresent(int slot) {
      return true;
    }

    @Override
    public byte[] reset(int slot) throws IOException {
      return answer(new byte[] {0x3B, 0x00});
    }

    @Override
    public byte[] transmit(int slot, byte[] commandApdu) throws IOException {
      if (commandApdu.length == 0) {
        throw new IOException("KT weg");
      }
      return answer(new byte[] {(byte) 0x90, 0x00});
    }

    @Override
    public byte[] pinCommand(int slot, PinCommand command) throws IOException {
      return answer(new byte[] {(byte) 0x90, 0x00});
    }

    private byte[] answer(byte[] response) throws IOException {
      try {
        Thread.sleep(delay);
      } catch (InterruptedException e) {
        interrupted.countDown();
        throw new IOException("unterbrochen");
      }
      return response;
    }
  }

  private final SlowTerminal slow = new SlowTerminal();
  private final TimeLimitedTerminal terminal =
      new TimeLimitedTerminal(slow, Duration.ofMillis(200));

  @Test
  @DisplayName(
      "TAB_KON_554 CARD_TIMEOUT_CARD: Antwort innerhalb der Frist kommt durch, Terminalfehler bleiben IOException")
  void innerhalbDerFrist() throws Exception {
    slow.delay = Duration.ofMillis(20);
    assertArrayEquals(new byte[] {0x3B, 0x00}, terminal.reset(1));
    assertArrayEquals(
        new byte[] {(byte) 0x90, 0x00}, terminal.transmit(1, new byte[] {0, (byte) 0xA4, 4, 0x0C}));
    IOException error = assertThrows(IOException.class, () -> terminal.transmit(1, new byte[0]));
    assertEquals("KT weg", error.getMessage());
    assertTrue(!(error instanceof CardTimeoutException));
  }

  @Test
  @DisplayName(
      "TUC_KON_200: Karte antwortet nicht innerhalb von CARD_TIMEOUT_CARD → CardTimeoutException, der Aufruf "
          + "an die Karte wird unterbrochen; gilt für Reset und APDU")
  void fristUeberschritten() throws Exception {
    slow.delay = Duration.ofSeconds(5);
    long start = System.nanoTime();
    assertThrows(
        CardTimeoutException.class,
        () -> terminal.transmit(1, new byte[] {0, (byte) 0xA4, 4, 0x0C}));
    long millis = Duration.ofNanos(System.nanoTime() - start).toMillis();
    assertTrue(millis >= 200 && millis < 2000, millis + " ms");
    assertTrue(slow.interrupted.await(1, TimeUnit.SECONDS));
    assertThrows(CardTimeoutException.class, () -> terminal.reset(1));
  }

  @Test
  @DisplayName(
      "TUC_KON_012: die PIN-Eingabe wartet auf den Nutzer und fällt nicht unter CARD_TIMEOUT_CARD")
  void pinEingabeAusgenommen() throws Exception {
    slow.delay = Duration.ofMillis(400);
    assertArrayEquals(
        new byte[] {(byte) 0x90, 0x00}, terminal.verifyPin(1, 1, PinDialog.pinSmc(1)));
  }

  @Test
  @DisplayName("CARD_TIMEOUT_CARD muss positiv sein")
  void positiv() {
    assertThrows(
        IllegalArgumentException.class, () -> new TimeLimitedTerminal(slow, Duration.ZERO));
  }
}

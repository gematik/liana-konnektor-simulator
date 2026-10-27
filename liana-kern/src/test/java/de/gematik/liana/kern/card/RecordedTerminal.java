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

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.gematik.liana.kern.terminal.CardTerminal;
import de.gematik.liana.kern.terminal.SlotListener;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HexFormat;
import java.util.List;

/**
 * Terminal without kartos: every inserted card plays back the recorded APDU sequence from {@code
 * apdu/egk-valid.txt}, {@link #reset} restarts it. Checks that exactly the recorded commands
 * arrive.
 */
public class RecordedTerminal implements CardTerminal {

  public static final Path EGK_VALID = Path.of("liana-kern/src/test/resources/apdu/egk-valid.txt");
  public static final Path SMCB_VALID =
      Path.of("liana-kern/src/test/resources/apdu/smcb-valid.txt");
  public static final Path HBA_VALID = Path.of("liana-kern/src/test/resources/apdu/hba-valid.txt");
  public static final Path HBA_VALID_OPS =
      Path.of("liana-kern/src/test/resources/apdu/hba-valid-ops.txt");
  public static final Path GSMCKT_ROOT6 =
      Path.of("liana-kern/src/test/resources/apdu/gsmckt-root6.txt");
  public static final Path SMCB_VALID_SIGN =
      Path.of("liana-kern/src/test/resources/apdu/smcb-valid-sign.txt");
  private static final HexFormat HEX = HexFormat.of().withUpperCase();

  private final String id;
  private final boolean[] present;
  private final List<String[]> recording;
  private final List<SlotListener> listeners = new ArrayList<>();
  final Deque<String[]> expected = new ArrayDeque<>();

  public RecordedTerminal(String id, int slots, Path recording) {
    this.id = id;
    this.present = new boolean[slots + 1];
    try {
      this.recording =
          Files.readAllLines(recording).stream()
              .filter(l -> !l.startsWith("#") && !l.isBlank())
              .map(l -> l.split(" "))
              .toList();
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
    expected.addAll(this.recording);
  }

  public void insert(int slot) {
    present[slot] = true;
    listeners.forEach(l -> l.slotInUse(id, slot));
  }

  public void eject(int slot) {
    present[slot] = false;
    listeners.forEach(l -> l.slotFree(id, slot));
  }

  @Override
  public String id() {
    return id;
  }

  @Override
  public int slots() {
    return present.length - 1;
  }

  @Override
  public void addSlotListener(SlotListener listener) {
    listeners.add(listener);
  }

  @Override
  public boolean cardPresent(int slot) {
    return present[slot];
  }

  @Override
  public byte[] reset(int slot) {
    expected.clear();
    expected.addAll(recording);
    return HEX.parseHex("3B00");
  }

  @Override
  public byte[] transmit(int slot, byte[] commandApdu) {
    String[] next = expected.poll();
    if (next == null) {
      throw new AssertionError("unerwartetes Kommando " + HEX.formatHex(commandApdu));
    }
    assertEquals(next[0], HEX.formatHex(commandApdu));
    return HEX.parseHex(next[1]);
  }
}

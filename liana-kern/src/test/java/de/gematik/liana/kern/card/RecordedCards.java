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
import de.gematik.liana.kern.terminal.NoCardException;
import de.gematik.liana.kern.terminal.PinCommand;
import de.gematik.liana.kern.terminal.PinDialog;
import de.gematik.liana.kern.terminal.SlotListener;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * CT whose slots hold recorded cards: each card answers the commands of its kartos recording
 * ({@link RecordedTerminal#EGK_VALID}, {@link RecordedTerminal#SMCB_VALID}) in any order, further
 * ones via {@link #answer}, everything else with 6D00. A command that occurs in several DFs (READ
 * BINARY via SFI) is answered by the card as in the recording, by the DF selected last. {@link
 * #sent} records the commands per slot. With {@link #hold} the APDUs of a slot hang until {@link
 * #release} frees them (concurrency).
 */
public final class RecordedCards implements CardTerminal {

  private static final HexFormat HEX = HexFormat.of().withUpperCase();
  private static final String SELECT_AID = "00A4040C";

  private final String id;
  private final Map<Integer, Map<String, String>> answers = new HashMap<>();
  private final List<SlotListener> listeners = new ArrayList<>();
  public final Map<Integer, List<String>> sent = new HashMap<>();
  private final Map<Integer, Gate> held = new ConcurrentHashMap<>();

  /** The last successfully selected SELECT (by AID) per slot. */
  private final Map<Integer, String> selected = new HashMap<>();

  /** Held slot: {@code arrived} counts the first waiting APDU, {@code released} frees it. */
  private record Gate(CountDownLatch arrived, CountDownLatch released) {}

  public RecordedCards(String id) {
    this.id = id;
  }

  /** Inserts the recorded card {@code recording} into {@code slot}. */
  public RecordedCards insert(int slot, Path recording) {
    answers.put(slot, new HashMap<>());
    selected.remove(slot);
    load(answers.get(slot), recording);
    sent.put(slot, new ArrayList<>());
    listeners.forEach(l -> l.slotInUse(id, slot));
    return this;
  }

  /** Further recording of the same card in {@code slot}, e.g. a signature. */
  public RecordedCards also(int slot, Path recording) {
    load(answers.get(slot), recording);
    return this;
  }

  /**
   * Reads the recording: each command on its own and under the DF the preceding SELECT selected.
   */
  private static void load(Map<String, String> card, Path recording) {
    try {
      String df = "";
      for (String[] line :
          Files.readAllLines(recording).stream()
              .filter(l -> !l.startsWith("#") && !l.isBlank())
              .map(l -> l.split(" "))
              .toList()) {
        card.put(line[0], line[1]);
        card.put(df + ">" + line[0], line[1]);
        if (line[0].startsWith(SELECT_AID) && line[1].endsWith("9000")) {
          df = line[0];
        }
      }
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  /** Removes the card from {@code slot}. */
  public void eject(int slot) {
    answers.remove(slot);
    listeners.forEach(l -> l.slotFree(id, slot));
  }

  /** APDUs to {@code slot} wait from now on until {@link #release} frees them. */
  void hold(int slot) {
    held.put(slot, new Gate(new CountDownLatch(1), new CountDownLatch(1)));
  }

  /** Waits at most 5 s until an APDU to {@code slot} is held; {@code false} if none came. */
  boolean awaitHeld(int slot) throws InterruptedException {
    return held.get(slot).arrived().await(5, TimeUnit.SECONDS);
  }

  /** Frees the held APDUs to {@code slot}. */
  void release(int slot) {
    held.remove(slot).released().countDown();
  }

  /** Additional or deviating response of the card in {@code slot}. */
  public void answer(int slot, String command, String response) {
    answers.get(slot).keySet().removeIf(key -> key.endsWith(">" + command));
    answers.get(slot).put(command, response);
  }

  @Override
  public String id() {
    return id;
  }

  @Override
  public int slots() {
    return 3;
  }

  @Override
  public void addSlotListener(SlotListener listener) {
    listeners.add(listener);
  }

  @Override
  public boolean cardPresent(int slot) {
    return answers.containsKey(slot);
  }

  @Override
  public byte[] reset(int slot) {
    if (!cardPresent(slot)) {
      throw new NoCardException(id, slot);
    }
    return HEX.parseHex("3B00");
  }

  /** Status word of the card for the PIN entry on the PIN pad; default 9000. */
  String pinAnswer = "9000";

  /** The terminal displays of the last PIN entry. */
  PinDialog pinDialog;

  /** All PIN operations on the PIN pad, in order. */
  final List<PinCommand> pinCommands = new ArrayList<>();

  /** Responses of the PIN pad in order: status word (hex) or {@link IOException}. */
  final java.util.Deque<Object> pinAnswers = new java.util.ArrayDeque<>();

  /**
   * PIN pad: records the operation (VERIFY as „PIN-Pad VERIFY P2=xx“, otherwise „PIN-Pad
   * &lt;Modus&gt; &lt;Kopf&gt;“) and answers with the next entry from {@link #pinAnswers}, without
   * an entry with {@link #pinAnswer}.
   */
  @Override
  public byte[] pinCommand(int slot, PinCommand command) throws IOException {
    if (!cardPresent(slot)) {
      throw new NoCardException(id, slot);
    }
    byte[] header = command.header();
    sent.get(slot)
        .add(
            header[1] == 0x20 && command.mode() == PinCommand.Mode.ONE
                ? "PIN-Pad VERIFY P2=" + String.format("%02X", header[3])
                : "PIN-Pad " + command);
    pinCommands.add(command);
    pinDialog = new PinDialog(command.prompts().getFirst(), command.success(), command.failure());
    Object answer = pinAnswers.isEmpty() ? pinAnswer : pinAnswers.removeFirst();
    if (answer instanceof IOException e) {
      throw e;
    }
    return HEX.parseHex((String) answer);
  }

  @Override
  public byte[] transmit(int slot, byte[] commandApdu) {
    if (!cardPresent(slot)) {
      throw new NoCardException(id, slot);
    }
    Gate gate = held.get(slot);
    if (gate != null) {
      gate.arrived().countDown();
      try {
        gate.released().await();
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      }
    }
    String command = HEX.formatHex(commandApdu);
    sent.get(slot).add(command);
    Map<String, String> card = answers.get(slot);
    String response =
        card.getOrDefault(
            selected.getOrDefault(slot, "") + ">" + command, card.getOrDefault(command, "6D00"));
    if (command.startsWith(SELECT_AID) && response.endsWith("9000")) {
      selected.put(slot, command);
    }
    return HEX.parseHex(response);
  }
}

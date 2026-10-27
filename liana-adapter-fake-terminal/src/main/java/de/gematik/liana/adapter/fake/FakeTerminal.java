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
import de.gematik.liana.kern.terminal.DisplayBusyException;
import de.gematik.liana.kern.terminal.NoCardException;
import de.gematik.liana.kern.terminal.PinCommand;
import de.gematik.liana.kern.terminal.PinMismatchException;
import de.gematik.liana.kern.terminal.SlotListener;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/**
 * Internal card terminal for phase 0/1 (decision-3). A card image is inserted; the card engine
 * starts the card only on the first {@link #reset} or {@link #transmit}, so JVM tests and dev mode
 * run without kartos. {@link #reset} restarts the card (cold start), removing terminates it.
 * Inserting and removing go as CT/SLOT_IN_USE and CT/SLOT_FREE to the {@link SlotListener}
 * (TIP1-A_4563, TIP1-A_4562).
 *
 * <p>A {@link Fault fault} can be set per slot (LIANA-41); it is attached to the slot, not to the
 * card, and affects reset, APDUs and PIN entry. A delay does not block the KT: the other slots
 * respond meanwhile, and an abort by the Konnektor (CARD_TIMEOUT_CARD) interrupts it without the
 * command reaching the card. An APDU also occupies only its card, not the KT: cards in different
 * slots work side by side. If the card is removed meanwhile, the APDU fails with an {@link
 * IOException}.
 *
 * <p>Request and eject card (LIANA-110): the display shows the prompt until the card is inserted or
 * removed (Admin API or Robot) or the waiting time expires; there is no user following the display.
 * Ejecting deactivates the card (card engine terminated) without removing it.
 *
 * <p>The KT runs a KVK (memory card, image with root {@code kvk}) itself, without card engine
 * ({@link KvkCard}, LIANA-113).
 *
 * <p>PIN pad (LIANA-68): {@link #pinCommand} takes the first {@link PinInput PIN input} for the
 * slot from the PIN script of the KT ({@link #enterPin}, Admin API or Robot), like the PIN script
 * of {@code kartos terminal}. Without input, the PIN pad types the configured PIN immediately; in
 * mode {@link #awaitPinInput(boolean) await} (Robot KTs) it waits for the input like a user, at
 * most {@link #pinTimeout(Duration)} (30 s, gemSpec_KT TIP1-A_3086), then {@code 6400}. The prompt
 * stays in the display for that time, if it is free; if the card is removed meanwhile, the KT
 * responds {@code 64A1}.
 */
public class FakeTerminal implements CardTerminal {

  /** PIN of the gematik test cards. */
  public static final String DEFAULT_PIN = "123456";

  /**
   * PUK of the gematik test cards (PIN.SMC and PIN.CH of the images of the eHealth KT suite, {@code
   * images_E2E_5V}).
   */
  public static final String DEFAULT_PUK = "12345678";

  /** Transport PIN of the {@code *_trans} images of the eHealth KT suite. */
  public static final String DEFAULT_TRANSPORT_PIN = "54321";

  /** gemSpec_KT TIP1-A_3086: the KT waits 30 s for the first character. */
  public static final Duration DEFAULT_PIN_TIMEOUT = Duration.ofSeconds(30);

  private static final byte[] SW_TIMEOUT = {0x64, 0x00};
  private static final byte[] SW_CANCEL = {0x64, 0x01};
  private static final byte[] SW_NO_CARD = {0x64, (byte) 0xA1};

  /**
   * A PIN input in the PIN script of the KT; {@code slotNo null} applies to the next PIN dialog at
   * any slot.
   */
  public record ScriptedPinInput(Integer slotNo, PinInput input) {}

  private final String id;
  private final int slots;
  private final CardEngine engine;
  private final String pin;
  private final String puk;
  private final String transportPin;
  private final Deque<ScriptedPinInput> pinScript = new ArrayDeque<>();
  private boolean awaitPinInput;
  private Duration pinTimeout = DEFAULT_PIN_TIMEOUT;
  private volatile Duration signatureTime = Duration.ZERO;
  private final Map<Integer, Inserted> inserted = new HashMap<>();
  private final Map<Integer, Fault> faults = new HashMap<>();
  private final List<SlotListener> listeners = new CopyOnWriteArrayList<>();

  /** Display during RequestCard/EjectCard, otherwise {@code null}. */
  private String display;

  private final List<Consumer<Optional<String>>> displayListeners = new CopyOnWriteArrayList<>();

  public FakeTerminal(String id, int slots, CardEngine engine) {
    this(id, slots, engine, DEFAULT_PIN);
  }

  public FakeTerminal(String id, int slots, CardEngine engine, String pin) {
    this(id, slots, engine, pin, DEFAULT_PUK, DEFAULT_TRANSPORT_PIN);
  }

  /**
   * {@code pin} is the PIN the simulated PIN pad “types” without other instruction; it enters
   * {@code puk} and {@code transportPin} for the PIN inputs {@link PinInput.Kind#PUK} and {@link
   * PinInput.Kind#TRANSPORT}.
   */
  public FakeTerminal(
      String id, int slots, CardEngine engine, String pin, String puk, String transportPin) {
    for (String digits : List.of(pin, puk, transportPin)) {
      if (!digits.matches("[0-9]{4,12}")) {
        throw new IllegalArgumentException(
            id + ": PIN, PUK und Transport-PIN müssen aus 4 bis 12 Ziffern bestehen");
      }
    }
    this.id = id;
    this.slots = slots;
    this.engine = engine;
    this.pin = pin;
    this.puk = puk;
    this.transportPin = transportPin;
  }

  @Override
  public String id() {
    return id;
  }

  @Override
  public int slots() {
    return slots;
  }

  @Override
  public void addSlotListener(SlotListener listener) {
    listeners.add(listener);
  }

  @Override
  public synchronized boolean cardPresent(int slot) {
    checkSlot(slot);
    return inserted.containsKey(slot);
  }

  /** Image of the card in {@code slot}, empty if the slot is free. */
  public synchronized Optional<Path> image(int slot) {
    checkSlot(slot);
    return Optional.ofNullable(inserted.get(slot)).map(Inserted::image);
  }

  /**
   * Inserts a card; an occupied slot must be cleared first. The {@link SlotListener} run outside
   * the KT lock: they read the card (TUC_KON_001), possibly from another thread
   * (CARD_TIMEOUT_CARD).
   */
  public void insert(int slot, Path image) {
    synchronized (this) {
      checkSlot(slot);
      if (inserted.containsKey(slot)) {
        throw new IllegalStateException(id + "/" + slot + ": Slot ist belegt");
      }
      inserted.put(slot, new Inserted(image));
      notifyAll();
    }
    listeners.forEach(l -> l.slotInUse(id, slot));
  }

  /**
   * Removes the card and terminates it in the card engine; the {@link SlotListener} run outside the
   * KT lock.
   */
  public void eject(int slot) {
    synchronized (this) {
      checkSlot(slot);
      Inserted card = inserted.remove(slot);
      if (card == null) {
        throw new NoCardException(id, slot);
      }
      card.stop();
      notifyAll();
    }
    listeners.forEach(l -> l.slotFree(id, slot));
  }

  @Override
  public byte[] reset(int slot) throws IOException {
    disturb(slot, null);
    synchronized (this) {
      Inserted card = card(slot);
      card.stop();
      return card.running().atr();
    }
  }

  @Override
  public byte[] transmit(int slot, byte[] commandApdu) throws IOException {
    byte[] statusWord = disturb(slot, commandApdu);
    if (statusWord != null) {
      return statusWord;
    }
    Card card;
    synchronized (this) {
      card = card(slot).running();
    }
    // outside the KT lock: the card serialises its APDUs itself, the other slots stay free
    // (LIANA-50)
    byte[] response = card.transmit(commandApdu);
    if (isPsoCds(commandApdu) && !signatureTime.isZero()) {
      try {
        Thread.sleep(signatureTime);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new InterruptedIOException(id + "/" + slot + ": Signatur abgebrochen");
      }
    }
    return response;
  }

  /**
   * Computation time of the card for PSO COMPUTE DIGITAL SIGNATURE (INS 2A, P1P2 9E9A, also under
   * secure messaging) by which the response is delayed; unlike {@link Fault faults} part of the
   * configuration, CATS and reset leave it in place. Default none.
   */
  public void signatureTime(Duration time) {
    if (time.isNegative()) {
      throw new IllegalArgumentException(id + ": Rechenzeit " + time + " ist negativ");
    }
    this.signatureTime = time;
  }

  private static boolean isPsoCds(byte[] command) {
    return command.length >= 4
        && command[1] == 0x2A
        && command[2] == (byte) 0x9E
        && command[3] == (byte) 0x9A;
  }

  /**
   * Simulated PIN pad (LIANA-68, LIANA-109): per requested secret the next PIN input for {@code
   * slot} ({@link PinInput}); the digits go to the card as format 2 PIN blocks in the card command,
   * the KT itself answers abort, timeout and removed card ([SICCT] §5.19.6, §5.20.6), without a
   * command to the card. With {@link PinCommand.Mode#OLD_NEW} and {@link PinCommand.Mode#NEW} the
   * repetition of the new PIN must be equal, otherwise {@link PinMismatchException}.
   */
  @Override
  public byte[] pinCommand(int slot, PinCommand command) throws IOException {
    List<String> secrets = new ArrayList<>();
    for (String prompt : command.prompts()) {
      PinInput input = awaitInput(slot, prompt, false);
      if (input != null && input.outcome() == PinInput.Outcome.INCOMPLETE) {
        // digits without confirmation: the KT keeps waiting until the time expires or the card is
        // removed
        input = awaitInput(slot, prompt, true);
      }
      if (input == null) {
        return (cardPresent(slot) ? SW_TIMEOUT : SW_NO_CARD).clone();
      }
      switch (input.outcome()) {
        case CANCEL -> {
          return SW_CANCEL.clone();
        }
        case TIMEOUT, INCOMPLETE -> {
          return SW_TIMEOUT.clone();
        }
        case CORRECT -> secrets.add(pin);
        case DIGITS -> secrets.add(input.pin());
        case WRONG -> secrets.add(wrong(pin));
        case PUK -> secrets.add(puk);
        case TRANSPORT -> secrets.add(transportPin);
      }
    }
    if (command.mode() != PinCommand.Mode.ONE) {
      String repeat = secrets.removeLast();
      if (!repeat.equals(secrets.getLast())) {
        throw new PinMismatchException(id + "/" + slot + ": " + command.mismatch());
      }
    }
    byte[] cardCommand = cardCommand(command.header(), secrets);
    // remote PIN procedure (TIP1-A_5012 steps 3 and 4): the gSMC-KT of the KT is LIANA, the command
    // goes to the
    // card with the encrypted PIN in the trusted channel
    return command.channel() == null
        ? transmit(slot, cardCommand)
        : command.channel().transmit(this, slot, cardCommand);
  }

  /** The gSMC-KT of the fake terminal is LIANA itself (TIP1-A_5012, LIANA-112.13). */
  @Override
  public boolean securePinEntry() {
    return true;
  }

  /**
   * The next input for {@code slot}; without input in the PIN script the configured PIN. In mode
   * await the PIN pad waits up to {@link #pinTimeout} with the prompt in the display, likewise
   * after an incomplete input ({@code incomplete}), but then accepts no further input. {@code null}
   * if the time expires or the card is removed.
   */
  private synchronized PinInput awaitInput(int slot, String prompt, boolean incomplete)
      throws IOException {
    card(slot);
    if (!incomplete) {
      Optional<PinInput> queued = take(slot);
      if (queued.isPresent() || !awaitPinInput) {
        return queued.orElse(PinInput.of(PinInput.Outcome.CORRECT));
      }
    }
    boolean showing = display == null;
    if (showing) {
      show(prompt);
    }
    long deadline = System.nanoTime() + pinTimeout.toNanos();
    try {
      while (inserted.containsKey(slot)) {
        Optional<PinInput> queued = incomplete ? Optional.empty() : take(slot);
        if (queued.isPresent()) {
          return queued.get();
        }
        long left = deadline - System.nanoTime();
        if (left <= 0) {
          return null;
        }
        TimeUnit.NANOSECONDS.timedWait(this, left);
      }
      return null;
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new InterruptedIOException(
          id + "/" + slot + ": Warten auf die PIN-Eingabe abgebrochen");
    } finally {
      if (showing) {
        show(null);
      }
    }
  }

  private Optional<PinInput> take(int slot) {
    for (var it = pinScript.iterator(); it.hasNext(); ) {
      ScriptedPinInput queued = it.next();
      if (queued.slotNo() == null || queued.slotNo() == slot) {
        it.remove();
        return Optional.of(queued.input());
      }
    }
    return Optional.empty();
  }

  /**
   * A wrong PIN of the same length as with kartos: each digit of the configured one incremented by
   * one.
   */
  static String wrong(String pin) {
    StringBuilder wrong = new StringBuilder();
    pin.chars().forEach(digit -> wrong.append((digit - '0' + 1) % 10));
    return wrong.toString();
  }

  /**
   * Appends PIN inputs to the PIN script; {@code slotNo} binds one to the PIN dialog of this slot,
   * {@code null} to the next one at any slot (Robot). A waiting PIN pad takes them immediately.
   * Invalid slots report {@link IllegalArgumentException}, then no input is appended.
   */
  public synchronized void enterPin(List<ScriptedPinInput> inputs) {
    inputs.stream().map(ScriptedPinInput::slotNo).filter(Objects::nonNull).forEach(this::checkSlot);
    pinScript.addAll(inputs);
    notifyAll();
  }

  /** {@link #enterPin(List)} with one input. */
  public void enterPin(Integer slotNo, PinInput input) {
    enterPin(List.of(new ScriptedPinInput(slotNo, input)));
  }

  /** The not yet consumed PIN inputs in the order in which the PIN pad takes them. */
  public synchronized List<ScriptedPinInput> pinScript() {
    return List.copyOf(pinScript);
  }

  /** Discards the PIN script. */
  public synchronized void clearPinScript() {
    pinScript.clear();
  }

  /**
   * Mode await: without input in the PIN script, the PIN pad waits for one instead of typing the
   * PIN itself.
   */
  public synchronized void awaitPinInput(boolean await) {
    this.awaitPinInput = await;
  }

  /** How long the PIN pad waits for an input (default {@link #DEFAULT_PIN_TIMEOUT}). */
  public synchronized void pinTimeout(Duration timeout) {
    this.pinTimeout = timeout;
  }

  /** What the display currently shows (prompt to insert or remove), empty without display. */
  /**
   * From now on reports every change of the display to {@code listener} (Admin API, LIANA-150);
   * called under the lock of the KT, the listener must not block.
   */
  public void addDisplayListener(Consumer<Optional<String>> listener) {
    displayListeners.add(listener);
  }

  private void show(String value) {
    if (!Objects.equals(display, value)) {
      display = value;
      displayListeners.forEach(listener -> listener.accept(Optional.ofNullable(value)));
    }
  }

  public synchronized Optional<String> display() {
    return Optional.ofNullable(display);
  }

  /**
   * Waits until a card is inserted in {@code slot}; the prompt stays in the display for that time.
   */
  @Override
  public boolean requestCard(int slot, String displayMessage, Duration wait) throws IOException {
    return await(slot, true, displayMessage, wait);
  }

  /**
   * Deactivates the card in {@code slot} and waits until it is removed; the prompt stays in the
   * display meanwhile.
   */
  @Override
  public boolean ejectCard(int slot, String displayMessage, Duration wait) throws IOException {
    synchronized (this) {
      checkSlot(slot);
      Inserted card = inserted.get(slot);
      if (card != null) {
        card.stop();
      }
    }
    return await(slot, false, displayMessage, wait);
  }

  /**
   * Waits at most {@code wait} until {@code slot} is occupied ({@code present}) or free; if it
   * already is, without display. A display shows one prompt at a time ({@link
   * DisplayBusyException}).
   */
  private synchronized boolean await(int slot, boolean present, String message, Duration wait)
      throws IOException {
    checkSlot(slot);
    if (inserted.containsKey(slot) == present) {
      return true;
    }
    if (display != null) {
      throw new DisplayBusyException(id + ": Display zeigt bereits „" + display + "“");
    }
    show(message);
    long deadline = System.nanoTime() + wait.toNanos();
    try {
      while (inserted.containsKey(slot) != present) {
        long left = deadline - System.nanoTime();
        if (left <= 0) {
          return false;
        }
        TimeUnit.NANOSECONDS.timedWait(this, left);
      }
      return true;
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new InterruptedIOException(id + "/" + slot + ": Warten auf den Anwender abgebrochen");
    } finally {
      show(null);
    }
  }

  /** Sets the fault of {@code slot}; an existing one is replaced. */
  public synchronized void fault(int slot, Fault fault) {
    checkSlot(slot);
    faults.put(slot, fault);
  }

  /** The fault of {@code slot}, empty if none is set or it is consumed. */
  public synchronized Optional<Fault> fault(int slot) {
    checkSlot(slot);
    return Optional.ofNullable(faults.get(slot));
  }

  /** Clears the fault of {@code slot}. */
  public synchronized void clearFault(int slot) {
    checkSlot(slot);
    faults.remove(slot);
  }

  /**
   * Applies the fault of {@code slot} to {@code command} ({@code null}: reset): throw IO errors,
   * wait for the delay, return a faulty status word; {@code null} if the card is to process the
   * command.
   */
  private byte[] disturb(int slot, byte[] command) throws IOException {
    Fault fault;
    synchronized (this) {
      card(slot);
      fault = faults.get(slot);
      if (fault == null || !fault.matches(command)) {
        return null;
      }
      Fault rest = fault.consumed();
      if (rest == null) {
        faults.remove(slot);
      } else {
        faults.put(slot, rest);
      }
    }
    switch (fault.type()) {
      case STATUS_WORD -> {
        return HexFormat.of().parseHex(fault.statusWord());
      }
      case RESPONSE -> {
        return HexFormat.of().parseHex(fault.response());
      }
      case IO_ERROR -> throw new IOException(id + "/" + slot + ": Störung io-error");
      case DELAY -> {
        try {
          Thread.sleep(fault.delay());
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
          throw new InterruptedIOException(id + "/" + slot + ": Verzögerung abgebrochen");
        }
        return null;
      }
      default -> throw new IllegalStateException(fault.type().toString());
    }
  }

  /** VERIFY {@code 00 20 00 <pinReference> 08 <format 2 PIN block>}. */
  static byte[] verifyCommand(int pinReference, String pin) {
    return cardCommand(new byte[] {0x00, 0x20, 0x00, (byte) pinReference}, List.of(pin));
  }

  /**
   * {@code header} (CLA INS P1 P2), Lc and per secret one format 2 PIN block (ISO 9564: 2, length,
   * digits, F…).
   */
  static byte[] cardCommand(byte[] header, List<String> secrets) {
    StringBuilder apdu =
        new StringBuilder(HexFormat.of().formatHex(header))
            .append("%02X".formatted(8 * secrets.size()));
    for (String secret : secrets) {
      StringBuilder block =
          new StringBuilder("2")
              .append(Integer.toHexString(secret.length()).toUpperCase())
              .append(secret);
      while (block.length() < 16) {
        block.append('F');
      }
      apdu.append(block);
    }
    return HexFormat.of().parseHex(apdu);
  }

  /** Removes all cards, clears all faults and discards the PIN inputs. */
  public void close() {
    List<Integer> slots;
    synchronized (this) {
      faults.clear();
      pinScript.clear();
      slots = List.copyOf(inserted.keySet());
    }
    slots.forEach(this::eject);
  }

  private Inserted card(int slot) {
    checkSlot(slot);
    Inserted card = inserted.get(slot);
    if (card == null) {
      throw new NoCardException(id, slot);
    }
    return card;
  }

  private void checkSlot(int slot) {
    if (slot < 1 || slot > slots) {
      throw new IllegalArgumentException(id + ": Slot " + slot + " außerhalb 1.." + slots);
    }
  }

  private final class Inserted {

    private final Path image;
    private Card card;

    Inserted(Path image) {
      this.image = image;
    }

    Path image() {
      return image;
    }

    Card running() throws IOException {
      if (card == null) {
        card = KvkCard.isKvk(image) ? KvkCard.open(image) : engine.open(image);
      }
      return card;
    }

    void stop() {
      if (card != null) {
        card.close();
        card = null;
      }
    }
  }
}

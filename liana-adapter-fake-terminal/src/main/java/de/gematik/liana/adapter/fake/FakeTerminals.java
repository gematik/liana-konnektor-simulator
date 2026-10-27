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

import java.nio.file.Path;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The fake terminals from the boot configuration. Cards are inserted by file name, ICCSN or path
 * from the known card images ({@link CardImages}, LIANA-98) and can be inserted and removed at
 * runtime (basis of the Admin API). {@link #reset()} restores the boot state (decision-4).
 */
public final class FakeTerminals {

  /**
   * A fake KT: ID, number of slots (CT.SLOTCOUNT), inserted images per slot, PIN, PUK and transport
   * PIN of the simulated PIN pad (LIANA-68).
   */
  /**
   * {@code signatureTime}: computation time of the cards for PSO COMPUTE DIGITAL SIGNATURE ({@link
   * FakeTerminal#signatureTime}).
   */
  public record Spec(
      String id,
      int slots,
      Map<Integer, String> cards,
      String pin,
      String puk,
      String transportPin,
      Duration signatureTime) {

    public Spec(
        String id,
        int slots,
        Map<Integer, String> cards,
        String pin,
        String puk,
        String transportPin) {
      this(id, slots, cards, pin, puk, transportPin, Duration.ZERO);
    }

    public Spec(String id, int slots, Map<Integer, String> cards) {
      this(id, slots, cards, FakeTerminal.DEFAULT_PIN);
    }

    public Spec(String id, int slots, Map<Integer, String> cards, String pin) {
      this(id, slots, cards, pin, FakeTerminal.DEFAULT_PUK, FakeTerminal.DEFAULT_TRANSPORT_PIN);
    }
  }

  private final List<Spec> specs;
  private final CardImages images;
  private final Map<String, FakeTerminal> terminals = new LinkedHashMap<>();

  public FakeTerminals(List<Spec> specs, CardImages images, CardEngine engine) {
    this.specs = List.copyOf(specs);
    this.images = images;
    for (Spec spec : specs) {
      FakeTerminal terminal =
          new FakeTerminal(
              spec.id(), spec.slots(), engine, spec.pin(), spec.puk(), spec.transportPin());
      terminal.signatureTime(spec.signatureTime());
      terminals.put(spec.id(), terminal);
    }
    insertBootCards();
  }

  public List<FakeTerminal> terminals() {
    return List.copyOf(terminals.values());
  }

  /** The KT with the ID {@code id}. */
  public FakeTerminal terminal(String id) {
    FakeTerminal terminal = terminals.get(id);
    if (terminal == null) {
      throw new IllegalArgumentException("unbekanntes KT '" + id + "'");
    }
    return terminal;
  }

  /**
   * Inserts the image {@code image} (file name, ICCSN or absolute path, {@link CardImages}) into
   * {@code terminal}/{@code slot}. An inserted card is removed first; if the image cannot be found,
   * the slot stays unchanged.
   */
  public synchronized void put(String terminal, int slot, String image) {
    FakeTerminal kt = terminal(terminal);
    Path resolved = resolve(terminal, slot, image);
    if (kt.cardPresent(slot)) {
      kt.eject(slot);
    }
    kt.insert(slot, resolved);
  }

  /** Removes the card from {@code terminal}/{@code slot}; an empty slot stays empty. */
  public synchronized void remove(String terminal, int slot) {
    FakeTerminal kt = terminal(terminal);
    if (kt.cardPresent(slot)) {
      kt.eject(slot);
    }
  }

  /** Removes all cards, clears all faults and inserts the cards from the boot configuration. */
  public synchronized void reset() {
    terminals.values().forEach(FakeTerminal::close);
    insertBootCards();
  }

  /** Removes all cards and terminates their processes. */
  public void close() {
    terminals.values().forEach(FakeTerminal::close);
  }

  private void insertBootCards() {
    for (Spec spec : specs) {
      spec.cards()
          .forEach(
              (slot, image) ->
                  terminals.get(spec.id()).insert(slot, resolve(spec.id(), slot, image)));
    }
  }

  /** The known card images from which cards are inserted. */
  public CardImages images() {
    return images;
  }

  private Path resolve(String terminal, int slot, String image) {
    try {
      return images.resolve(image);
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException(terminal + "/" + slot + ": " + e.getMessage(), e);
    }
  }
}

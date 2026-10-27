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

import de.gematik.liana.adapter.fake.CardImages;
import de.gematik.liana.adapter.fake.FakeTerminals;
import de.gematik.liana.adapter.fake.PinInput;
import de.gematik.liana.config.LianaConfig;
import de.gematik.liana.kern.card.CardList;
import jakarta.inject.Provider;
import jakarta.inject.Singleton;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import org.jboss.logging.Logger;

/**
 * Content of the robot interface (LIANA-106), independent of the HTTP transport in {@link
 * RobotServer}: the commands that tiger-ehealth-kt-e2e ({@code AutomationRobotGlueCode}, {@code
 * SmartCardSteps}) sends to the card robot act on the CTs from {@code liana.robot.terminals}. The
 * Removinator selects per robot terminal an eGK and a professional card from its compartments,
 * plugs push them into slot 1 or 2, opening removes them; inserting and removing go through {@link
 * FakeTerminals} on the fake CT like the admin API, with slot events and CardHandles, and on the
 * eHealth CT through the control interface of kartos terminal ({@link KartosRobots}, LIANA-112.15),
 * which reports the events via SICCT.
 *
 * <p>The stylus on the PIN pad (LIANA-68): the suite first calls the connector operation and then
 * sends the PIN input. With {@code liana.robot.await-pin} the PIN pads of the robot terminals
 * therefore wait for the input ({@link #awaitPinInput}, mode await) instead of typing the
 * configured PIN themselves; the commands append a {@link PinInput} to the selected terminal, for
 * the next PIN dialog at any slot. {@code enterAdminPin} (admin PIN of the CT) and the Virtual Card
 * Kit are not implemented and report {@link UnsupportedOperationException}. Errors: unknown command
 * argument {@link IllegalArgumentException}, insert without a selected card {@link
 * IllegalStateException}.
 */
@Singleton
public class RobotTerminals {

  private static final Logger LOG = Logger.getLogger(RobotTerminals.class);

  /** How long an insert or removal on the eHealth CT waits for the report in the card list. */
  private static final java.time.Duration CARD_EVENT = java.time.Duration.ofSeconds(10);

  /** Side of the Removinator and slot in the CT. */
  enum Side {
    EGK(1),
    BERECHTIGT(2);

    final int slot;

    Side(int slot) {
      this.slot = slot;
    }
  }

  private final FakeTerminals terminals;
  private final KartosRobots kartos;
  private final CardImages images;
  private final boolean awaitPin;
  private final Provider<CardList> cardList;
  private final List<String> robotTerminals;
  private final Map<Side, Map<String, String>> cards;

  /** Selected compartment per robot terminal and side. */
  private final Map<Integer, Map<Side, String>> chosen = new HashMap<>();

  private int selected = 1;

  RobotTerminals(
      FakeTerminals terminals,
      KartosRobots kartos,
      LianaConfig config,
      Provider<CardList> cardList) {
    this.terminals = terminals;
    this.cardList = cardList;
    this.kartos = kartos;
    this.images = new CardImages(config.cardImages());
    this.awaitPin = config.robot().awaitPin();
    this.robotTerminals = List.copyOf(config.robot().terminals());
    this.cards =
        Map.of(
            Side.EGK,
            Map.copyOf(config.robot().egk()),
            Side.BERECHTIGT,
            Map.copyOf(config.robot().berechtigt()));
  }

  /** {@code POST /api/robot/robotCommand} with {@code command} and {@code input}. */
  public synchronized void command(String command, String input) {
    if (command == null || command.isBlank()) {
      throw new IllegalArgumentException("command fehlt");
    }
    if (command.matches("selTerminal[0-9]+")) {
      selected = terminal(Integer.parseInt(command.substring("selTerminal".length())));
      return;
    }
    switch (command) {
      // Removinator: select compartment (steps „ROBOT wählt eine eGk …“, „… Berechtigtenkarte …“)
      case "sendToRemovinatorMaster" -> choose(1, Side.EGK, input);
      case "sendToRemovinator" -> choose(1, Side.BERECHTIGT, input);
      case "sendToRemovinatorEgkT2" -> choose(2, Side.EGK, input);
      case "sendToRemovinatorHbaT2" -> choose(2, Side.BERECHTIGT, input);
      // Plug: Ingenico at robot terminal 1, Cherry at 2; P pushes the card in, O opens (removes)
      case "IGP" -> insert(1, Side.EGK);
      case "IHP" -> insert(1, Side.BERECHTIGT);
      case "CGP" -> insert(2, Side.EGK);
      case "CHP" -> insert(2, Side.BERECHTIGT);
      case "IGO" -> eject(1, Side.EGK);
      case "IHO" -> eject(1, Side.BERECHTIGT);
      case "CGO" -> eject(2, Side.EGK);
      case "CHO" -> eject(2, Side.BERECHTIGT);
      // Robot at the selected terminal
      case "pressPatientenkarte" -> insert(selected, Side.EGK);
      case "pressBerechtigtenkarte" -> insert(selected, Side.BERECHTIGT);
      case "pressCards" -> {
        insert(selected, Side.EGK);
        insert(selected, Side.BERECHTIGT);
      }
      case "removePatientenkarte" -> eject(selected, Side.EGK);
      case "removeBerechtigtenkarte" -> eject(selected, Side.BERECHTIGT);
      case "removeCards" -> {
        eject(selected, Side.EGK);
        eject(selected, Side.BERECHTIGT);
      }
      // Stylus on the PIN pad of the selected terminal
      case "verifyPin" -> enterPin(PinInput.of(PinInput.Outcome.CORRECT));
      case "enterWrongPin" -> enterPin(PinInput.of(PinInput.Outcome.WRONG));
      case "enterPUK" -> enterPin(PinInput.of(PinInput.Outcome.PUK));
      case "enterTransportPin" -> enterPin(PinInput.of(PinInput.Outcome.TRANSPORT));
      case "enterCustomPin", "customPin" ->
          enterPin(new PinInput(PinInput.Outcome.DIGITS, input == null ? null : input.strip()));
      case "enterPinWithStop" -> enterPin(PinInput.of(PinInput.Outcome.CANCEL));
      case "enterIncompletePin" -> enterPin(PinInput.of(PinInput.Outcome.INCOMPLETE));
      case "enterAdminPin" ->
          throw new UnsupportedOperationException(
              "Admin-PIN des KT: das Fake-KT hat keine Managementschnittstelle");
      default ->
          throw new UnsupportedOperationException(
              "Robot-Kommando " + command + " in LIANA nicht umgesetzt");
    }
  }

  /**
   * With {@code liana.robot.await-pin} the PIN pads of the fake CTs among the robot terminals wait
   * for the stylus (mode await) while the robot interface is running; the eHealth CTs wait via
   * {@link KartosRobots#wrap}.
   */
  public void awaitPinInput() {
    if (awaitPin) {
      robotTerminals.stream()
          .filter(id -> kartos.terminal(id).isEmpty())
          .forEach(id -> terminals.terminal(id).awaitPinInput(true));
    }
  }

  /**
   * Admin reset (decision-4): forgets selection and terminal; {@link FakeTerminals} restores the
   * cards and PIN inputs.
   */
  public synchronized void reset() {
    chosen.clear();
    selected = 1;
    kartos.reset();
  }

  private void choose(int terminal, Side side, String fach) {
    terminal(terminal);
    String key = fach == null ? "" : fach.strip().toUpperCase(Locale.ROOT);
    if (!cards.get(side).containsKey(key)) {
      throw new IllegalArgumentException(
          "Fach '"
              + fach
              + "' der Seite "
              + side
              + " nicht belegt (liana.robot."
              + side.name().toLowerCase(Locale.ROOT)
              + ": "
              + new TreeMap<>(cards.get(side)).keySet()
              + ")");
    }
    chosen.computeIfAbsent(terminal, t -> new HashMap<>()).put(side, key);
  }

  /** Inserts the selected card; an inserted one is removed first (CARD/REMOVED, CARD/INSERTED). */
  private void insert(int terminal, Side side) {
    String fach = chosen.getOrDefault(terminal(terminal), Map.of()).get(side);
    if (fach == null) {
      throw new IllegalStateException(
          "Robot-Terminal " + terminal + ": keine " + side + "-Karte gewählt");
    }
    String image = cards.get(side).get(fach);
    var sicct = kartos.terminal(kt(terminal));
    if (sicct.isPresent()) {
      Path file = images.resolve(image);
      String iccsn =
          CardImages.iccsn(file)
              .orElseThrow(
                  () ->
                      new IllegalArgumentException(
                          "Fach "
                              + fach
                              + ": Image "
                              + file
                              + " ohne ICCSN in EF.GDO, kartos steckt nur Karten aus seiner Bibliothek"));
      sicct.get().insert(side.slot, iccsn, file);
      // The suite asks GetCards right afterwards; like the robot in the lab, the command only
      // returns once the CT
      // has reported the card and LIANA has recognized it
      await(
          kt(terminal),
          side.slot,
          () ->
              cardList
                  .get()
                  .card(kt(terminal), side.slot)
                  .filter(card -> iccsn.equals(card.data().iccsn()))
                  .isPresent(),
          "gesteckt");
    } else {
      terminals.put(kt(terminal), side.slot, image);
    }
  }

  private void enterPin(PinInput pin) {
    var sicct = kartos.terminal(kt(selected));
    if (sicct.isPresent()) {
      sicct.get().enterPin(pin);
      return;
    }
    LOG.infof("Robot: PIN-Eingabe %s an %s", pin, kt(selected));
    terminals.terminal(kt(selected)).enterPin(null, pin);
  }

  private void eject(int terminal, Side side) {
    var sicct = kartos.terminal(kt(terminal));
    if (sicct.isPresent()) {
      sicct.get().eject(side.slot);
      await(
          kt(terminal),
          side.slot,
          () -> cardList.get().card(kt(terminal), side.slot).isEmpty(),
          "gezogen");
    } else {
      terminals.remove(kt(terminal), side.slot);
    }
  }

  /**
   * Waits up to {@link #CARD_EVENT} until the card list shows {@code done} (SICCT 84/85 and
   * TUC_KON_001).
   */
  private static void await(
      String kt, int slot, java.util.function.BooleanSupplier done, String what) {
    long deadline = System.nanoTime() + CARD_EVENT.toNanos();
    while (!done.getAsBoolean()) {
      if (System.nanoTime() > deadline) {
        throw new IllegalStateException(
            kt
                + "/"
                + slot
                + ": Karte nach "
                + CARD_EVENT.toSeconds()
                + " s nicht "
                + what
                + " gemeldet");
      }
      try {
        Thread.sleep(50);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new IllegalStateException(kt + "/" + slot + ": Warten unterbrochen", e);
      }
    }
  }

  private String kt(int terminal) {
    return robotTerminals.get(terminal(terminal) - 1);
  }

  private int terminal(int terminal) {
    if (terminal < 1 || terminal > robotTerminals.size()) {
      throw new IllegalArgumentException(
          "Robot-Terminal "
              + terminal
              + " nicht konfiguriert (liana.robot.terminals: "
              + robotTerminals
              + ")");
    }
    return terminal;
  }
}

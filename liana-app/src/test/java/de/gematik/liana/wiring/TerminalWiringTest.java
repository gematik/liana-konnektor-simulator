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
package de.gematik.liana.wiring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.adapter.fake.CardEngine;
import de.gematik.liana.adapter.fake.FakeTerminals;
import de.gematik.liana.adapter.fake.TrafficPushingTerminal;
import de.gematik.liana.adapter.sicct.SicctTerminals;
import de.gematik.liana.config.TestConfig;
import de.gematik.liana.kern.card.CardList;
import de.gematik.liana.kern.card.CardObject;
import de.gematik.liana.kern.event.SystemLog;
import de.gematik.liana.kern.management.ManagementSettings;
import de.gematik.liana.kern.terminal.CardTerminal;
import de.gematik.liana.kern.terminal.NoCardException;
import de.gematik.liana.kern.terminal.TerminalRegistry;
import de.gematik.liana.kern.terminal.TimeLimitedTerminal;
import de.gematik.liana.sm.TrustedChannelTerminal;
import java.io.IOException;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class TerminalWiringTest {

  private static final ManagementSettings SETTINGS =
      new ManagementSettings(
          Duration.ofSeconds(30), Duration.ofSeconds(10), new SystemLog(Clock.systemUTC(), 10));

  private static FakeTerminals fakeTerminals(Map<String, String> overrides) throws IOException {
    return TerminalWiring.fakeTerminalsOf(
        TestConfig.load(overrides),
        image -> {
          throw new AssertionError("kartos darf beim Verdrahten nicht starten");
        });
  }

  @Test
  @DisplayName(
      "LIANA-121: Fake-KTs ohne lauffähiges kartos (kartos-bin fehlt, kein tools/kartos/) brechen den Start "
          + "ab, statt jede Karte als UNKNOWN zu führen")
  void ohneKartosKeinStart(@TempDir Path root) throws IOException {
    Path missing = root.resolve("opt/liana/bin/kartos");
    IllegalStateException e =
        assertThrows(
            IllegalStateException.class,
            () ->
                TerminalWiring.cardEngineOf(
                    TestConfig.load(Map.of("liana.card.kartos-bin", missing.toString())), root));
    assertTrue(e.getMessage().contains(missing + ": fehlt"), e.getMessage());
    assertTrue(e.getMessage().contains("LIANA_CARD_KARTOS_BIN"), e.getMessage());
  }

  @Test
  @DisplayName("LIANA-121: nur eHealth-KTs brauchen kein kartos-Binary in LIANA")
  void nurSicctOhneKartos(@TempDir Path root) throws IOException {
    // KartosLocator.resolve would throw: the configured binary does not exist
    CardEngine engine =
        TerminalWiring.cardEngineOf(
            TestConfig.load(
                Map.of(
                    "liana.card.kartos-bin", root.resolve("fehlt").toString(),
                    "liana.infrastructure.terminals.KT-01.type", "sicct",
                    "liana.infrastructure.terminals.KT-01.host", "kt-01",
                    "liana.infrastructure.terminals.KT-02.type", "sicct",
                    "liana.infrastructure.terminals.KT-02.host", "kt-02")),
            root);
    assertNotNull(engine);
  }

  @Test
  @DisplayName(
      "LIANA-98: Fake-Terminals und Terminal-Register entstehen aus liana.infrastructure.terminals (type: fake)")
  void fromYaml() throws IOException {
    TerminalRegistry registry = new TerminalRegistry(fakeTerminals(Map.of()).terminals());
    assertEquals(
        List.of("KT-01", "KT-02"), registry.terminals().stream().map(CardTerminal::id).toList());
    CardTerminal kt01 = registry.terminal("KT-01").orElseThrow();
    assertEquals(3, kt01.slots());
    assertTrue(kt01.cardPresent(1));
    assertEquals(2, registry.terminal("KT-02").orElseThrow().slots());
  }

  @Test
  @DisplayName(
      "TUC_KON_025: die Karten aus der YAML stehen nach dem Start in CM_CARD_LIST, reset vergibt neue CardHandles")
  void kartenlisteAusYaml() throws IOException {
    // without kartos: the cards are unreadable and are listed as UNKNOWN (TUC_KON_001)
    FakeTerminals terminals =
        TerminalWiring.fakeTerminalsOf(
            TestConfig.load(Map.of()),
            image -> {
              throw new IOException("kein kartos im Test");
            });
    CardList cards = new CardList(new TerminalRegistry(terminals.terminals()), Clock.systemUTC());
    cards.start();
    CardObject boot = cards.card("KT-01", 1).orElseThrow();
    assertEquals(2, cards.cards().size(), "egk-valid und smcb-valid");

    terminals.reset();
    CardObject nachReset = cards.card("KT-01", 1).orElseThrow();
    assertNotEquals(boot.cardHandle(), nachReset.cardHandle());
    assertTrue(cards.card(boot.cardHandle()).isEmpty());
    assertEquals(2, cards.cards().size(), "egk-valid und smcb-valid");
  }

  @Test
  @DisplayName(
      "LIANA-27 / TAB_KON_554: ohne liana.trace.push-url (Standard) gehen APDUs über CARD_TIMEOUT_CARD direkt "
          + "an die Fake-Terminals, kein Push; mit push-url meldet jedes KT seine APDUs")
  void trafficPushNurMitUrl() throws IOException {
    var wiring = new TerminalWiring();
    var ohne =
        wiring.terminalRegistry(
            fakeTerminals(Map.of()),
            sicctTerminals(List.of()),
            TestConfig.load(Map.of()),
            () -> null,
            SETTINGS);
    assertTrue(ohne.terminals().stream().allMatch(TimeLimitedTerminal.class::isInstance));

    var mit =
        wiring.terminalRegistry(
            fakeTerminals(Map.of()),
            sicctTerminals(List.of()),
            TestConfig.load(Map.of("liana.trace.push-url", "http://localhost:1")),
            () -> null,
            SETTINGS);
    assertTrue(mit.terminals().stream().allMatch(TrafficPushingTerminal.class::isInstance));
    wiring.close(mit);
  }

  @Test
  @DisplayName(
      "LIANA-28: mit card.terminate-secure-messaging liegt um jedes KT der Trusted Channel mit seiner "
          + "gSMC-KT (gsmc-kt, LIANA-99), außen um den Traffic-Push")
  void trustedChannelAussen() throws IOException {
    var wiring = new TerminalWiring();
    var config =
        TestConfig.load(
            Map.of(
                "liana.card.terminate-secure-messaging",
                "true",
                "liana.trace.push-url",
                "http://localhost:1",
                "liana.infrastructure.terminals.KT-01.gsmc-kt",
                "gsmckt-valid",
                "liana.infrastructure.terminals.KT-02.gsmc-kt",
                "80276883110000148887"));
    var registry =
        wiring.terminalRegistry(
            fakeTerminals(Map.of()), sicctTerminals(List.of()), config, () -> null, SETTINGS);
    assertTrue(registry.terminals().stream().allMatch(TrustedChannelTerminal.class::isInstance));
    wiring.close(registry);
  }

  /** SICCT KTs without network: service discovery only starts with {@link SicctTerminals#start}. */
  private static SicctTerminals sicctTerminals(List<String> ids) {
    return new SicctTerminals(
        ids.stream().map(id -> new SicctTerminals.Spec(id, "127.0.0.1")).toList(),
        (host, port) -> {
          throw new IOException("kein KT im Test");
        },
        new SicctTerminals.Settings(
            4742, Duration.ofSeconds(1), Duration.ofSeconds(1), List.of("1.0.0")),
        new SystemLog(Clock.systemUTC(), 10));
  }

  @Test
  @DisplayName(
      "LIANA-76: Fake- und SICCT-KTs stehen nebeneinander hinter CardTerminal im Register; "
          + "ein SICCT-KT ohne CT-Object hat keine Slots und keine Karten")
  void mixed() throws IOException {
    var config =
        TestConfig.load(
            Map.of(
                "liana.infrastructure.terminals.KT-S1.type",
                "sicct",
                "liana.infrastructure.terminals.KT-S1.host",
                "127.0.0.1"));
    var registry =
        new TerminalWiring()
            .terminalRegistry(
                TerminalWiring.fakeTerminalsOf(
                    config,
                    image -> {
                      throw new AssertionError("kartos darf beim Verdrahten nicht starten");
                    }),
                sicctTerminals(List.of("KT-S1")),
                config,
                () -> null,
                SETTINGS);
    assertEquals(
        List.of("KT-01", "KT-02", "KT-S1"),
        registry.terminals().stream().map(CardTerminal::id).toList());
    CardTerminal sicct = registry.terminal("KT-S1").orElseThrow();
    assertTrue(sicct instanceof TimeLimitedTerminal, "auch SICCT-KTs über CARD_TIMEOUT_CARD");
    assertEquals(0, sicct.slots());
    assertThrows(
        NoCardException.class,
        () -> sicct.transmit(1, new byte[] {0, (byte) 0xA4, 0, 0}),
        "ohne Arbeitsverbindung keine Karte, wie beim Fake-Terminal ohne gesteckte Karte");
  }

  @Test
  @DisplayName(
      "LIANA-98: ein überlagertes KT mit type: sicct läuft nicht als Fake-KT, seine Fake-Felder bleiben "
          + "unbeachtet")
  void nurSicct() throws IOException {
    assertEquals(
        List.of("KT-02"),
        fakeTerminals(
                Map.of(
                    "liana.infrastructure.terminals.KT-01.type",
                    "sicct",
                    "liana.infrastructure.terminals.KT-01.host",
                    "127.0.0.1"))
            .terminals()
            .stream()
            .map(CardTerminal::id)
            .toList());
  }
}

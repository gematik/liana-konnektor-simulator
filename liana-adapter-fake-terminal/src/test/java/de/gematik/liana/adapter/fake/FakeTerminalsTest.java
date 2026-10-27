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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class FakeTerminalsTest {

  static final CardImages SEARCH_PATH =
      new CardImages(List.of(Path.of("./support/images"), Path.of("/opt/liana/images")));

  private final FakeTerminalTest.StubEngine engine = new FakeTerminalTest.StubEngine();

  private FakeTerminals terminals() {
    return new FakeTerminals(
        List.of(
            new FakeTerminals.Spec("KT-01", 3, Map.of(1, "egk-valid")),
            new FakeTerminals.Spec("KT-02", 2, Map.of())),
        SEARCH_PATH,
        engine);
  }

  @Test
  @DisplayName("Fake-Terminals entstehen mit Slots und gesteckten Karten aus den Specs")
  void fromSpecs() {
    FakeTerminals terminals = terminals();
    assertEquals(
        List.of("KT-01", "KT-02"), terminals.terminals().stream().map(FakeTerminal::id).toList());
    FakeTerminal kt01 = terminals.terminals().getFirst();
    assertEquals(3, kt01.slots());
    assertTrue(kt01.cardPresent(1));
    assertFalse(kt01.cardPresent(2));
  }

  @Test
  @DisplayName("Karten lassen sich zur Laufzeit stecken und ziehen")
  void putAndRemove() throws IOException {
    FakeTerminals terminals = terminals();
    terminals.put("KT-02", 1, "egk-valid");
    FakeTerminal kt02 = terminals.terminals().get(1);
    assertTrue(kt02.cardPresent(1));
    kt02.reset(1);
    assertEquals(List.of(Path.of("./support/images/egk-valid.xml")), engine.opened);
    terminals.remove("KT-02", 1);
    assertFalse(kt02.cardPresent(1));
    assertEquals(1, engine.closed);
    terminals.remove("KT-02", 1);
    assertFalse(kt02.cardPresent(1));
  }

  @Test
  @DisplayName(
      "Stecken in einen belegten Slot ersetzt die Karte, ein unbekanntes Image lässt sie stecken")
  void putReplaces() {
    FakeTerminals terminals = terminals();
    FakeTerminal kt01 = terminals.terminal("KT-01");
    Path absolute = Path.of("support/images/egk-valid.xml").toAbsolutePath();
    terminals.put("KT-01", 1, absolute.toString());
    assertEquals(absolute, kt01.image(1).orElseThrow());
    assertThrows(IllegalArgumentException.class, () -> terminals.put("KT-01", 1, "egk-expired"));
    assertEquals(absolute, kt01.image(1).orElseThrow());
  }

  @Test
  @DisplayName("reset stellt den Stand aus den Specs wieder her")
  void reset() {
    FakeTerminals terminals = terminals();
    terminals.remove("KT-01", 1);
    terminals.put("KT-02", 2, "egk-valid");
    terminals.reset();
    assertEquals(
        Path.of("./support/images/egk-valid.xml"),
        terminals.terminal("KT-01").image(1).orElseThrow());
    assertFalse(terminals.terminal("KT-02").cardPresent(2));
  }

  @Test
  @DisplayName(
      "put auf belegten Slot, reset: Ziehen und Stecken gehen als Slot-Ereignisse an die Listener")
  void slotEreignisse() {
    FakeTerminals terminals = terminals();
    FakeTerminalTest.Recorder recorder = new FakeTerminalTest.Recorder();
    terminals.terminals().forEach(kt -> kt.addSlotListener(recorder));
    terminals.put("KT-01", 1, "egk-valid");
    terminals.put("KT-02", 2, "egk-valid");
    terminals.reset();
    assertEquals(
        List.of(
            "FREE KT-01/1",
            "IN_USE KT-01/1",
            "IN_USE KT-02/2",
            "FREE KT-01/1",
            "FREE KT-02/2",
            "IN_USE KT-01/1"),
        recorder.events);
  }

  @Test
  @DisplayName(
      "Stecken eines unbekannten Images, in ein unbekanntes KT oder einen unbekannten Slot wird abgewiesen")
  void insertErrors() {
    FakeTerminals terminals = terminals();
    IllegalArgumentException e =
        assertThrows(
            IllegalArgumentException.class, () -> terminals.put("KT-02", 1, "egk-expired"));
    assertEquals(
        "KT-02/1: Image 'egk-expired' nicht gefunden in [./support/images, /opt/liana/images], ähnlich: [egk-valid]",
        e.getMessage());
    assertThrows(IllegalArgumentException.class, () -> terminals.put("KT-99", 1, "egk-valid"));
    assertThrows(IllegalArgumentException.class, () -> terminals.put("KT-02", 3, "egk-valid"));
  }
}

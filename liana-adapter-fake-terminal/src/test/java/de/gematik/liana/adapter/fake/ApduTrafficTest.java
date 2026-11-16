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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.kern.terminal.CardTerminal;
import de.gematik.liana.kern.terminal.SlotListener;
import de.gematik.liana.kern.trace.Traffic;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** LIANA-27: card APDUs as SICCT envelopes to {@link Traffic}, paired (LIANA-195). */
class ApduTrafficTest {

  private static final HexFormat HEX = HexFormat.of().withUpperCase();
  private static final byte[] SELECT = HEX.parseHex("00A4040C07D2760001448000");
  private static final byte[] OK = HEX.parseHex("9000");

  record Report(byte[] message, String sender, String receiver, String responseTo, String uuid) {}

  private final List<Report> reports = new ArrayList<>();

  private final Traffic traffic =
      (message, sender, receiver, time, responseTo) -> {
        String uuid = "uuid-" + reports.size();
        reports.add(new Report(message, sender, receiver, responseTo, uuid));
        return uuid;
      };

  /** KT with a card in slot 1 that answers 9000 to everything. */
  private static CardTerminal kt() {
    return new CardTerminal() {
      public String id() {
        return "KT-01";
      }

      public int slots() {
        return 1;
      }

      public void addSlotListener(SlotListener listener) {}

      public boolean cardPresent(int slot) {
        return true;
      }

      public byte[] reset(int slot) {
        return new byte[] {0x3B};
      }

      public byte[] transmit(int slot, byte[] commandApdu) {
        return OK;
      }
    };
  }

  @Test
  @DisplayName(
      "Jede APDU ergibt zwei Meldungen: Kommando konnektor → konnektor-KT-01:1 (C_COMMAND), Antwort zurück "
          + "(R_RESPONSE) mit tgr-response-to auf das Kommando, gleiche Sequenznummer")
  void zweiNachrichtenJeApdu() throws Exception {
    var terminal = new TrafficPushingTerminal(kt(), new ApduTraffic(traffic));
    assertArrayEquals(OK, terminal.transmit(1, SELECT));
    terminal.transmit(1, SELECT);

    assertEquals(4, reports.size());
    Report command = reports.get(0);
    Report response = reports.get(1);
    assertEquals("konnektor", command.sender());
    assertEquals("konnektor-KT-01:1", command.receiver());
    assertNull(command.responseTo());
    assertEquals("konnektor-KT-01:1", response.sender());
    assertEquals("konnektor", response.receiver());
    assertEquals(command.uuid(), response.responseTo());
    // SICCT envelope: type, slot 1, sequence 0, RFU, length 12, APDU
    assertEquals(
        "6B" + "0001" + "0000" + "00" + "0000000C" + "00A4040C07D2760001448000",
        HEX.formatHex(command.message()));
    assertEquals(
        "83" + "0001" + "0000" + "00" + "00000002" + "9000", HEX.formatHex(response.message()));
    assertEquals("6B" + "0001" + "0001", HEX.formatHex(reports.get(2).message()).substring(0, 10));
    assertEquals("83" + "0001" + "0001", HEX.formatHex(reports.get(3).message()).substring(0, 10));
  }

  @Test
  @DisplayName(
      "LIANA-195.04: zwei Konnektoren mit verschiedenem Namen melden KT-01 unter verschiedenen Adressen")
  void zweiKonnektoren() {
    for (String name : List.of("konnektor-a", "konnektor-b")) {
      Traffic named =
          new Traffic() {
            @Override
            public String report(
                byte[] message, String sender, String receiver, Instant time, String responseTo) {
              return traffic.report(message, sender, receiver, time, responseTo);
            }

            @Override
            public String name() {
              return name;
            }
          };
      new ApduTraffic(named).apdu("KT-01", 1, SELECT, Instant.now(), OK, Instant.now());
    }
    assertEquals("konnektor-a", reports.get(0).sender());
    assertEquals("konnektor-a-KT-01:1", reports.get(0).receiver());
    assertEquals("konnektor-b", reports.get(2).sender());
    assertEquals("konnektor-b-KT-01:1", reports.get(2).receiver());
  }

  @Test
  @DisplayName(
      "LIANA-28: Klartext einer terminierten SM-APDU mit eigenem Absender konnektor-sm-klartext und Empfänger "
          + "konnektor-KT-SM-sm-klartext:1")
  void klartext() {
    new ApduTraffic(traffic).plaintext("KT-SM", 1, SELECT, Instant.now(), OK, Instant.now());
    assertEquals(2, reports.size());
    assertEquals("konnektor-sm-klartext", reports.get(0).sender());
    assertEquals("konnektor-KT-SM-sm-klartext:1", reports.get(0).receiver());
    assertTrue(HEX.formatHex(reports.get(0).message()).endsWith(HEX.formatHex(SELECT)));
    assertEquals("konnektor-KT-SM-sm-klartext:1", reports.get(1).sender());
    assertEquals("konnektor-sm-klartext", reports.get(1).receiver());
    assertEquals(reports.get(0).uuid(), reports.get(1).responseTo());
  }

  @Test
  @DisplayName("Andere Operationen gehen unverändert an das KT, ohne Meldung")
  void nurApdus() throws Exception {
    var terminal = new TrafficPushingTerminal(kt(), new ApduTraffic(traffic));
    assertEquals("KT-01", terminal.id());
    assertArrayEquals(new byte[] {0x3B}, terminal.reset(1));
    assertTrue(terminal.cardPresent(1));
    assertTrue(reports.isEmpty());
  }
}

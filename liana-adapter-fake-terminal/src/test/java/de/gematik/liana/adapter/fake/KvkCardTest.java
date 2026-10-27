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
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The KVK as memory card in the fake KT (LIANA-113), KBV leaflet KVK 2.05 section 4. */
class KvkCardTest {

  private static final HexFormat HEX = HexFormat.of().withUpperCase();
  private static final Path KVK_VALID = Path.of("support/images/kvk/kvk-valid.xml");

  private static String send(KvkCard card, String apdu) {
    return HEX.formatHex(card.transmit(HEX.parseHex(apdu)));
  }

  @Test
  @DisplayName(
      "KBV-Merkblatt 4.1/4.2: SELECT der KVK-AID, READ BINARY Le 00 liefert das Template mit 6282; Le kleiner "
          + "als der Rest 9000, darüber 6282; Offset hinter dem Ende 6B00; READ BINARY ohne SELECT 6900; fremde AID 6A82")
  void kvkValid() throws IOException {
    KvkCard card = KvkCard.open(KVK_VALID);
    assertEquals("A2131091", HEX.formatHex(card.atr()));
    assertEquals("6900", send(card, "00B0000000"));
    assertEquals("6A82", send(card, "00A4040006D27600000102"));
    assertEquals("9000", send(card, "00A4040006D27600000101"));
    String all = send(card, "00B0000000");
    assertTrue(all.startsWith("607F800F") && all.endsWith("8E01B36282"), all);
    assertEquals(129 * 2 + 4, all.length());
    assertEquals("607F80" + "9000", send(card, "00B0000003"));
    assertEquals("8E01B3" + "6282", send(card, "00B0007E10"));
    assertEquals("B3" + "9000", send(card, "00B0008001"));
    assertEquals("6B00", send(card, "00B0008100"));
    assertEquals("9000", send(card, "00A4040006D28000000101"));
    assertEquals("6D00", send(card, "0084000008"));
  }

  @Test
  @DisplayName(
      "Image: isKvk nur für die Wurzel kvk; CardImage.check prüft eine KVK ganz, ohne template scheitert sie")
  void image(@TempDir Path dir) throws IOException {
    assertTrue(KvkCard.isKvk(KVK_VALID));
    assertFalse(KvkCard.isKvk(Path.of("support/images/egk-valid.xml")));
    CardImage.check(KVK_VALID);
    Path broken = dir.resolve("kvk-leer.xml");
    Files.writeString(broken, "<kvk atr=\"A2131091\"/>");
    var e = assertThrows(IllegalArgumentException.class, () -> CardImage.check(broken));
    assertEquals("KVK-Image kvk-leer.xml: Attribut atr und Element template nötig", e.getMessage());
  }

  @Test
  @DisplayName("Fake-KT: die KVK im Slot läuft ohne Card-Engine")
  void fakeTerminal() throws IOException {
    FakeTerminal terminal =
        new FakeTerminal(
            "KT-01",
            1,
            image -> {
              throw new IOException("Card-Engine für " + image);
            });
    terminal.insert(1, KVK_VALID);
    assertEquals("A2131091", HEX.formatHex(terminal.reset(1)));
    assertEquals(
        "9000", HEX.formatHex(terminal.transmit(1, HEX.parseHex("00A4040006D27600000101"))));
  }
}

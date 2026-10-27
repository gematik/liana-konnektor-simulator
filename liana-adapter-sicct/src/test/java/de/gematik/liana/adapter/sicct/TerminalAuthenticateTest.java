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
package de.gematik.liana.adapter.sicct;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * EHEALTH TERMINAL AUTHENTICATE (gemSpec_KT 3.7.2, CMD_KT_0001) from the Konnektor's point of view.
 */
class TerminalAuthenticateTest {

  static final HexFormat HEX = HexFormat.of();
  static final byte[] SS = HEX.parseHex("000102030405060708090a0b0c0d0e0f");
  static final byte[] CHALLENGE = HEX.parseHex("202122232425262728292a2b2c2d2e2f");

  @Test
  @DisplayName(
      "TUC_KON_053 Schritt 5: CREATE 81 AA 00 01 mit SS DO D4 (16 Byte) und APPL DO 50 mit der Anzeige "
          + "„KT:AABBCC:DDEEFF MIT KON:<Hostname> PAIREN OK?“, Le 00")
  void create() {
    String display = TerminalAuthenticate.displayMessage("02:00:00:4C:49:41", "liana");
    assertEquals("KT:020000:4C4941 MIT KON:liana PAIREN OK?", display);
    byte[] text = display.getBytes(StandardCharsets.US_ASCII);
    String expected =
        "81aa0001"
            + String.format("%02x", 2 + 16 + 2 + text.length)
            + "d410"
            + HEX.formatHex(SS)
            + "50"
            + String.format("%02x", text.length)
            + HEX.formatHex(text)
            + "00";
    assertEquals(expected, HEX.formatHex(TerminalAuthenticate.create(SS, display)));
  }

  @Test
  @DisplayName(
      "TUC_KON_050 Schritt 7/8: VALIDATE 81 AA 00 02 mit SSC DO D5, Le 20; Erwartung SHA-256(Challenge ‖ SS) "
          + "(SEQ_KT_0002)")
  void validate() {
    assertEquals(
        "81aa000212d510" + HEX.formatHex(CHALLENGE) + "20",
        HEX.formatHex(TerminalAuthenticate.validate(CHALLENGE)));
    assertArrayEquals(
        HEX.parseHex("c5435ead2526ad8b97efe48c5ee5b3f3e1b3f0c6be99bcc23f5f00484fbb8005"),
        TerminalAuthenticate.expectedValidation(CHALLENGE, SS));
  }

  @Test
  @DisplayName(
      "DO_KT_0003/0004: Shared Secret genau 16 Byte, Challenge 16–127 Byte; neue Werte in diesen Längen")
  void laengen() {
    assertThrows(
        IllegalArgumentException.class, () -> TerminalAuthenticate.create(new byte[15], "x"));
    assertThrows(IllegalArgumentException.class, () -> TerminalAuthenticate.validate(new byte[15]));
    assertThrows(
        IllegalArgumentException.class, () -> TerminalAuthenticate.validate(new byte[128]));
    assertEquals(16, TerminalAuthenticate.newSharedSecret().length);
    assertEquals(16, TerminalAuthenticate.newChallenge().length);
  }

  @Test
  @DisplayName(
      "Antwort ohne 9000 hat keinen Body (6400 Timeout, 6401 Abbruch, 6900 kein Pairing-Block)")
  void antwort() {
    assertArrayEquals(HEX.parseHex("aabb"), TerminalAuthenticate.body(HEX.parseHex("aabb9000")));
    assertNull(TerminalAuthenticate.body(HEX.parseHex("6401")));
    assertNull(TerminalAuthenticate.body(HEX.parseHex("6900")));
  }
}

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
package de.gematik.liana.sm;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * LIANA-28: SM codec according to gemSpec_COS 13.2/13.3 against the vectors recorded with kartos in
 * {@code support/sm/}.
 */
class SecureMessagingTest {

  private static final HexFormat HEX = HexFormat.of().withUpperCase();
  private static final Path VECTORS = Path.of("support/sm/elc-sessionkey4sm-egk-valid.txt");

  record Vector(
      byte[] ssc, String command, String response, String plainCommand, String plainResponse) {}

  record Recording(SecureMessaging.Session session, List<Vector> apdus) {}

  static Recording recording() throws IOException {
    List<String> lines =
        Files.readAllLines(VECTORS).stream().filter(line -> !line.startsWith("#")).toList();
    String[] session = lines.getFirst().split(" ");
    List<Vector> apdus =
        lines.stream()
            .skip(1)
            .map(line -> line.split(" "))
            .map(f -> new Vector(HEX.parseHex(f[1]), f[2], f[3], f[4], f[5]))
            .toList();
    return new Recording(
        new SecureMessaging.Session(
            HEX.parseHex(session[1]), HEX.parseHex(session[2]), apdus.getFirst().ssc()),
        apdus);
  }

  private static SecureMessaging.Session at(Recording recording, Vector vector) {
    return new SecureMessaging.Session(
        recording.session().kEnc(), recording.session().kMac(), vector.ssc());
  }

  @Test
  @DisplayName(
      "G2_N032.000–G2_N034.300: Auswickeln liefert den aufgezeichneten Klartext, Einwickeln byteidentisch "
          + "die aufgezeichnete APDU, Kommandos (DO87, DO97) wie Antworten (DO81, DO99)")
  void recordedSequence() throws Exception {
    Recording recording = recording();
    assertEquals(2, recording.apdus().size());
    for (Vector vector : recording.apdus()) {
      SecureMessaging.Session session = at(recording, vector);
      byte[] command = HEX.parseHex(vector.command());
      SecureMessaging.Plain plain =
          SecureMessaging.unwrapCommand(command, session, session.commandSsc());
      assertEquals(vector.plainCommand(), HEX.formatHex(plain.apdu()));
      assertArrayEquals(command, SecureMessaging.wrapCommand(plain, session, session.commandSsc()));

      byte[] response = HEX.parseHex(vector.response());
      SecureMessaging.Plain plainResponse =
          SecureMessaging.unwrapResponse(response, session, session.responseSsc());
      assertEquals(vector.plainResponse(), HEX.formatHex(plainResponse.apdu()));
      assertFalse(plainResponse.encrypted());
      assertArrayEquals(
          response, SecureMessaging.wrapResponse(plainResponse, session, session.responseSsc()));
    }
    assertTrue(
        SecureMessaging.unwrapCommand(
                HEX.parseHex(recording.apdus().getFirst().command()),
                recording.session(),
                recording.session().commandSsc())
            .encrypted(),
        "SELECT mit Daten in DO87");
  }

  @Test
  @DisplayName("G2_N032.800.b: falscher MAC, falscher SSC oder falsches Padding werden erkannt")
  void rejects() throws Exception {
    Recording recording = recording();
    Vector select = recording.apdus().getFirst();
    SecureMessaging.Session session = at(recording, select);
    byte[] command = HEX.parseHex(select.command());
    byte[] mac = command.clone();
    mac[mac.length - 2] ^= 1;
    assertThrows(
        SecureMessaging.SecureMessagingException.class,
        () -> SecureMessaging.unwrapCommand(mac, session, session.commandSsc()));
    assertThrows(
        SecureMessaging.SecureMessagingException.class,
        () -> SecureMessaging.unwrapCommand(command, session, session.responseSsc()));
    assertThrows(
        SecureMessaging.SecureMessagingException.class,
        () -> SecureMessaging.unwrapResponse(HEX.parseHex("6988"), session, session.responseSsc()));
    assertThrows(
        SecureMessaging.SecureMessagingException.class,
        () ->
            SecureMessaging.unwrapCommand(
                HEX.parseHex("00A4040C00"), session, session.commandSsc()));
  }

  @Test
  @DisplayName(
      "G2_N033.800: verschlüsselte Antwortdaten (DO87) und Kommandos ohne Daten (Case 1, nur DO8E) "
          + "überstehen Ein- und Auswickeln")
  void roundTrips() throws Exception {
    SecureMessaging.Session session = recording().session();
    for (String apdu :
        List.of(
            "00B0840000",
            "8022000000",
            "00B08400000000",
            "00D6000003010203",
            "00D60000000100" + "AB".repeat(256))) {
      byte[] wrapped =
          SecureMessaging.wrapCommand(
              new SecureMessaging.Plain(HEX.parseHex(apdu), true), session, session.commandSsc());
      assertEquals(
          apdu,
          HEX.formatHex(
              SecureMessaging.unwrapCommand(wrapped, session, session.commandSsc()).apdu()));
    }
    SecureMessaging.Plain secret =
        new SecureMessaging.Plain(HEX.parseHex("0102030405060708090A0B0C0D0E0F109000"), true);
    byte[] wrapped = SecureMessaging.wrapResponse(secret, session, session.responseSsc());
    assertEquals(0x87, wrapped[0] & 0xFF);
    SecureMessaging.Plain unwrapped =
        SecureMessaging.unwrapResponse(wrapped, session, session.responseSsc());
    assertArrayEquals(secret.apdu(), unwrapped.apdu());
    assertTrue(unwrapped.encrypted());
  }

  @Test
  @DisplayName("AES-CMAC nach RFC 4493, Beispiele 1–4")
  void cmac() throws Exception {
    byte[] key = HEX.parseHex("2B7E151628AED2A6ABF7158809CF4F3C");
    String message =
        "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E51"
            + "30C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710";
    assertEquals(
        "BB1D6929E95937287FA37D129B756746", HEX.formatHex(SecureMessaging.cmac(key, new byte[0])));
    assertEquals(
        "070A16B46B4D4144F79BDD9DD04A287C",
        HEX.formatHex(SecureMessaging.cmac(key, HEX.parseHex(message.substring(0, 32)))));
    assertEquals(
        "DFA66747DE9AE63030CA32611497C827",
        HEX.formatHex(SecureMessaging.cmac(key, HEX.parseHex(message.substring(0, 80)))));
    assertEquals(
        "51F0BEBF7E3B9D92FC49741779363CFE",
        HEX.formatHex(SecureMessaging.cmac(key, HEX.parseHex(message))));
  }

  @Test
  @DisplayName(
      "Sitzungsschlüssel K_enc K_mac SSC in Hex; SSC des Kommandos +1, der Antwort +2 (G2_N032.190, G2_N033.690)")
  void session() {
    SecureMessaging.Session session =
        SecureMessaging.Session.parse(
            "11".repeat(16) + " " + "22".repeat(16) + " " + "00".repeat(15) + "FF");
    assertEquals("00".repeat(14) + "0100", HEX.formatHex(session.commandSsc()));
    assertEquals("00".repeat(14) + "0101", HEX.formatHex(session.responseSsc()));
    assertThrows(IllegalArgumentException.class, () -> SecureMessaging.Session.parse("-"));
  }

  @Test
  @DisplayName("G2_N032.500.a: SM-Kommandos haben im CLA die Bits b4 b3 gesetzt, Kanal 0–3")
  void secured() {
    assertTrue(SecureMessaging.isSecured(HEX.parseHex("0CA4040C")));
    assertTrue(SecureMessaging.isSecured(HEX.parseHex("8CCA0100")));
    assertFalse(SecureMessaging.isSecured(HEX.parseHex("00A4040C")));
    assertFalse(SecureMessaging.isSecured(HEX.parseHex("08A4040C")));
    assertFalse(SecureMessaging.isSecured(HEX.parseHex("4CA4040C")));
  }
}

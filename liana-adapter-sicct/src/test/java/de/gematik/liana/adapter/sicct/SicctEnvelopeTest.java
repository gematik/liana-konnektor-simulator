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
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * SICCT 1.2.3 §6.2.4.2 table 16: the envelope codec against the test vectors from the kartos wire
 * trace ({@code support/traces/sicct/kartos-wire.jsonl}, peer openssl, not LIANA).
 */
class SicctEnvelopeTest {

  static final Path WIRE_TRACE = Path.of("support/traces/sicct/kartos-wire.jsonl");
  static final HexFormat HEX = HexFormat.of();

  /** An envelope of the trace: the fields kartos logs alongside it, and the bytes. */
  record Vector(String dir, String msg, int fu, int seq, int payloadLength, byte[] bytes) {}

  static List<Vector> vectors() throws IOException {
    ObjectMapper json = new ObjectMapper();
    List<Vector> vectors = new ArrayList<>();
    for (String line : Files.readAllLines(WIRE_TRACE)) {
      JsonNode node = json.readTree(line);
      if (node.has("meta")) {
        continue;
      }
      vectors.add(
          new Vector(
              node.get("dir").asText(),
              node.get("msg").asText(),
              Integer.decode(node.get("fu").asText()),
              node.get("seq").asInt(),
              node.get("payload_len").asInt(),
              HEX.parseHex(node.get("hex").asText())));
    }
    return vectors;
  }

  private static SicctEnvelope.Type type(String kartosName) {
    return switch (kartosName) {
      case "CommandC" -> SicctEnvelope.Type.C_COMMAND;
      case "CommandR" -> SicctEnvelope.Type.R_COMMAND;
      case "Event" -> SicctEnvelope.Type.EVENT;
      default -> throw new IllegalArgumentException(kartosName);
    };
  }

  @Test
  @DisplayName(
      "Tabelle 16: jeder Umschlag des kartos-Traces dekodiert zu Typ, FU, Sequenznummer und Länge, die kartos "
          + "protokolliert, und kodiert byte-gleich zurück")
  void kartosWireTrace() throws IOException {
    List<Vector> vectors = vectors();
    assertEquals(13, vectors.size());
    for (Vector vector : vectors) {
      SicctEnvelope envelope = SicctEnvelope.decode(vector.bytes());
      assertEquals(type(vector.msg()), envelope.type(), vector.toString());
      assertEquals(vector.fu(), envelope.fu());
      assertEquals(vector.seq(), envelope.seq());
      assertEquals(vector.payloadLength(), envelope.payload().length);
      assertArrayEquals(vector.bytes(), envelope.encode());
    }
  }

  @Test
  @DisplayName(
      "§6.2.4.2/6.2.4.4: im Trace kommen die Ereignisse von FU 0000 mit FD00, FD01, FD02 – 85 und 84 für Slot 3, "
          + "KEEP ALIVE 80")
  void ereignisseImTrace() throws IOException {
    List<SicctEnvelope> events = new ArrayList<>();
    for (Vector vector : vectors()) {
      SicctEnvelope envelope = SicctEnvelope.decode(vector.bytes());
      if (envelope.type() == SicctEnvelope.Type.EVENT) {
        events.add(envelope);
      }
    }
    assertEquals(
        List.of(
            new SicctEnvelope(SicctEnvelope.Type.EVENT, 0, 0xFD00, HEX.parseHex("85020003")),
            new SicctEnvelope(SicctEnvelope.Type.EVENT, 0, 0xFD01, HEX.parseHex("84020003")),
            new SicctEnvelope(SicctEnvelope.Type.EVENT, 0, 0xFD02, HEX.parseHex("80020000"))),
        events);
  }

  @Test
  @DisplayName("Aus einem Datenstrom liest read() die Umschläge des KT nacheinander, am Ende null")
  void stromLesen() throws IOException {
    ByteArrayOutputStream stream = new ByteArrayOutputStream();
    List<SicctEnvelope> expected = new ArrayList<>();
    for (Vector vector : vectors()) {
      if (vector.dir().equals("out")) {
        stream.write(vector.bytes());
        expected.add(SicctEnvelope.decode(vector.bytes()));
      }
    }
    ByteArrayInputStream in = new ByteArrayInputStream(stream.toByteArray());
    List<SicctEnvelope> read = new ArrayList<>();
    for (SicctEnvelope envelope; (envelope = SicctEnvelope.read(in)) != null; ) {
      read.add(envelope);
    }
    assertEquals(expected, read);
  }

  @Test
  @DisplayName(
      "Fehlerhafte Umschläge: zu kurz, Länge passt nicht, unbekannter Typ, abgebrochener Strom")
  void fehlerfaelle() {
    assertThrows(IOException.class, () -> SicctEnvelope.decode(HEX.parseHex("6b0000000100")));
    assertThrows(
        IOException.class, () -> SicctEnvelope.decode(HEX.parseHex("6b000000010000000005802800")));
    IOException unknown =
        assertThrows(
            IOException.class,
            () -> SicctEnvelope.decode(HEX.parseHex("770000000100000000029000")));
    assertTrue(unknown.getMessage().contains("77"), unknown.getMessage());
    assertThrows(
        EOFException.class,
        () -> SicctEnvelope.read(new ByteArrayInputStream(HEX.parseHex("8300000001000000000290"))));
    assertThrows(
        EOFException.class,
        () -> SicctEnvelope.read(new ByteArrayInputStream(HEX.parseHex("8300"))));
    assertThrows(
        IOException.class,
        () -> SicctEnvelope.read(new ByteArrayInputStream(HEX.parseHex("8300000001007fffffff"))));
    assertNull(
        assertDoesNotThrowIo(() -> SicctEnvelope.read(new ByteArrayInputStream(new byte[0]))));
  }

  @Test
  @DisplayName("Tabelle 16: C-Kommandos nur mit Sequenznummer 0000–FCFF, FU und Sequenz 16 Bit")
  void kommandoSequenz() {
    assertArrayEquals(
        HEX.parseHex("6b0001fcff00000000029000"),
        SicctEnvelope.command(1, 0xFCFF, HEX.parseHex("9000")).encode());
    assertThrows(
        IllegalArgumentException.class, () -> SicctEnvelope.command(1, 0xFD00, new byte[0]));
    assertThrows(
        IllegalArgumentException.class, () -> SicctEnvelope.command(0x10000, 1, new byte[0]));
  }

  interface IoSupplier<T> {
    T get() throws IOException;
  }

  static <T> T assertDoesNotThrowIo(IoSupplier<T> supplier) {
    try {
      return supplier.get();
    } catch (IOException e) {
      throw new AssertionError(e);
    }
  }
}

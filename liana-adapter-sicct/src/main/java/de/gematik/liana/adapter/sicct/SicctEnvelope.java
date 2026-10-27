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

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HexFormat;

/**
 * SICCT envelope per SICCT 1.2.3 §6.2.4.2, table 16: a 10-byte header before every C-command,
 * R-command and event message.
 *
 * <pre>
 * Offset 0  bMessageType   1 byte   6B C-command, 83 R-command, 50 event message
 * Offset 1  wSrcOrDesAddr  2 bytes  destination (C) or source FU (R, event), network byte order
 * Offset 3  wSeq           2 bytes  0000–FCFF commands, FD00–FFFF events
 * Offset 5  abRFU          1 byte   00
 * Offset 6  dwLength       4 bytes  length of abCmd
 * Offset 10 abCmd                   SICCT or card APDU, TLV for events
 * </pre>
 *
 * @param type message type
 * @param fu destination or source FU: {@code 0000} the terminal, {@code 0001}–{@code 00FF} ICC
 *     1–255
 * @param seq sequence number
 * @param payload abCmd
 */
public record SicctEnvelope(Type type, int fu, int seq, byte[] payload) {

  /** Length of the header. */
  public static final int HEADER_LENGTH = 10;

  /** FU of the SICCT terminal itself. */
  public static final int FU_TERMINAL = 0x0000;

  /** Highest sequence number of a command; the events start above it (FD00–FFFF). */
  public static final int MAX_COMMAND_SEQ = 0xFCFF;

  /** Maximum length of abCmd that LIANA accepts (extended APDU with response, generous). */
  static final int MAX_PAYLOAD = 1 << 20;

  private static final HexFormat HEX = HexFormat.of().withUpperCase();

  /** bMessageType */
  public enum Type {
    C_COMMAND(0x6B),
    R_COMMAND(0x83),
    EVENT(0x50);

    private final int value;

    Type(int value) {
      this.value = value;
    }

    public int value() {
      return value;
    }

    static Type of(int value) throws IOException {
      for (Type type : values()) {
        if (type.value == value) {
          return type;
        }
      }
      throw new IOException(
          String.format("SICCT-Umschlag: unbekannter Nachrichtentyp %02X", value));
    }
  }

  public SicctEnvelope {
    if (fu < 0 || fu > 0xFFFF || seq < 0 || seq > 0xFFFF) {
      throw new IllegalArgumentException("FU und Sequenznummer sind 16 Bit");
    }
    payload = payload.clone();
  }

  /** C-command to {@code fu}. */
  public static SicctEnvelope command(int fu, int seq, byte[] apdu) {
    if (seq > MAX_COMMAND_SEQ) {
      throw new IllegalArgumentException(
          String.format("Sequenznummer %04X liegt im Ereignisbereich", seq));
    }
    return new SicctEnvelope(Type.C_COMMAND, fu, seq, apdu);
  }

  @Override
  public byte[] payload() {
    return payload.clone();
  }

  /** The whole envelope, header and abCmd. */
  public byte[] encode() {
    return ByteBuffer.allocate(HEADER_LENGTH + payload.length)
        .put((byte) type.value)
        .putShort((short) fu)
        .putShort((short) seq)
        .put((byte) 0)
        .putInt(payload.length)
        .put(payload)
        .array();
  }

  /** Exactly one envelope in {@code bytes}. */
  public static SicctEnvelope decode(byte[] bytes) throws IOException {
    if (bytes.length < HEADER_LENGTH) {
      throw new IOException("SICCT-Umschlag kürzer als der Kopf: " + bytes.length + " Byte");
    }
    int length = ByteBuffer.wrap(bytes, 6, 4).getInt();
    if (length < 0 || length != bytes.length - HEADER_LENGTH) {
      throw new IOException(
          "SICCT-Umschlag: dwLength "
              + Integer.toUnsignedString(length)
              + ", abCmd "
              + (bytes.length - HEADER_LENGTH)
              + " Byte");
    }
    return fromHeader(bytes, Arrays.copyOfRange(bytes, HEADER_LENGTH, bytes.length));
  }

  /** Reads the next envelope; {@code null} if the data stream ends before a new header. */
  public static SicctEnvelope read(InputStream in) throws IOException {
    byte[] header = new byte[HEADER_LENGTH];
    int first = in.read();
    if (first < 0) {
      return null;
    }
    header[0] = (byte) first;
    readFully(in, header, 1);
    int length = ByteBuffer.wrap(header, 6, 4).getInt();
    if (length < 0 || length > MAX_PAYLOAD) {
      throw new IOException(
          "SICCT-Umschlag: dwLength " + Integer.toUnsignedString(length) + " zu groß");
    }
    byte[] payload = new byte[length];
    readFully(in, payload, 0);
    return fromHeader(header, payload);
  }

  private static SicctEnvelope fromHeader(byte[] header, byte[] payload) throws IOException {
    Type type = Type.of(header[0] & 0xFF);
    int fu = ((header[1] & 0xFF) << 8) | (header[2] & 0xFF);
    int seq = ((header[3] & 0xFF) << 8) | (header[4] & 0xFF);
    return new SicctEnvelope(type, fu, seq, payload);
  }

  private static void readFully(InputStream in, byte[] buffer, int offset) throws IOException {
    for (int read = offset; read < buffer.length; ) {
      int n = in.read(buffer, read, buffer.length - read);
      if (n < 0) {
        throw new EOFException(
            "SICCT-Umschlag nach " + read + " von " + buffer.length + " Byte abgebrochen");
      }
      read += n;
    }
  }

  @Override
  public boolean equals(Object other) {
    return other instanceof SicctEnvelope that
        && type == that.type
        && fu == that.fu
        && seq == that.seq
        && Arrays.equals(payload, that.payload);
  }

  @Override
  public int hashCode() {
    return 31 * (31 * (31 * type.hashCode() + fu) + seq) + Arrays.hashCode(payload);
  }

  @Override
  public String toString() {
    return String.format("%s FU %04X seq %04X %s", type, fu, seq, HEX.formatHex(payload));
  }
}

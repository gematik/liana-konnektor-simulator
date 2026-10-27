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

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/** APDU and TLV building blocks for the trusted channel (LIANA-28, LIANA-112.13). */
final class Apdus {

  private static final System.Logger LOG = System.getLogger(Apdus.class.getName());
  static final byte[] OK = {(byte) 0x90, 0x00};
  static final byte[] WRONG_DATA = {0x6A, (byte) 0x80};

  private Apdus() {}

  static boolean isOk(byte[] response) {
    return response.length >= 2
        && (response[response.length - 2] & 0xFF) == 0x90
        && response[response.length - 1] == 0;
  }

  static byte[] status(byte[] response) {
    return response.length < 2
        ? WRONG_DATA
        : Arrays.copyOfRange(response, response.length - 2, response.length);
  }

  /** Data field of a short APDU (case 3 or 4). */
  static byte[] data(byte[] command) {
    int lc = command[4] & 0xFF;
    return command.length >= 5 + lc && lc > 0
        ? Arrays.copyOfRange(command, 5, 5 + lc)
        : new byte[0];
  }

  /** The top-level TLV fields, per tag (one or two bytes). */
  static Map<Integer, byte[]> fields(byte[] data) {
    Map<Integer, byte[]> fields = new HashMap<>();
    try {
      for (int offset = 0; offset < data.length; ) {
        Cvc.Tlv tlv = Cvc.Tlv.read(data, offset);
        fields.putIfAbsent(tlv.tag(), tlv.value());
        offset = tlv.end();
      }
    } catch (IllegalArgumentException e) {
      LOG.log(System.Logger.Level.DEBUG, "TLV nicht lesbar: {0}", e.getMessage());
    }
    return fields;
  }

  static byte[] apdu(int cla, int ins, int p1, int p2, byte[] data) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.writeBytes(new byte[] {(byte) cla, (byte) ins, (byte) p1, (byte) p2, (byte) data.length});
    out.writeBytes(data);
    return out.toByteArray();
  }

  static byte[] withLe(byte[] command) {
    return concat(command, new byte[] {0});
  }

  static byte[] tlv(int tag, byte[] value) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    if (tag > 0xFF) {
      out.write(tag >> 8);
    }
    out.write(tag);
    Cvc.Tlv.length(out, value.length);
    out.writeBytes(value);
    return out.toByteArray();
  }

  static byte[] concat(byte[] a, byte[] b) {
    byte[] out = Arrays.copyOf(a, a.length + b.length);
    System.arraycopy(b, 0, out, a.length, b.length);
    return out;
  }
}

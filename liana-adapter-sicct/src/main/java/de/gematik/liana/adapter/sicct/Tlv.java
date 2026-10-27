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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * BER-TLV, as far as SICCT needs it (SICCT 1.2.3 §5.5.10.3): tags of one or two bytes (subsequent
 * byte for {@code xx1F}), lengths short up to 127 or {@code 81}/{@code 82} with one or two bytes.
 *
 * @param tag tag as a number, e.g. {@code 0x63} or {@code 0x5F41}
 * @param value value
 */
public record Tlv(int tag, byte[] value) {

  public Tlv {
    value = value.clone();
  }

  @Override
  public byte[] value() {
    return value.clone();
  }

  /** The data objects in {@code bytes}, one after another. */
  public static List<Tlv> parse(byte[] bytes) throws IOException {
    List<Tlv> objects = new ArrayList<>();
    int i = 0;
    while (i < bytes.length) {
      int tag = bytes[i++] & 0xFF;
      if ((tag & 0x1F) == 0x1F) {
        need(bytes, i, 1);
        tag = (tag << 8) | (bytes[i++] & 0xFF);
      }
      need(bytes, i, 1);
      int length = bytes[i++] & 0xFF;
      if (length == 0x81) {
        need(bytes, i, 1);
        length = bytes[i++] & 0xFF;
      } else if (length == 0x82) {
        need(bytes, i, 2);
        length = ((bytes[i] & 0xFF) << 8) | (bytes[i + 1] & 0xFF);
        i += 2;
      } else if (length > 0x7F) {
        throw new IOException(String.format("TLV: Längenkodierung %02X nicht unterstützt", length));
      }
      need(bytes, i, length);
      objects.add(new Tlv(tag, Arrays.copyOfRange(bytes, i, i + length)));
      i += length;
    }
    return objects;
  }

  /** The first data object with {@code tag}. */
  public static Optional<Tlv> find(List<Tlv> objects, int tag) {
    return objects.stream().filter(o -> o.tag == tag).findFirst();
  }

  /** Tag, length and value. */
  public byte[] encode() {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    if (tag > 0xFF) {
      out.write(tag >> 8);
    }
    out.write(tag & 0xFF);
    if (value.length > 0xFF) {
      out.write(0x82);
      out.write(value.length >> 8);
      out.write(value.length & 0xFF);
    } else if (value.length > 0x7F) {
      out.write(0x81);
      out.write(value.length);
    } else {
      out.write(value.length);
    }
    out.writeBytes(value);
    return out.toByteArray();
  }

  private static void need(byte[] bytes, int offset, int count) throws IOException {
    if (offset + count > bytes.length) {
      throw new IOException("TLV: abgeschnitten bei Byte " + offset + " von " + bytes.length);
    }
  }

  @Override
  public boolean equals(Object other) {
    return other instanceof Tlv that && tag == that.tag && Arrays.equals(value, that.value);
  }

  @Override
  public int hashCode() {
    return 31 * tag + Arrays.hashCode(value);
  }

  @Override
  public String toString() {
    return String.format("%X:%s", tag, java.util.HexFormat.of().formatHex(value));
  }
}

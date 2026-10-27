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
import java.util.HexFormat;

/**
 * CV certificate per gemSpec_PKI 6.4.5 ({@code 7F21}), as far as LIANA needs it for the trusted
 * channel: CAR, CHR and public key. The card verifies the signature (PSO VERIFY CERTIFICATE), not
 * LIANA.
 *
 * @param encoded the whole certificate with {@code 7F21}
 * @param car Certification Authority Reference (8 bytes)
 * @param chr Certificate Holder Reference (8 bytes for CAs, 12 bytes for end entities)
 * @param publicKey uncompressed point ({@code 04 || x || y})
 */
public record Cvc(byte[] encoded, byte[] car, byte[] chr, byte[] publicKey) {

  private static final HexFormat HEX = HexFormat.of().withUpperCase();

  public Cvc {
    encoded = encoded.clone();
    car = car.clone();
    chr = chr.clone();
    publicKey = publicKey.clone();
  }

  /**
   * Reads a CVC, with or without the outer tag {@code 7F21}: without it, it is the data field of
   * PSO VERIFY CERTIFICATE ({@code 7F4E … 5F37 …}, gemSpec_COS 14.8.7).
   */
  public static Cvc parse(byte[] data) {
    byte[] content = data;
    if (data.length > 2 && (data[0] & 0xFF) == 0x7F && (data[1] & 0xFF) == 0x21) {
      content = Tlv.read(data, 0).value();
    }
    Tlv body = Tlv.read(content, 0);
    if (body.tag() != 0x7F4E) {
      throw new IllegalArgumentException(
          "kein CVC: erwartet 7F4E, gefunden " + Integer.toHexString(body.tag()));
    }
    byte[] car = null;
    byte[] chr = null;
    byte[] point = null;
    for (int offset = 0; offset < body.value().length; ) {
      Tlv field = Tlv.read(body.value(), offset);
      switch (field.tag()) {
        case 0x42 -> car = field.value();
        case 0x5F20 -> chr = field.value();
        case 0x7F49 -> {
          for (int inner = 0; inner < field.value().length; ) {
            Tlv key = Tlv.read(field.value(), inner);
            if (key.tag() == 0x86) {
              point = key.value();
            }
            inner = key.end();
          }
        }
        default -> {}
      }
      offset = field.end();
    }
    if (car == null || chr == null || point == null) {
      throw new IllegalArgumentException("CVC ohne CAR, CHR oder öffentlichen Schlüssel");
    }
    byte[] encoded = content == data ? wrap(content) : data.clone();
    return new Cvc(encoded, car, chr, point);
  }

  /** Data field for PSO VERIFY CERTIFICATE: the content of {@code 7F21}. */
  public byte[] content() {
    return Tlv.read(encoded, 0).value();
  }

  @Override
  public byte[] encoded() {
    return encoded.clone();
  }

  @Override
  public byte[] car() {
    return car.clone();
  }

  @Override
  public byte[] chr() {
    return chr.clone();
  }

  @Override
  public byte[] publicKey() {
    return publicKey.clone();
  }

  @Override
  public boolean equals(Object other) {
    return other instanceof Cvc cvc && Arrays.equals(encoded, cvc.encoded);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(encoded);
  }

  @Override
  public String toString() {
    return "Cvc[CHR " + HEX.formatHex(chr) + ", CAR " + HEX.formatHex(car) + "]";
  }

  private static byte[] wrap(byte[] content) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.write(0x7F);
    out.write(0x21);
    Tlv.length(out, content.length);
    out.writeBytes(content);
    return out.toByteArray();
  }

  /** BER-TLV with one- or two-byte tag and length up to 3 bytes. */
  record Tlv(int tag, byte[] value, int end) {

    static Tlv read(byte[] data, int offset) {
      try {
        int tag = data[offset++] & 0xFF;
        if ((tag & 0x1F) == 0x1F) {
          tag = tag << 8 | data[offset++] & 0xFF;
        }
        int length = data[offset++] & 0xFF;
        if (length == 0x81) {
          length = data[offset++] & 0xFF;
        } else if (length == 0x82) {
          length = (data[offset] & 0xFF) << 8 | data[offset + 1] & 0xFF;
          offset += 2;
        } else if (length > 0x7F) {
          throw new IllegalArgumentException("TLV-Länge ungültig");
        }
        if (offset + length > data.length) {
          throw new IllegalArgumentException("TLV abgeschnitten");
        }
        return new Tlv(tag, Arrays.copyOfRange(data, offset, offset + length), offset + length);
      } catch (ArrayIndexOutOfBoundsException e) {
        throw new IllegalArgumentException("TLV abgeschnitten", e);
      }
    }

    static void length(ByteArrayOutputStream out, int length) {
      if (length < 0x80) {
        out.write(length);
      } else if (length <= 0xFF) {
        out.write(0x81);
        out.write(length);
      } else {
        out.write(0x82);
        out.write(length >> 8);
        out.write(length);
      }
    }
  }
}

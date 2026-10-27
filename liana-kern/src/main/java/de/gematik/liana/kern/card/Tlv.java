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
package de.gematik.liana.kern.card;

import java.util.Arrays;
import java.util.HexFormat;

/** Minimal BER-TLV reader for the files TUC_KON_001 reads (EF.GDO, EF.ATR, EF.Version2). */
final class Tlv {

  private Tlv() {}

  /**
   * Value of the first data object with {@code tag} (hex, e.g. {@code "5A"} or {@code "5F52"}) at
   * the top level of {@code data}; {@code null} if it is missing or the encoding is broken.
   */
  static byte[] find(byte[] data, String tag) {
    byte[] wanted = HexFormat.of().parseHex(tag);
    int i = 0;
    while (i < data.length) {
      int tagStart = i;
      if (data[i] == 0x00 || data[i] == (byte) 0xFF) {
        i++;
        continue;
      }
      if ((data[i] & 0x1F) == 0x1F) {
        do {
          i++;
        } while (i < data.length && (data[i] & 0x80) != 0);
      }
      i++;
      if (i >= data.length) {
        return null;
      }
      byte[] currentTag = Arrays.copyOfRange(data, tagStart, i);
      int length = data[i++] & 0xFF;
      if (length > 0x80) {
        int octets = length & 0x7F;
        length = 0;
        for (int k = 0; k < octets && i < data.length; k++) {
          length = (length << 8) | (data[i++] & 0xFF);
        }
      }
      if (i + length > data.length) {
        return null;
      }
      if (Arrays.equals(currentTag, wanted)) {
        return Arrays.copyOfRange(data, i, i + length);
      }
      i += length;
    }
    return null;
  }
}

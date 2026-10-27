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
package de.gematik.liana.kern.vsdm;

import java.time.YearMonth;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * The VersichertenDatenTemplate of the KVK (KBV-Merkblatt KVK 2.05, table 1) with the checks from
 * [gemSpec_FM_VSDM] Annex E (LIANA-113, VSDM-A_2611):
 *
 * <ul>
 *   <li>tag {@code '60'}, length 70–212 (short or long BER form) and exactly that many bytes up to
 *       the checksum,
 *   <li>only the tags from table 1, each at most once, with lengths in the permitted range;
 *       VersichertenStatus with length 4 or, for cards of an older standard, 1 (note 1); VKNR,
 *       StatusErgänzung and, deviating from the KVK specification, the GültigkeitsDatum may be
 *       missing,
 *   <li>values in the restricted character set per DIN 66003 (table 4), numeric ones digits only;
 *       the postal code is alphanumeric only with WohnsitzLänderCode,
 *   <li>GeburtsDatum TTMMJJJJ with day and month 00 (month 00 only with day 00, Tab_FM_VSDM_25),
 *       GültigkeitsDatum MMJJ,
 *   <li>PrüfSumme {@code '8E'} as the last data object: XOR over all bytes from tag {@code '60'} up
 *       to its length ({@link ChecksumException}).
 * </ul>
 *
 * Not checked: ATR header, ATR data, DIR data, filler and last bytes. The connector's view ends at
 * the template (READ BINARY from offset 0000 after SELECT of the application); what lies before and
 * after is checked by the card terminal on SELECT (KBV-Merkblatt 4.1, {@code 6A82}). Also not: the
 * common maximum lengths for printing (notes 2 and 3), which the Merkblatt specifies for the forms.
 */
public final class KvkTemplate {

  /** Data type of a data object (Tab_FM_VSDM_25). */
  private enum Type {
    ALPHANUMERIC,
    NUMERIC,
    BIRTH_DATE,
    VALIDITY
  }

  /** A data object from table 1: tag, length, type, mandatory. */
  private record Field(int tag, String name, int min, int max, Type type, boolean mandatory) {}

  static final int TEMPLATE = 0x60;
  static final int CHECKSUM = 0x8E;
  private static final int VALIDITY = 0x8D;
  private static final int STATUS = 0x83;
  private static final int COUNTRY = 0x8A;
  private static final int POSTCODE = 0x8B;
  private static final Map<Integer, Field> FIELDS = new LinkedHashMap<>();

  static {
    field(0x80, "KrankenKassenName", 2, 28, Type.ALPHANUMERIC, true);
    field(0x81, "KrankenKassenNummer", 7, 7, Type.NUMERIC, true);
    field(0x8F, "VKNR", 5, 5, Type.NUMERIC, false);
    field(0x82, "VersichertenNummer", 6, 12, Type.NUMERIC, true);
    field(STATUS, "VersichertenStatus", 1, 4, Type.NUMERIC, true);
    field(0x90, "StatusErgänzung", 1, 1, Type.ALPHANUMERIC, false);
    field(0x84, "Titel", 2, 15, Type.ALPHANUMERIC, false);
    field(0x85, "VorName", 1, 28, Type.ALPHANUMERIC, false);
    field(0x86, "NamensZusatz/VorsatzWort", 1, 15, Type.ALPHANUMERIC, false);
    field(0x87, "FamilienName", 2, 28, Type.ALPHANUMERIC, true);
    field(0x88, "GeburtsDatum", 8, 8, Type.BIRTH_DATE, true);
    field(0x89, "StraßenName&HausNummer", 2, 28, Type.ALPHANUMERIC, false);
    field(COUNTRY, "WohnsitzLänderCode", 1, 3, Type.ALPHANUMERIC, false);
    field(POSTCODE, "Postleitzahl", 4, 7, Type.NUMERIC, true);
    field(0x8C, "OrtsName", 2, 22, Type.ALPHANUMERIC, true);
    field(VALIDITY, "GültigkeitsDatum", 4, 4, Type.VALIDITY, false);
    field(CHECKSUM, "PrüfSumme", 1, 1, Type.ALPHANUMERIC, true);
  }

  /**
   * Special characters of the restricted character set (table 3) and Ä Ö Ü ä ö ü ß in DIN 66003
   * (table 4).
   */
  private static final Set<Integer> SPECIAL =
      Set.of(
          0x20, 0x26, 0x27, 0x28, 0x29, 0x2B, 0x2D, 0x2E, 0x2F, 0x5F, 0x5B, 0x5C, 0x5D, 0x7B, 0x7C,
          0x7D, 0x7E);

  /** The checksum does not match (3021). */
  public static final class ChecksumException extends IllegalArgumentException {

    ChecksumException(String message) {
      super(message);
    }
  }

  private final byte[] bytes;
  private final Map<Integer, byte[]> values;

  private KvkTemplate(byte[] bytes, Map<Integer, byte[]> values) {
    this.bytes = bytes;
    this.values = values;
  }

  private static void field(int tag, String name, int min, int max, Type type, boolean mandatory) {
    FIELDS.put(tag, new Field(tag, name, min, max, type, mandatory));
  }

  /**
   * Checks {@code data} (from tag '60', as READ BINARY returns it). {@link ChecksumException} on a
   * wrong checksum, {@link IllegalArgumentException} with the reason on any other violation.
   */
  public static KvkTemplate parse(byte[] data) {
    if (data.length < 2 || (data[0] & 0xFF) != TEMPLATE) {
      throw new IllegalArgumentException("kein VersichertenDatenTemplate (Tag '60')");
    }
    int offset = 1;
    int length = data[offset++] & 0xFF;
    if (length == 0x81 && data.length > 2) {
      length = data[offset++] & 0xFF;
    }
    if (length < 70 || length > 212) {
      throw new IllegalArgumentException(
          "Länge des VersichertenDatenTemplates " + length + ", zulässig 70–212");
    }
    if (offset + length > data.length) {
      throw new IllegalArgumentException(
          "VersichertenDatenTemplate mit Länge "
              + length
              + ", gelesen "
              + (data.length - offset)
              + " Byte");
    }
    byte[] template = Arrays.copyOf(data, offset + length);
    Map<Integer, byte[]> values = new LinkedHashMap<>();
    int end = offset + length;
    while (offset < end) {
      int tag = template[offset++] & 0xFF;
      Field field = FIELDS.get(tag);
      if (field == null) {
        throw new IllegalArgumentException(String.format("unzulässiger Tag '%02X'", tag));
      }
      if (values.containsKey(tag)) {
        throw new IllegalArgumentException(field.name() + " doppelt");
      }
      if (offset >= end) {
        throw new IllegalArgumentException(field.name() + " ohne Länge");
      }
      int n = template[offset++] & 0xFF;
      if (offset + n > end) {
        throw new IllegalArgumentException(
            field.name() + " mit Länge " + n + " über das Template hinaus");
      }
      if (n < field.min() || n > field.max() || tag == STATUS && n != 1 && n != 4) {
        throw new IllegalArgumentException(
            field.name()
                + " mit Länge "
                + n
                + ", zulässig "
                + (tag == STATUS ? "4 oder 1" : field.min() + "–" + field.max()));
      }
      values.put(tag, Arrays.copyOfRange(template, offset, offset + n));
      offset += n;
      if (tag == CHECKSUM && offset != end) {
        throw new IllegalArgumentException("Daten nach der PrüfSumme");
      }
    }
    for (Field field : FIELDS.values()) {
      if (field.mandatory() && !values.containsKey(field.tag())) {
        throw new IllegalArgumentException(field.name() + " fehlt");
      }
    }
    int xor = 0;
    for (int i = 0; i < template.length - 1; i++) {
      xor ^= template[i] & 0xFF;
    }
    int checksum = template[template.length - 1] & 0xFF;
    if (xor != checksum) {
      throw new ChecksumException(
          String.format("PrüfSumme '%02X', berechnet '%02X'", checksum, xor));
    }
    for (Map.Entry<Integer, byte[]> value : values.entrySet()) {
      if (value.getKey() != CHECKSUM) {
        check(FIELDS.get(value.getKey()), value.getValue(), values.containsKey(COUNTRY));
      }
    }
    return new KvkTemplate(template, values);
  }

  private static void check(Field field, byte[] value, boolean country) {
    Type type = field.tag() == POSTCODE && country ? Type.ALPHANUMERIC : field.type();
    for (byte b : value) {
      int c = b & 0xFF;
      boolean digit = c >= '0' && c <= '9';
      boolean allowed =
          type == Type.ALPHANUMERIC
              ? digit || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || SPECIAL.contains(c)
              : digit;
      if (!allowed) {
        throw new IllegalArgumentException(
            String.format("%s mit unzulässigem Zeichen '%02X'", field.name(), c));
      }
    }
    String text = new String(value, java.nio.charset.StandardCharsets.US_ASCII);
    if (type == Type.BIRTH_DATE) {
      int day = Integer.parseInt(text.substring(0, 2));
      int month = Integer.parseInt(text.substring(2, 4));
      if (day > 31 || month > 12 || month == 0 && day != 0) {
        throw new IllegalArgumentException(field.name() + " " + text + " ist kein TTMMJJJJ");
      }
    } else if (type == Type.VALIDITY) {
      int month = Integer.parseInt(text.substring(0, 2));
      if (month < 1 || month > 12) {
        throw new IllegalArgumentException(field.name() + " " + text + " ist kein MMJJ");
      }
    }
  }

  /** The checked template from tag '60' up to the checksum, unchanged. */
  public byte[] bytes() {
    return bytes.clone();
  }

  /** The GültigkeitsDatum as month (JJ as 20JJ), {@code null} without data object '8D'. */
  public YearMonth validity() {
    byte[] value = values.get(VALIDITY);
    if (value == null) {
      return null;
    }
    String text = new String(value, java.nio.charset.StandardCharsets.US_ASCII);
    return YearMonth.of(
        2000 + Integer.parseInt(text.substring(2, 4)), Integer.parseInt(text.substring(0, 2)));
  }

  /**
   * Whether the GültigkeitsDatum is before {@code now}; the card is valid until the end of the
   * named month.
   */
  public boolean expiredAt(YearMonth now) {
    YearMonth validity = validity();
    return validity != null && validity.isBefore(now);
  }
}

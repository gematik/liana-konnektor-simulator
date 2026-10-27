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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.YearMonth;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Check of the VersichertenDatenTemplate per [gemSpec_FM_VSDM] Annex E and KBV-Merkblatt KVK 2.05
 * (LIANA-113).
 */
class KvkTemplateTest {

  /** The template from support/images/kvk/kvk-valid.xml. */
  static final String KVK_VALID =
      "607F800F546573746B61737365204C49414E418107313233343536378F053939393939820A3132333435"
          + "3637383930830431303030900131840344722E85054572696B61870A4D75737465726D616E6E880831323038313936348"
          + "90D54657374737472617373652031"
          + "8B0531303131378C064265726C696E8D04313233308E01B3";

  /**
   * The fields of kvk-valid; {@link #template} builds a template with a correct checksum from them.
   */
  private static Map<Integer, String> fields() {
    Map<Integer, String> fields = new LinkedHashMap<>();
    fields.put(0x80, "Testkasse LIANA");
    fields.put(0x81, "1234567");
    fields.put(0x8F, "99999");
    fields.put(0x82, "1234567890");
    fields.put(0x83, "1000");
    fields.put(0x90, "1");
    fields.put(0x84, "Dr.");
    fields.put(0x85, "Erika");
    fields.put(0x87, "Mustermann");
    fields.put(0x88, "12081964");
    fields.put(0x89, "Teststrasse 1");
    fields.put(0x8B, "10117");
    fields.put(0x8C, "Berlin");
    fields.put(0x8D, "1230");
    return fields;
  }

  private static byte[] template(Map<Integer, String> fields) {
    ByteArrayOutputStream body = new ByteArrayOutputStream();
    fields.forEach(
        (tag, value) -> {
          byte[] v = value.getBytes(StandardCharsets.ISO_8859_1);
          body.write(tag);
          body.write(v.length);
          body.writeBytes(v);
        });
    body.write(0x8E);
    body.write(1);
    int length = body.size() + 1;
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.write(0x60);
    if (length > 127) {
      out.write(0x81);
    }
    out.write(length);
    out.writeBytes(body.toByteArray());
    int xor = 0;
    for (byte b : out.toByteArray()) {
      xor ^= b & 0xFF;
    }
    out.write(xor);
    return out.toByteArray();
  }

  @Test
  @DisplayName(
      "VSDM-A_2609: kvk-valid besteht die Prüfung, bytes() ist das Template unverändert, Gültigkeit 12/2030")
  void kvkValid() {
    byte[] data = HexFormat.of().parseHex(KVK_VALID);
    assertArrayEquals(data, template(fields()));
    KvkTemplate template = KvkTemplate.parse(data);
    assertArrayEquals(data, template.bytes());
    assertEquals(YearMonth.of(2030, 12), template.validity());
    assertFalse(template.expiredAt(YearMonth.of(2030, 12)));
    assertTrue(template.expiredAt(YearMonth.of(2031, 1)));
  }

  @Test
  @DisplayName(
      "Anhang E: Bytes hinter dem Template (Filler, Rest des Speichers) gehören nicht zur Antwort")
  void bytesHinterDemTemplate() {
    byte[] data = HexFormat.of().parseHex(KVK_VALID + "2020200000");
    assertArrayEquals(HexFormat.of().parseHex(KVK_VALID), KvkTemplate.parse(data).bytes());
  }

  @Test
  @DisplayName("VSDM-A_2611 / 3021: falsche Prüfsumme ist eine ChecksumException")
  void pruefsumme() {
    byte[] data = HexFormat.of().parseHex(KVK_VALID);
    data[data.length - 1] ^= 1;
    var e = assertThrows(KvkTemplate.ChecksumException.class, () -> KvkTemplate.parse(data));
    assertEquals("PrüfSumme 'B2', berechnet 'B3'", e.getMessage());
  }

  @Test
  @DisplayName(
      "KBV-Merkblatt Anmerkung 1 und Anhang E: ohne VKNR, StatusErgänzung und GültigkeitsDatum, "
          + "VersichertenStatus mit Länge 1 (ältere Karten); Umlaute und ß nach DIN 66003; lange Längenform 81")
  void aeltereKarten() {
    Map<Integer, String> fields = fields();
    fields.remove(0x8F);
    fields.remove(0x90);
    fields.remove(0x8D);
    fields.put(0x83, "1");
    fields.put(0x89, "Gr~e Stra~e 1"); // ß
    fields.put(0x87, "M{ller-L\\denscheid"); // ä and Ö
    assertNull(KvkTemplate.parse(template(fields)).validity());

    Map<Integer, String> lang = fields();
    lang.put(0x80, "Testkasse LIANA mit Namen xx");
    lang.put(0x85, "Erika Maria Anna Luise Paula");
    lang.put(0x8C, "Berlin Mitte Moabit xy");
    lang.put(0x84, "Prof. Dr. med.");
    byte[] data = template(lang);
    assertEquals(0x81, data[1] & 0xFF);
    KvkTemplate.parse(data);
  }

  @Test
  @DisplayName(
      "Anhang E / VSDM-A_2611 / 3020: unzulässiger Tag, doppelter Tag, Pflichtfeld fehlt, Länge außerhalb, "
          + "Zeichen außerhalb DIN 66003, Ziffern in numerischen Feldern, GeburtsDatum, GültigkeitsDatum")
  void verstoesse() {
    List<String> reasons = new ArrayList<>();
    for (Map<Integer, String> fields :
        List.of(
            with(0x91, "x"),
            without(0x87),
            with(0x81, "123456"),
            with(0x83, "10"),
            with(0x87, "Muster@mann"),
            with(0x82, "12345A7890"),
            with(0x88, "32081964"),
            with(0x88, "01001964"),
            with(0x8D, "1330"),
            with(0x8B, "1O117"))) {
      var e =
          assertThrows(IllegalArgumentException.class, () -> KvkTemplate.parse(template(fields)));
      assertFalse(e instanceof KvkTemplate.ChecksumException);
      reasons.add(e.getMessage());
    }
    assertEquals(
        List.of(
            "unzulässiger Tag '91'",
            "FamilienName fehlt",
            "KrankenKassenNummer mit Länge 6, zulässig 7–7",
            "VersichertenStatus mit Länge 2, zulässig 4 oder 1",
            "FamilienName mit unzulässigem Zeichen '40'",
            "VersichertenNummer mit unzulässigem Zeichen '41'",
            "GeburtsDatum 32081964 ist kein TTMMJJJJ",
            "GeburtsDatum 01001964 ist kein TTMMJJJJ",
            "GültigkeitsDatum 1330 ist kein MMJJ",
            "Postleitzahl mit unzulässigem Zeichen '4F'"),
        reasons);

    Map<Integer, String> mitLand = fields();
    mitLand.put(0x8A, "NL");
    mitLand.put(0x8B, "1012AB");
    KvkTemplate.parse(template(mitLand));
    Map<Integer, String> nullnull = fields();
    nullnull.put(0x88, "00001964");
    KvkTemplate.parse(template(nullnull));

    byte[] doppelt = HexFormat.of().parseHex("6050" + "80025858".repeat(20) + "8E0100");
    assertEquals(
        "KrankenKassenName doppelt",
        assertThrows(IllegalArgumentException.class, () -> KvkTemplate.parse(doppelt))
            .getMessage());
    assertEquals(
        "kein VersichertenDatenTemplate (Tag '60')",
        assertThrows(IllegalArgumentException.class, () -> KvkTemplate.parse(new byte[] {0x61, 0}))
            .getMessage());
    byte[] kurz = HexFormat.of().parseHex(KVK_VALID.substring(0, 100));
    assertEquals(
        "VersichertenDatenTemplate mit Länge 127, gelesen 48 Byte",
        assertThrows(IllegalArgumentException.class, () -> KvkTemplate.parse(kurz)).getMessage());
  }

  private static Map<Integer, String> with(int tag, String value) {
    Map<Integer, String> fields = fields();
    fields.put(tag, value);
    return fields;
  }

  private static Map<Integer, String> without(int tag) {
    Map<Integer, String> fields = fields();
    fields.remove(tag);
    return fields;
  }
}

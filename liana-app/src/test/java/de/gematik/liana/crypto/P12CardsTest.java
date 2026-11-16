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
package de.gematik.liana.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.adapter.fake.CardImages;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** LIANA-220: SMC-B from a PKCS#12, without kartos (the card itself: P12SmcbKartosIT). */
class P12CardsTest {

  private static final List<String> PASSWORDS =
      List.of("00", "changeit", "gematik", "12345678", "123456", "liana");

  @TempDir Path tmp;

  private P12Cards cards() {
    return new P12Cards(PASSWORDS, tmp.resolve("generated"));
  }

  @Test
  @DisplayName(
      "LIANA-220 Regel A: Telematik-ID 1-SMC-B-Testkarte--<15 Ziffern> → ICCSN 80276 und diese"
          + " Ziffern; Zertifikat, Schlüssel und ICCSN stehen in der Vorlage, kein Platzhalter bleibt")
  void ruleA() throws Exception {
    Path p12 = TestP12.write(tmp.resolve("smcb.p12"), "00", "1-SMC-B-Testkarte--883110000999901");

    Path image = cards().generate(p12);

    String xml = Files.readString(image);
    String der =
        HexFormat.of().withUpperCase().formatHex(TestP12.certificate(p12, "00").getEncoded());
    assertEquals(Optional.of("80276883110000999901"), CardImages.iccsn(image));
    assertTrue(xml.contains(der));
    assertTrue(xml.contains(String.format(">%04X<", der.length() / 2)));
    assertTrue(xml.contains("<attribute id=\"iccsn8\">6883110000999901</attribute>"));
    assertFalse(xml.matches("(?s).*@[A-Za-z0-9.]+@.*"), "Platzhalter übrig");
  }

  @Test
  @DisplayName(
      "LIANA-220 Regel B: andere Telematik-ID → ICCSN 80276 99999 und 10 Ziffern aus SHA-256 des"
          + " Zertifikats, gleich bei jedem Aufruf")
  void ruleB() throws Exception {
    Path p12 = TestP12.write(tmp.resolve("smcb.p12"), "00", "5-2-123456789");

    Path first = cards().generate(p12);
    Path second = new P12Cards(PASSWORDS, tmp.resolve("other")).generate(p12);

    String iccsn = CardImages.iccsn(first).orElseThrow();
    assertTrue(iccsn.matches("8027699999[0-9]{10}"), iccsn);
    assertEquals(Optional.of(iccsn), CardImages.iccsn(second));
    assertEquals(Files.readString(first), Files.readString(second));
  }

  @Test
  @DisplayName(
      "LIANA-220 Rateliste: Passwort aus card-p12.passwords oder leer; passt keins, nennt die"
          + " Meldung die Zahl der Versuche, nicht die Passwörter")
  void passwords() throws Exception {
    String telematikId = "1-SMC-B-Testkarte--883110000999902";
    cards().generate(TestP12.write(tmp.resolve("a.p12"), "changeit", telematikId));
    cards().generate(TestP12.write(tmp.resolve("b.p12"), "", telematikId));

    Path secret = TestP12.write(tmp.resolve("c.p12"), "geheim-220", telematikId);
    IllegalArgumentException e =
        assertThrows(IllegalArgumentException.class, () -> cards().generate(secret));

    assertEquals(
        "keine lesbare PKCS#12, keins der 7 Passwörter passt (card-p12.passwords und leeres"
            + " Passwort)",
        e.getMessage());
  }

  @Test
  @DisplayName(
      "LIANA-220 unbrauchbare PKCS#12: Schlüssel nicht brainpoolP256r1, ohne Telematik-ID,"
          + " Schlüssel passt nicht zum Zertifikat, Zertifikat ohne oid_smc_b_aut (GS-A_4445)")
  void unusable() throws Exception {
    Path p256 =
        TestP12.write(tmp.resolve("p256.p12"), "00", "1-SMC-B-Testkarte--1", "secp256r1", null);
    Path noAdmission = TestP12.write(tmp.resolve("ohne.p12"), "00", null);
    Path foreign =
        TestP12.write(
            tmp.resolve("fremd.p12"),
            "00",
            "1-SMC-B-Testkarte--1",
            "brainpoolP256r1",
            TestP12.keyPair("brainpoolP256r1").getPrivate());

    Path hba =
        TestP12.write(
            tmp.resolve("hba.p12"),
            "00",
            "1-SMC-B-Testkarte--1",
            "brainpoolP256r1",
            null,
            "1.2.276.0.76.4.75");

    assertTrue(
        message(hba)
            .endsWith("ohne Zertifikatstyp oid_smc_b_aut 1.2.276.0.76.4.77 (keine SMC-B AUT)"),
        message(hba));
    assertTrue(
        message(p256).startsWith("Schlüssel nicht brainpoolP256r1 (AUT_E256)"), message(p256));
    assertTrue(
        message(noAdmission).startsWith("keine Telematik-ID (Admission, registrationNumber)"),
        message(noAdmission));
    assertTrue(
        message(foreign).startsWith("Schlüssel passt nicht zum Zertifikat"), message(foreign));
  }

  @Test
  @DisplayName(
      "LIANA-220 CardImages: p12 im Ordner per Name (mit und ohne .p12) und ICCSN wählbar;"
          + " eine unbrauchbare p12 scheitert erst, wenn sie gewählt wird, mit Datei und Grund")
  void index() throws Exception {
    Path folder = tmp.resolve("images");
    TestP12.write(folder.resolve("smcb_private.p12"), "00", "1-SMC-B-Testkarte--883110000999903");
    Path broken = TestP12.write(folder.resolve("kaputt.p12"), "geheim-220", "x");
    CardImages images = new CardImages(List.of(folder), cards());

    Path image = images.resolve("smcb_private");

    assertEquals(image, images.resolve("smcb_private.p12"));
    assertEquals(image, images.resolve("80276883110000999903"));
    assertEquals(
        List.of("kaputt", "smcb_private"),
        images.images().stream().map(CardImages.Image::name).toList());
    assertEquals(
        folder.resolve("smcb_private.p12"),
        images.images().get(1).source(),
        "GET /admin/images zeigt die p12");
    IllegalArgumentException e =
        assertThrows(IllegalArgumentException.class, () -> images.resolve("kaputt"));
    assertTrue(e.getMessage().startsWith(broken + ": keine lesbare PKCS#12"), e.getMessage());
  }

  private String message(Path p12) {
    return assertThrows(IllegalArgumentException.class, () -> cards().generate(p12)).getMessage();
  }
}

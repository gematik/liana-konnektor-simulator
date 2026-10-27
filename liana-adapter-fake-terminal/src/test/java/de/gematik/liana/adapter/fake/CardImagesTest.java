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
package de.gematik.liana.adapter.fake;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** LIANA-98: card images by file name, ICCSN or path from a known set. */
class CardImagesTest {

  @TempDir Path tmp;

  /** Minimal image: EF.GDO with ICCSN as in the gematik images, without ICCSN any XML. */
  private Path image(String dir, String name, String iccsn) throws IOException {
    String body =
        iccsn == null
            ? "<configuration/>"
            : "<cardImage><child id=\"EF.GDO\" objectType=\"TransparentElementaryFile\"><attributes>"
                + "<attribute id=\"body\">5A0A"
                + iccsn
                + "</attribute></attributes></child></cardImage>";
    return Files.writeString(Files.createDirectories(tmp.resolve(dir)).resolve(name), body);
  }

  @Test
  @DisplayName("Dateiname mit und ohne .xml und ICCSN wählen dasselbe Image")
  void nameAndIccsn() throws IOException {
    Path egk = image("a", "egk-valid.xml", "80276883110000168584");
    image("a", "smcb-valid.xml", "80276883110000165043");
    CardImages images = new CardImages(List.of(tmp.resolve("a")));
    assertEquals(egk, images.resolve("egk-valid"));
    assertEquals(egk, images.resolve("egk-valid.xml"));
    assertEquals(egk, images.resolve("80276883110000168584"));
    assertEquals(Optional.of("80276883110000168584"), images.images().getFirst().iccsn());
  }

  @Test
  @DisplayName("Echtes gematik-Image: ICCSN aus EF.GDO von support/images/egk-valid.xml")
  void realImage() {
    CardImages images = new CardImages(List.of(Path.of("support/images")));
    assertEquals(Path.of("support/images/egk-valid.xml"), images.resolve("80276883110000168584"));
  }

  @Test
  @DisplayName("Derselbe Dateiname in mehreren Ordnern: der erste Ordner gewinnt")
  void firstDirectoryWins() throws IOException {
    image("b", "egk-valid.xml", "80276883110000000002");
    Path first = image("a", "egk-valid.xml", "80276883110000000001");
    CardImages images =
        new CardImages(List.of(tmp.resolve("leer"), tmp.resolve("a"), tmp.resolve("b")));
    assertEquals(first, images.resolve("egk-valid"));
  }

  @Test
  @DisplayName(
      "Mehrdeutige ICCSN bricht mit den Kandidaten ab; kein Treffer nennt die Ordner und Ähnliches")
  void ambiguousAndMissing() throws IOException {
    image("a", "egk-valid.xml", "80276883110000168584");
    image("b", "EGK_80276883110000168584_gema5.xml", "80276883110000168584");
    CardImages images = new CardImages(List.of(tmp.resolve("a"), tmp.resolve("b")));
    var ambiguous =
        assertThrows(IllegalArgumentException.class, () -> images.resolve("80276883110000168584"));
    assertTrue(
        ambiguous.getMessage().contains("mehrdeutig")
            && ambiguous.getMessage().contains("EGK_8027"),
        ambiguous.getMessage());
    var missing = assertThrows(IllegalArgumentException.class, () -> images.resolve("egk"));
    assertTrue(missing.getMessage().contains("ähnlich: [egk-valid"), missing.getMessage());
    assertThrows(IllegalArgumentException.class, () -> images.resolve("80276883110000000000"));
  }

  @Test
  @DisplayName("Absoluter Pfad umgeht den Index; XML ohne EF.GDO hat keine ICCSN")
  void absoluteAndNonCard() throws IOException {
    Path elsewhere = image("elsewhere", "karte.xml", null);
    CardImages images = new CardImages(List.of(tmp.resolve("a")));
    assertEquals(elsewhere, images.resolve(elsewhere.toString()));
    assertEquals(Optional.empty(), CardImages.iccsn(elsewhere));
    assertThrows(
        IllegalArgumentException.class, () -> images.resolve(tmp.resolve("fehlt.xml").toString()));
  }

  @Test
  @DisplayName("Ein nach dem Start abgelegtes Image wird beim ersten Fehlgriff gefunden")
  void rescan() throws IOException {
    Files.createDirectories(tmp.resolve("a"));
    CardImages images = new CardImages(List.of(tmp.resolve("a")));
    Path later = image("a", "hba-valid.xml", "80276883110000014332");
    assertEquals(later, images.resolve("80276883110000014332"));
  }
}

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

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

/**
 * The known card images (LIANA-98): all {@code *.xml} of the folders from {@code
 * liana.card-images}, indexed at startup. A value from the infrastructure object, the Admin API or
 * CATS selects exactly one image from them:
 *
 * <ul>
 *   <li>file name with or without {@code .xml} ({@code egk-valid}); if the same name is in several
 *       folders, the first in folder order wins,
 *   <li>ICCSN, 20 digits from EF.GDO ({@code 80276883110000168584}); if several images match, the
 *       value is ambiguous,
 *   <li>absolute path, which bypasses the index.
 * </ul>
 *
 * No match or an ambiguous match is an {@link IllegalArgumentException} with the candidates. LIANA
 * finds images added after startup, because a miss rebuilds the index once.
 */
public final class CardImages {

  public static final String EXTENSION = ".xml";
  private static final Pattern ICCSN = Pattern.compile("[0-9]{20}");

  /** An image in the index: file and ICCSN from EF.GDO, if it is a card with EF.GDO. */
  public record Image(Path file, Optional<String> iccsn) {

    public String name() {
      String file = this.file.getFileName().toString();
      return file.substring(0, file.length() - EXTENSION.length());
    }
  }

  private final List<Path> directories;
  private volatile List<Image> images;

  public CardImages(List<Path> directories) {
    this.directories = List.copyOf(directories);
    this.images = scan(this.directories);
  }

  public List<Path> directories() {
    return directories;
  }

  public List<Image> images() {
    return images;
  }

  /** The image for {@code value}; throws with the candidates if none or several match. */
  public Path resolve(String value) {
    try {
      return select(value, images);
    } catch (IllegalArgumentException first) {
      List<Image> rescanned = scan(directories);
      if (rescanned.equals(images)) {
        throw first;
      }
      images = rescanned;
      return select(value, rescanned);
    }
  }

  private Path select(String value, List<Image> index) {
    Path direct = Path.of(value);
    if (direct.isAbsolute()) {
      if (Files.isRegularFile(direct)) {
        return direct;
      }
      throw new IllegalArgumentException("Kartenimage " + value + " nicht gefunden");
    }
    if (ICCSN.matcher(value).matches()) {
      List<Image> hits =
          index.stream().filter(image -> image.iccsn().filter(value::equals).isPresent()).toList();
      if (hits.size() == 1) {
        return hits.getFirst().file();
      }
      if (hits.isEmpty()) {
        throw new IllegalArgumentException(
            "kein Kartenimage mit ICCSN " + value + " in " + directories);
      }
      throw new IllegalArgumentException(
          "ICCSN "
              + value
              + " ist mehrdeutig, passende Images: "
              + hits.stream().map(Image::file).toList()
              + "; Dateiname angeben");
    }
    String name =
        value.endsWith(EXTENSION) ? value.substring(0, value.length() - EXTENSION.length()) : value;
    return index.stream()
        .filter(image -> image.name().equals(name))
        .findFirst()
        .map(Image::file)
        .orElseThrow(
            () ->
                new IllegalArgumentException(
                    "Image '"
                        + value
                        + "' nicht gefunden in "
                        + directories
                        + candidates(name, index)));
  }

  /**
   * Images whose name contains the searched one, vice versa, or starts with the same word prefix
   * ({@code egk-…}).
   */
  private static String candidates(String name, List<Image> index) {
    String lower = name.toLowerCase(java.util.Locale.ROOT);
    String stem = lower.split("[-_.]", 2)[0];
    List<String> similar =
        index.stream()
            .map(Image::name)
            .filter(
                other -> {
                  String o = other.toLowerCase(java.util.Locale.ROOT);
                  return o.contains(lower)
                      || lower.contains(o)
                      || !stem.isEmpty() && o.startsWith(stem);
                })
            .distinct()
            .limit(5)
            .toList();
    return similar.isEmpty() ? "" : ", ähnlich: " + similar;
  }

  private static List<Image> scan(List<Path> directories) {
    List<Image> found = new ArrayList<>();
    for (Path directory : directories) {
      if (!Files.isDirectory(directory)) {
        continue;
      }
      try (Stream<Path> files = Files.list(directory)) {
        files
            .filter(file -> file.getFileName().toString().endsWith(EXTENSION))
            .filter(Files::isRegularFile)
            .sorted()
            .forEach(file -> found.add(new Image(file, iccsn(file))));
      } catch (IOException e) {
        throw new UncheckedIOException("Ordner " + directory + " nicht lesbar", e);
      }
    }
    return List.copyOf(found);
  }

  /**
   * ICCSN from the body of EF.GDO ({@code 5A 0A} and 10 bytes BCD); empty if the XML is not a card
   * with it.
   */
  public static Optional<String> iccsn(Path image) {
    XMLInputFactory factory = XMLInputFactory.newDefaultFactory();
    factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
    try (InputStream in = Files.newInputStream(image)) {
      XMLStreamReader xml = factory.createXMLStreamReader(in);
      try {
        boolean gdo = false;
        while (xml.hasNext()) {
          if (xml.next() != XMLStreamReader.START_ELEMENT) {
            continue;
          }
          if ("child".equals(xml.getLocalName())) {
            gdo = "EF.GDO".equals(xml.getAttributeValue(null, "id"));
          } else if (gdo
              && "attribute".equals(xml.getLocalName())
              && "body".equals(xml.getAttributeValue(null, "id"))) {
            String body = xml.getElementText().strip().toLowerCase(java.util.Locale.ROOT);
            return body.startsWith("5a0a") && body.length() == 24
                ? Optional.of(body.substring(4)).filter(ICCSN.asMatchPredicate())
                : Optional.empty();
          }
        }
        return Optional.empty();
      } finally {
        xml.close();
      }
    } catch (XMLStreamException e) {
      return Optional.empty();
    } catch (IOException e) {
      throw new UncheckedIOException("Kartenimage " + image + " nicht lesbar", e);
    }
  }
}

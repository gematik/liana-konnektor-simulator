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
 * liana.card-images}, indexed at startup; with a {@link Generator} also every {@code *.p12}, from
 * which the generator builds an image (SMC-B from a PKCS#12, LIANA-220). A value from the
 * infrastructure object, the Admin API or CATS selects exactly one image from them:
 *
 * <ul>
 *   <li>file name with or without {@code .xml} or {@code .p12} ({@code egk-valid}); if the same
 *       name is in several folders, the first in folder order wins,
 *   <li>ICCSN, 20 digits from EF.GDO ({@code 80276883110000168584}); if several images match, the
 *       value is ambiguous,
 *   <li>absolute path, which bypasses the index.
 * </ul>
 *
 * No match or an ambiguous match is an {@link IllegalArgumentException} with the candidates, as is
 * a PKCS#12 from which the generator could not build an image; the latter only once it is selected,
 * so that an unusable file does not block the others. LIANA finds images added after startup,
 * because a miss rebuilds the index once.
 */
public final class CardImages {

  public static final String EXTENSION = ".xml";

  /** Extension of a PKCS#12 from which a {@link Generator} builds an image (LIANA-220). */
  public static final String P12 = ".p12";

  private static final Pattern ICCSN = Pattern.compile("[0-9]{20}");

  /**
   * A found file from which no card can be built (PKCS#12, LIANA-220), unlike an unknown value; the
   * Admin API answers it with 400 instead of 404.
   */
  public static final class Unusable extends IllegalArgumentException {

    public Unusable(String message, Throwable cause) {
      super(message, cause);
    }
  }

  /** Builds a card image from a PKCS#12 (LIANA-220). */
  public interface Generator {

    /**
     * The image built from {@code p12}; {@link IllegalArgumentException} with the reason if that is
     * not possible.
     */
    Path generate(Path p12);
  }

  /**
   * An image in the index: file that kartos loads, ICCSN from EF.GDO (if it is a card with EF.GDO)
   * and the file in the folder ({@code source}, the PKCS#12 for a generated image); {@code problem}
   * if the generator could not build the image.
   */
  public record Image(Path file, Optional<String> iccsn, Path source, Optional<String> problem) {

    public Image(Path file, Optional<String> iccsn) {
      this(file, iccsn, file, Optional.empty());
    }

    public String name() {
      return stem(source.getFileName().toString());
    }
  }

  private final List<Path> directories;
  private final Optional<Generator> generator;
  private volatile List<Image> images;

  public CardImages(List<Path> directories) {
    this(directories, null);
  }

  /** With {@code generator} the index also contains the {@code *.p12} of the folders. */
  public CardImages(List<Path> directories, Generator generator) {
    this.directories = List.copyOf(directories);
    this.generator = Optional.ofNullable(generator);
    this.images = scan(this.directories, this.generator);
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
      List<Image> rescanned = scan(directories, generator);
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
      if (!Files.isRegularFile(direct)) {
        throw new IllegalArgumentException("Kartenimage " + value + " nicht gefunden");
      }
      if (value.endsWith(P12) && generator.isPresent()) {
        return generate(generator.get(), direct);
      }
      return direct;
    }
    if (ICCSN.matcher(value).matches()) {
      List<Image> hits =
          index.stream().filter(image -> image.iccsn().filter(value::equals).isPresent()).toList();
      if (hits.size() == 1) {
        return usable(hits.getFirst());
      }
      if (hits.isEmpty()) {
        throw new IllegalArgumentException(
            "kein Kartenimage mit ICCSN " + value + " in " + directories);
      }
      throw new IllegalArgumentException(
          "ICCSN "
              + value
              + " ist mehrdeutig, passende Images: "
              + hits.stream().map(Image::source).toList()
              + "; Dateiname angeben");
    }
    String name = stem(value);
    return index.stream()
        .filter(image -> image.name().equals(name))
        .findFirst()
        .map(CardImages::usable)
        .orElseThrow(
            () ->
                new IllegalArgumentException(
                    "Image '"
                        + value
                        + "' nicht gefunden in "
                        + directories
                        + candidates(name, index)));
  }

  /** The file of {@code image}; for a PKCS#12 the generator could not use, its reason. */
  private static Path usable(Image image) {
    if (image.problem().isPresent()) {
      throw new Unusable(image.source() + ": " + image.problem().get(), null);
    }
    return image.file();
  }

  private static Path generate(Generator generator, Path p12) {
    try {
      return generator.generate(p12);
    } catch (IllegalArgumentException e) {
      throw new Unusable(p12 + ": " + e.getMessage(), e);
    }
  }

  /** File name without {@code .xml} or {@code .p12}. */
  private static String stem(String file) {
    for (String extension : List.of(EXTENSION, P12)) {
      if (file.endsWith(extension)) {
        return file.substring(0, file.length() - extension.length());
      }
    }
    return file;
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

  private static List<Image> scan(List<Path> directories, Optional<Generator> generator) {
    List<Image> found = new ArrayList<>();
    for (Path directory : directories) {
      if (!Files.isDirectory(directory)) {
        continue;
      }
      try (Stream<Path> files = Files.list(directory)) {
        files
            .filter(
                file ->
                    file.getFileName().toString().endsWith(EXTENSION)
                        || generator.isPresent() && file.getFileName().toString().endsWith(P12))
            .filter(Files::isRegularFile)
            .sorted()
            .forEach(file -> found.add(image(file, generator)));
      } catch (IOException e) {
        throw new UncheckedIOException("Ordner " + directory + " nicht lesbar", e);
      }
    }
    return List.copyOf(found);
  }

  private static Image image(Path file, Optional<Generator> generator) {
    if (!file.getFileName().toString().endsWith(P12)) {
      return new Image(file, iccsn(file));
    }
    try {
      Path image = generator.orElseThrow().generate(file);
      return new Image(image, iccsn(image), file, Optional.empty());
    } catch (IllegalArgumentException e) {
      return new Image(file, Optional.empty(), file, Optional.of(e.getMessage()));
    }
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

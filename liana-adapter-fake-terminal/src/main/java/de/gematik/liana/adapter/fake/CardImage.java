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
import java.nio.file.Files;
import java.nio.file.Path;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

/**
 * Checks a card image before it is inserted (LIANA-67): gematik object system XML with root {@code
 * card} and the attribute {@code coldAnswerToReset}, from which LIANA reads the ATR ({@link
 * KartosCard}). Only kartos checks the content. A KVK ({@link KvkCard}, root {@code kvk}) is
 * checked completely by {@link KvkCard#open}.
 */
public final class CardImage {

  private CardImage() {}

  /**
   * Throws {@link IllegalArgumentException} with the reason if {@code image} is not a card image.
   */
  public static void check(Path image) {
    if (!Files.isRegularFile(image)) {
      throw new IllegalArgumentException("Image " + image + " nicht gefunden");
    }
    if (KvkCard.isKvk(image)) {
      try {
        KvkCard.open(image).close();
        return;
      } catch (IOException e) {
        throw new IllegalArgumentException(e.getMessage());
      }
    }
    try (InputStream in = Files.newInputStream(image)) {
      XMLInputFactory factory = XMLInputFactory.newDefaultFactory();
      factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
      XMLStreamReader xml = factory.createXMLStreamReader(in);
      boolean root = true;
      while (xml.hasNext()) {
        if (xml.next() != XMLStreamReader.START_ELEMENT) {
          continue;
        }
        if (root && !"card".equals(xml.getLocalName())) {
          throw new IllegalArgumentException(
              "Image "
                  + image.getFileName()
                  + ": Wurzelelement '"
                  + xml.getLocalName()
                  + "', erwartet card (gematik-Objektsystem-XML) oder kvk");
        }
        root = false;
        if ("attribute".equals(xml.getLocalName())
            && "coldAnswerToReset".equals(xml.getAttributeValue(null, "id"))) {
          return;
        }
      }
      throw new IllegalArgumentException(
          "Image "
              + image.getFileName()
              + ": "
              + (root ? "leer" : "Attribut coldAnswerToReset (ATR) fehlt"));
    } catch (XMLStreamException e) {
      throw new IllegalArgumentException(
          "Image " + image.getFileName() + " ist kein XML: " + e.getMessage());
    } catch (IOException e) {
      throw new IllegalArgumentException("Image " + image + " nicht lesbar: " + e.getMessage());
    }
  }
}

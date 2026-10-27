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
import java.util.Arrays;
import java.util.HexFormat;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

/**
 * Health insurance card (Krankenversichertenkarte, KVK) in the fake KT (LIANA-113): a memory card
 * without COS that LIANA emulates itself instead of kartos. The fake KT behaves like a SICCT
 * terminal with support for synchronous cards ([SICCT] 5.5.8.1): it maps SELECT FILE and READ
 * BINARY onto the memory of the card, as described in the KBV leaflet (Merkblatt) KVK 2.05 section
 * 4.
 *
 * <ul>
 *   <li>SELECT FILE with the AID of the KVK application {@code D27600000101} or the old {@code
 *       D28000000101}: 9000, any other AID 6A82,
 *   <li>READ BINARY from offset P1P2 over the VersichertenDatenTemplate: Le bytes with 9000; if the
 *       template ends earlier or Le is 00, the bytes up to the end with 6282; offset beyond the end
 *       6B00, without SELECT 6900,
 *   <li>everything else 6D00.
 * </ul>
 *
 * <p>Image: XML with root {@code kvk}, attribute {@code atr} (hex) and element {@code template}
 * (hex, from tag '60' up to the check byte); see {@code support/images/kvk/kvk-valid.xml}.
 */
public final class KvkCard implements Card {

  static final String ROOT = "kvk";
  private static final HexFormat HEX = HexFormat.of();
  private static final byte[][] AIDS = {HEX.parseHex("D27600000101"), HEX.parseHex("D28000000101")};
  private static final byte[] OK = {(byte) 0x90, 0x00};
  private static final byte[] END_OF_FILE = {0x62, (byte) 0x82};
  private static final byte[] NOT_FOUND = {0x6A, (byte) 0x82};
  private static final byte[] WRONG_OFFSET = {0x6B, 0x00};
  private static final byte[] NOT_ALLOWED = {0x69, 0x00};
  private static final byte[] WRONG_LENGTH = {0x67, 0x00};
  private static final byte[] WRONG_INSTRUCTION = {0x6D, 0x00};

  private final byte[] atr;
  private final byte[] template;
  private volatile boolean selected;

  KvkCard(byte[] atr, byte[] template) {
    this.atr = atr.clone();
    this.template = template.clone();
  }

  /** Reads the image; throws {@link IOException} if it is not a KVK in the format above. */
  public static KvkCard open(Path image) throws IOException {
    XMLInputFactory factory = XMLInputFactory.newDefaultFactory();
    factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
    try (InputStream in = Files.newInputStream(image)) {
      XMLStreamReader xml = factory.createXMLStreamReader(in);
      String atr = null;
      String template = null;
      while (xml.hasNext()) {
        if (xml.next() != XMLStreamReader.START_ELEMENT) {
          continue;
        }
        if (ROOT.equals(xml.getLocalName())) {
          atr = xml.getAttributeValue(null, "atr");
        } else if ("template".equals(xml.getLocalName())) {
          template = xml.getElementText().replaceAll("\\s", "");
        }
      }
      if (atr == null || template == null || template.isEmpty()) {
        throw new IOException(
            "KVK-Image " + image.getFileName() + ": Attribut atr und Element template nötig");
      }
      return new KvkCard(HEX.parseHex(atr.strip()), HEX.parseHex(template));
    } catch (XMLStreamException | IllegalArgumentException e) {
      throw new IOException(
          "KVK-Image " + image.getFileName() + " nicht lesbar: " + e.getMessage(), e);
    }
  }

  /** Whether {@code image} is a KVK image (root element {@code kvk}). */
  public static boolean isKvk(Path image) {
    XMLInputFactory factory = XMLInputFactory.newDefaultFactory();
    factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
    try (InputStream in = Files.newInputStream(image)) {
      XMLStreamReader xml = factory.createXMLStreamReader(in);
      while (xml.hasNext()) {
        if (xml.next() == XMLStreamReader.START_ELEMENT) {
          return ROOT.equals(xml.getLocalName());
        }
      }
      return false;
    } catch (IOException | XMLStreamException e) {
      return false;
    }
  }

  @Override
  public byte[] atr() {
    return atr.clone();
  }

  @Override
  public byte[] transmit(byte[] apdu) {
    if (apdu.length < 4 || apdu[0] != 0x00) {
      return WRONG_INSTRUCTION.clone();
    }
    return switch (apdu[1]) {
      case (byte) 0xA4 -> select(apdu);
      case (byte) 0xB0 -> readBinary(apdu);
      default -> WRONG_INSTRUCTION.clone();
    };
  }

  private byte[] select(byte[] apdu) {
    int lc = apdu.length > 4 ? apdu[4] & 0xFF : 0;
    if (apdu[2] != 0x04 || apdu.length < 5 + lc) {
      selected = false;
      return NOT_FOUND.clone();
    }
    byte[] aid = Arrays.copyOfRange(apdu, 5, 5 + lc);
    selected = Arrays.stream(AIDS).anyMatch(known -> Arrays.equals(known, aid));
    return (selected ? OK : NOT_FOUND).clone();
  }

  private byte[] readBinary(byte[] apdu) {
    if (!selected) {
      return NOT_ALLOWED.clone();
    }
    if (apdu.length != 5) {
      return WRONG_LENGTH.clone();
    }
    int offset = (apdu[2] & 0xFF) << 8 | apdu[3] & 0xFF;
    if (offset >= template.length) {
      return WRONG_OFFSET.clone();
    }
    int le = apdu[4] & 0xFF;
    int available = template.length - offset;
    // Le 00 reads up to EOF; 6282 if the end is reached before Le bytes
    boolean shortRead = le == 0 || le > available;
    int n = shortRead ? available : le;
    byte[] response = Arrays.copyOfRange(template, offset, offset + n + 2);
    byte[] sw = shortRead ? END_OF_FILE : OK;
    response[n] = sw[0];
    response[n + 1] = sw[1];
    return response;
  }

  @Override
  public void close() {
    selected = false;
  }
}

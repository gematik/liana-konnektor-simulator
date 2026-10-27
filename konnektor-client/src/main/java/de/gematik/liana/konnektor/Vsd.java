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
package de.gematik.liana.konnektor;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 * Response of ReadVSD (VSDService 5.2, VSDM-A_2567; LIANA-105): the Versichertenstammdaten from the
 * eGK, unpacked from the gzip in the response, as XML documents in the charset of their XML
 * declaration (ISO-8859-15 on the eGK).
 *
 * @param pd PersoenlicheVersichertendaten (UC_PersoenlicheVersichertendatenXML)
 * @param vd AllgemeineVersicherungsdaten (UC_AllgemeineVersicherungsdatenXML)
 * @param gvd GeschuetzteVersichertendaten, may be absent
 * @param status VSD_Status
 */
public record Vsd(byte[] pd, byte[] vd, Optional<byte[]> gvd, Status status) {

  private static final Pattern ENCODING =
      Pattern.compile("^<\\?xml[^>]*encoding=[\"']([A-Za-z0-9._-]+)[\"']");

  /**
   * VSD_Status.
   *
   * @param transactionsOpen status 1: transactions open
   * @param timestamp time of the last update of the VSD
   * @param version version of the VSD schemas, such as {@code 5.2.0}
   */
  public record Status(boolean transactionsOpen, LocalDateTime timestamp, String version) {}

  /** PD as text. */
  public String pdXml() {
    return text(pd);
  }

  /** VD as text. */
  public String vdXml() {
    return text(vd);
  }

  /** GVD as text, if present. */
  public Optional<String> gvdXml() {
    return gvd.map(Vsd::text);
  }

  /**
   * Text of the first element with this local name in the PD, such as {@code Vorname}, {@code
   * Nachname}.
   */
  public Optional<String> pdValue(String localName) {
    return value(pd, localName);
  }

  /**
   * Text of the first element with this local name in the VD, such as {@code Kostentraegerkennung}
   * (IKNR).
   */
  public Optional<String> vdValue(String localName) {
    return value(vd, localName);
  }

  private static Optional<String> value(byte[] xml, String localName) {
    try {
      DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
      factory.setNamespaceAware(true);
      factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
      NodeList nodes =
          factory
              .newDocumentBuilder()
              .parse(new ByteArrayInputStream(xml))
              .getElementsByTagNameNS("*", localName);
      return nodes.getLength() == 0
          ? Optional.empty()
          : Optional.of(nodes.item(0).getTextContent().strip());
    } catch (ParserConfigurationException | SAXException | IOException e) {
      throw new KonnektorException("ReadVSD: Versichertendaten sind kein XML", e);
    }
  }

  static byte[] gunzip(String field, byte[] compressed) {
    try (GZIPInputStream in = new GZIPInputStream(new ByteArrayInputStream(compressed))) {
      return in.readAllBytes();
    } catch (IOException e) {
      throw new KonnektorException("ReadVSD: " + field + " ist kein gzip", e);
    }
  }

  /** Decodes an XML document in the charset of its declaration, UTF-8 without declaration. */
  static String text(byte[] xml) {
    String head = new String(xml, 0, Math.min(xml.length, 100), StandardCharsets.ISO_8859_1);
    Matcher encoding = ENCODING.matcher(head);
    return new String(
        xml, encoding.find() ? Charset.forName(encoding.group(1)) : StandardCharsets.UTF_8);
  }
}

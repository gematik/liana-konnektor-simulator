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

import de.gematik.liana.kern.error.ConnectorError;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;
import org.xml.sax.helpers.DefaultHandler;

/**
 * Read and write XML documents without DTD and external entities. LIANA implements ISO-8859-15
 * (Latin-9) itself (decision-023): the native image only knows the standard charsets, but the NFDs
 * of the Konnektor QES are Latin-9. Latin-9 is ISO-8859-1 with eight different characters; output
 * uses the document's charset, characters outside Latin-9 as character references.
 */
final class XmlCodec {

  private static final Set<String> LATIN9 =
      Set.of(
          "ISO-8859-15",
          "ISO8859-15",
          "ISO_8859-15",
          "ISO8859_15",
          "LATIN9",
          "LATIN-9",
          "L9",
          "CSISOLATIN9",
          "ISO_8859-15:1998",
          "LATIN0",
          "CSISO885915");

  /** Latin-9 0xA4, 0xA6, 0xA8, 0xB4, 0xB8, 0xBC, 0xBD, 0xBE (ISO/IEC 8859-15 Annex A). */
  private static final int[] LATIN9_BYTES = {0xA4, 0xA6, 0xA8, 0xB4, 0xB8, 0xBC, 0xBD, 0xBE};

  private static final char[] LATIN9_CHARS = {
    '\u20AC', '\u0160', '\u0161', '\u017D', '\u017E', '\u0152', '\u0153', '\u0178'
  };
  private static final Pattern ENCODING =
      Pattern.compile("^<\\?xml[^>]*?encoding\\s*=\\s*[\"']([^\"']+)[\"']");

  private XmlCodec() {}

  /** Well-formed (TUC_KON_080 (A)), otherwise 4022. */
  static Document parse(byte[] xml) {
    try {
      DocumentBuilder builder = factory().newDocumentBuilder();
      // without „[Fatal Error]“ on stderr: the error arrives as SAXException
      builder.setErrorHandler(
          new DefaultHandler() {
            @Override
            public void error(SAXParseException e) throws SAXException {
              throw e;
            }
          });
      if (latin9(declaredEncoding(xml))) {
        InputSource source = new InputSource(new StringReader(decodeLatin9(xml)));
        return builder.parse(source);
      }
      return builder.parse(new ByteArrayInputStream(xml));
    } catch (SAXException | IOException e) {
      throw ConnectorError.XML_NOT_WELL_FORMED.exception(e.getMessage()).causedBy(e);
    } catch (ParserConfigurationException e) {
      throw new IllegalStateException(e);
    }
  }

  /** The document in the charset of its XML declaration (UTF-8 if not specified). */
  @SuppressWarnings("java:S2755") // only serializes a DOM, nothing is parsed
  static byte[] serialize(Document document) {
    String encoding = document.getXmlEncoding() == null ? "UTF-8" : document.getXmlEncoding();
    try {
      Transformer transformer = TransformerFactory.newInstance().newTransformer();
      if (!latin9(encoding)) {
        transformer.setOutputProperty(OutputKeys.ENCODING, encoding);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(out));
        return out.toByteArray();
      }
      transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
      StringWriter text = new StringWriter();
      transformer.transform(new DOMSource(document), new StreamResult(text));
      String declaration =
          "<?xml version=\"1.0\" encoding=\""
              + encoding
              + "\""
              + (document.getXmlStandalone() ? " standalone=\"yes\"" : " standalone=\"no\"")
              + "?>";
      return encodeLatin9(declaration + text);
    } catch (TransformerException e) {
      throw new IllegalStateException("XML schreiben: " + e.getMessage(), e);
    }
  }

  static DocumentBuilderFactory factory() {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setNamespaceAware(true);
    try {
      factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
      factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    } catch (ParserConfigurationException e) {
      throw new IllegalStateException(e);
    }
    factory.setExpandEntityReferences(false);
    return factory;
  }

  /**
   * {@code encoding} of the XML declaration, if the document starts with an ASCII-compatible
   * declaration.
   */
  static String declaredEncoding(byte[] xml) {
    int end = Math.min(xml.length, 200);
    Matcher matcher = ENCODING.matcher(new String(xml, 0, end, StandardCharsets.ISO_8859_1));
    return matcher.find() ? matcher.group(1) : null;
  }

  static boolean latin9(String encoding) {
    return encoding != null && LATIN9.contains(encoding.strip().toUpperCase(Locale.ROOT));
  }

  static String decodeLatin9(byte[] bytes) {
    char[] chars = new char[bytes.length];
    for (int i = 0; i < bytes.length; i++) {
      int b = bytes[i] & 0xFF;
      chars[i] = (char) b;
      for (int j = 0; j < LATIN9_BYTES.length; j++) {
        if (LATIN9_BYTES[j] == b) {
          chars[i] = LATIN9_CHARS[j];
        }
      }
    }
    return new String(chars);
  }

  static byte[] encodeLatin9(String text) {
    ByteArrayOutputStream out = new ByteArrayOutputStream(text.length());
    text.codePoints()
        .forEach(
            c -> {
              int b = latin9Byte(c);
              if (b >= 0) {
                out.write(b);
              } else {
                out.writeBytes(
                    ("&#x" + Integer.toHexString(c).toUpperCase(Locale.ROOT) + ";")
                        .getBytes(StandardCharsets.US_ASCII));
              }
            });
    return out.toByteArray();
  }

  /** The Latin-9 byte for {@code c}, -1 outside Latin-9. */
  private static int latin9Byte(int c) {
    for (int j = 0; j < LATIN9_CHARS.length; j++) {
      if (LATIN9_CHARS[j] == c) {
        return LATIN9_BYTES[j];
      }
    }
    if (c > 0xFF) {
      return -1;
    }
    for (int b : LATIN9_BYTES) {
      if (b == c) {
        // occupied by a different character in Latin-9
        return -1;
      }
    }
    return c;
  }
}

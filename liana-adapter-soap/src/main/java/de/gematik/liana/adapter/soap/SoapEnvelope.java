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
package de.gematik.liana.adapter.soap;

import java.io.ByteArrayInputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

/**
 * Reads the first element in the SOAP 1.1 body (the operation) with StAX, without DTDs and external
 * entities. For an MTOM message ({@code multipart/related} with XOP, like konnektor-service-client
 * with {@code pssim.enableMtom}) it reads it from the root part; the attachments are not evaluated.
 */
final class SoapEnvelope {

  static final String SOAP_ENV = "http://schemas.xmlsoap.org/soap/envelope/";

  private static final XMLInputFactory FACTORY = XMLInputFactory.newFactory();
  private static final Pattern PARAMETER =
      Pattern.compile(";\\s*([A-Za-z-]+)\\s*=\\s*(?:\"([^\"]*)\"|([^;\\s]*))");

  static {
    FACTORY.setProperty(XMLInputFactory.SUPPORT_DTD, false);
    FACTORY.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
    FACTORY.setProperty(XMLInputFactory.IS_NAMESPACE_AWARE, true);
  }

  /** No SOAP envelope, no body or no well-formed XML. */
  static final class InvalidSoapException extends Exception {
    InvalidSoapException(String message) {
      super(message);
    }

    InvalidSoapException(String message, Throwable cause) {
      super(message, cause);
    }
  }

  private SoapEnvelope() {}

  /**
   * Like {@link #operation(byte[])}, for {@code multipart/related} from the root part of the MTOM
   * message.
   */
  static XmlNode operation(String contentType, byte[] message) throws InvalidSoapException {
    return operation(rootPart(contentType, message));
  }

  /** Whether the Content-Type announces an MTOM message ({@code multipart/related}). */
  static boolean isMtom(String contentType) {
    return contentType != null
        && contentType.strip().toLowerCase(Locale.ROOT).startsWith("multipart/related");
  }

  /**
   * Root part of a {@code multipart/related} message (XOP, RFC 2387): the part with the Content-ID
   * from the parameter {@code start}, without it the first. Other Content-Types stay as they are.
   */
  static byte[] rootPart(String contentType, byte[] message) throws InvalidSoapException {
    if (!isMtom(contentType)) {
      return message;
    }
    String start = parameters(contentType).get("start");
    List<Part> parts = parts(contentType, message);
    if (start == null) {
      return parts.get(0).content();
    }
    return parts.stream()
        .filter(p -> p.contentId().equals(stripAngles(start)))
        .findFirst()
        .orElseThrow(
            () -> new InvalidSoapException("multipart/related: kein Teil mit Content-ID " + start))
        .content();
  }

  /**
   * Content of an XOP reference ({@code xop:Include/@href}, {@code cid:} per RFC 2392, URL-encoded)
   * in a {@code multipart/related} message.
   */
  static byte[] attachment(String contentType, byte[] message, String href)
      throws InvalidSoapException {
    if (!isMtom(contentType) || href == null || !href.startsWith("cid:")) {
      throw new InvalidSoapException("xop:Include ohne MTOM-Teil: " + href);
    }
    String id = URLDecoder.decode(href.substring(4), StandardCharsets.UTF_8);
    return parts(contentType, message).stream()
        .filter(p -> p.contentId().equals(id))
        .findFirst()
        .orElseThrow(
            () -> new InvalidSoapException("multipart/related: kein Teil mit Content-ID " + id))
        .content();
  }

  /** A part of a {@code multipart/related} message: Content-ID without angle brackets, content. */
  private record Part(String contentId, byte[] content) {}

  private static Map<String, String> parameters(String contentType) {
    Map<String, String> parameters = new LinkedHashMap<>();
    Matcher m = PARAMETER.matcher(contentType);
    while (m.find()) {
      parameters.put(
          m.group(1).toLowerCase(Locale.ROOT), m.group(2) != null ? m.group(2) : m.group(3));
    }
    return parameters;
  }

  private static List<Part> parts(String contentType, byte[] message) throws InvalidSoapException {
    String boundary = parameters(contentType).get("boundary");
    if (boundary == null || boundary.isEmpty()) {
      throw new InvalidSoapException("multipart/related ohne boundary");
    }
    // ISO-8859-1 maps every byte to one character: search in the string, parts back to bytes
    // unchanged
    String body = new String(message, StandardCharsets.ISO_8859_1);
    String delimiter = "--" + boundary;
    List<Part> parts = new ArrayList<>();
    int at = body.indexOf(delimiter);
    while (at >= 0) {
      int partStart = at + delimiter.length();
      if (body.startsWith("--", partStart)) {
        break;
      }
      int next = body.indexOf("\r\n" + delimiter, partStart);
      int end = next >= 0 ? next : body.indexOf("\n" + delimiter, partStart);
      if (end < 0) {
        throw new InvalidSoapException("multipart/related ohne abschließende boundary");
      }
      String part = body.substring(partStart, end).replaceFirst("^[ \t]*\r?\n", "");
      int headerEnd = part.indexOf("\r\n\r\n");
      int contentStart = headerEnd >= 0 ? headerEnd + 4 : part.indexOf("\n\n") + 2;
      if (contentStart < 2) {
        throw new InvalidSoapException("multipart/related: Teil ohne Header-Ende");
      }
      parts.add(
          new Part(
              contentId(part.substring(0, contentStart)),
              part.substring(contentStart).getBytes(StandardCharsets.ISO_8859_1)));
      at = body.indexOf(delimiter, end + 1);
    }
    if (parts.isEmpty()) {
      throw new InvalidSoapException("multipart/related ohne Teile");
    }
    return parts;
  }

  private static String contentId(String headers) {
    for (String line : headers.split("\r?\n")) {
      int colon = line.indexOf(':');
      if (colon > 0 && line.substring(0, colon).strip().equalsIgnoreCase("Content-ID")) {
        return stripAngles(line.substring(colon + 1));
      }
    }
    return "";
  }

  private static String stripAngles(String id) {
    return id.strip().replaceAll("^<|>$", "");
  }

  static XmlNode operation(byte[] message) throws InvalidSoapException {
    try {
      XMLStreamReader reader = FACTORY.createXMLStreamReader(new ByteArrayInputStream(message));
      try {
        boolean inBody = false;
        while (reader.hasNext()) {
          if (reader.next() == XMLStreamConstants.START_ELEMENT) {
            if (inBody) {
              return element(reader);
            }
            inBody =
                SOAP_ENV.equals(reader.getNamespaceURI()) && "Body".equals(reader.getLocalName());
          }
        }
      } finally {
        reader.close();
      }
    } catch (XMLStreamException e) {
      throw new InvalidSoapException("kein wohlgeformtes XML: " + e.getMessage(), e);
    }
    throw new InvalidSoapException("SOAP-Body ohne Operation");
  }

  /** Reads the element whose START_ELEMENT {@code reader} is on, including its subtree. */
  private static XmlNode element(XMLStreamReader reader) throws XMLStreamException {
    Deque<Builder> stack = new ArrayDeque<>();
    stack.push(new Builder(reader));
    while (true) {
      switch (reader.next()) {
        case XMLStreamConstants.START_ELEMENT -> stack.push(new Builder(reader));
        case XMLStreamConstants.CHARACTERS, XMLStreamConstants.CDATA ->
            stack.peek().text.append(reader.getText());
        case XMLStreamConstants.END_ELEMENT -> {
          XmlNode done = stack.pop().build();
          if (stack.isEmpty()) {
            return done;
          }
          stack.peek().children.add(done);
        }
        default -> {}
      }
    }
  }

  private static final class Builder {
    final String namespace;
    final String name;
    final Map<String, String> attributes = new LinkedHashMap<>();
    final StringBuilder text = new StringBuilder();
    final List<XmlNode> children = new ArrayList<>();

    Builder(XMLStreamReader reader) {
      namespace = reader.getNamespaceURI() == null ? "" : reader.getNamespaceURI();
      name = reader.getLocalName();
      for (int i = 0; i < reader.getAttributeCount(); i++) {
        attributes.put(reader.getAttributeLocalName(i), reader.getAttributeValue(i));
      }
    }

    XmlNode build() {
      return new XmlNode(
          namespace, name, Map.copyOf(attributes), text.toString(), List.copyOf(children));
    }
  }
}

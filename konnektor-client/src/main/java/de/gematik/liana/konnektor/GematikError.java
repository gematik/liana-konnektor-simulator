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

import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

/**
 * The gematik error trace from the {@code detail} of a SOAP fault ({@code GERROR:Error},
 * TelematikError v2.0; LIANA-137). Read leniently: Konnektors fill different fields (quirks table,
 * LIANA-134), hence only element names without namespace, every field optional, even an error
 * without {@code Trace}.
 *
 * @param messageId {@code MessageID}
 * @param timestamp {@code Timestamp} as text
 * @param traces {@code Trace} entries in document order; the first one is the triggering business
 *     error
 */
public record GematikError(String messageId, String timestamp, List<Trace> traces) {

  public GematikError {
    traces = List.copyOf(traces);
  }

  /**
   * An entry of the trace.
   *
   * @param code {@code Code}, {@code null} if not numeric or empty
   * @param errorType {@code ErrorType} ({@code Technical}, {@code Security}, {@code
   *     Infrastructure}, {@code Business}, {@code Other})
   */
  public record Trace(
      String eventId,
      String instance,
      String logReference,
      String compType,
      Integer code,
      String severity,
      String errorType,
      String errorText,
      String detail) {}

  /** Code of the first trace entry. */
  public Optional<Integer> code() {
    return traces.stream().map(Trace::code).filter(c -> c != null).findFirst();
  }

  /** ErrorType of the first trace entry. */
  public Optional<String> errorType() {
    return traces.stream().map(Trace::errorType).filter(t -> t != null && !t.isBlank()).findFirst();
  }

  /** ErrorText of the first trace entry. */
  public Optional<String> errorText() {
    return traces.stream().map(Trace::errorText).filter(t -> t != null && !t.isBlank()).findFirst();
  }

  /**
   * Reads the error from the content of {@code detail}; empty if there is no {@code Error} in it.
   */
  static Optional<GematikError> parse(String detail) {
    if (detail == null || detail.isBlank()) {
      return Optional.empty();
    }
    try {
      DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
      factory.setNamespaceAware(true);
      factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
      Document document =
          factory
              .newDocumentBuilder()
              .parse(new InputSource(new StringReader("<detail>" + detail + "</detail>")));
      Element error = first(document.getDocumentElement(), "Error");
      if (error == null) {
        return Optional.empty();
      }
      List<Trace> traces = new ArrayList<>();
      for (Node node = error.getFirstChild(); node != null; node = node.getNextSibling()) {
        if (node instanceof Element trace && "Trace".equals(trace.getLocalName())) {
          traces.add(
              new Trace(
                  text(trace, "EventID"),
                  text(trace, "Instance"),
                  text(trace, "LogReference"),
                  text(trace, "CompType"),
                  number(text(trace, "Code")),
                  text(trace, "Severity"),
                  text(trace, "ErrorType"),
                  text(trace, "ErrorText"),
                  text(trace, "Detail")));
        }
      }
      return Optional.of(
          new GematikError(text(error, "MessageID"), text(error, "Timestamp"), traces));
    } catch (Exception e) {
      return Optional.empty();
    }
  }

  private static Element first(Element parent, String localName) {
    for (Node node = parent.getFirstChild(); node != null; node = node.getNextSibling()) {
      if (node instanceof Element element) {
        if (localName.equals(element.getLocalName())) {
          return element;
        }
        Element nested = first(element, localName);
        if (nested != null) {
          return nested;
        }
      }
    }
    return null;
  }

  private static String text(Element parent, String localName) {
    for (Node node = parent.getFirstChild(); node != null; node = node.getNextSibling()) {
      if (node instanceof Element element && localName.equals(element.getLocalName())) {
        return element.getTextContent().trim();
      }
    }
    return null;
  }

  private static Integer number(String text) {
    try {
      return text == null || text.isBlank() ? null : Integer.valueOf(text.trim());
    } catch (NumberFormatException e) {
      return null;
    }
  }
}

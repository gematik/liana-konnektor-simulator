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
package de.gematik.liana.adapter.cetp;

import de.gematik.liana.kern.event.Event;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import javax.xml.XMLConstants;
import javax.xml.namespace.NamespaceContext;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

/**
 * The event message as XML document (TIP1-A_4596, TAB_KON_030): element {@code Event} from
 * EventService.xsd v7.2 with Topic, Type, Severity, SubscriptionID and Message/Parameter, UTF-8.
 * The namespace is the default namespace, as the filter of a subscription sees it (TAB_KON_571).
 */
public final class EventXml {

  static final String NAMESPACE = "http://ws.gematik.de/conn/EventService/v7.2";

  private EventXml() {}

  /** The event document for the subscription {@code subscriptionId}. */
  public static byte[] render(Event event, String subscriptionId) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    try {
      XMLStreamWriter xml =
          XMLOutputFactory.newDefaultFactory().createXMLStreamWriter(out, "UTF-8");
      xml.writeStartDocument("UTF-8", "1.0");
      xml.setDefaultNamespace(NAMESPACE);
      xml.writeStartElement(NAMESPACE, "Event");
      xml.writeDefaultNamespace(NAMESPACE);
      element(xml, "Topic", event.topic());
      element(xml, "Type", event.type().value());
      element(xml, "Severity", event.severity().value());
      element(xml, "SubscriptionID", subscriptionId);
      xml.writeStartElement(NAMESPACE, "Message");
      for (Map.Entry<String, String> parameter : event.parameters().entrySet()) {
        xml.writeStartElement(NAMESPACE, "Parameter");
        element(xml, "Key", parameter.getKey());
        element(xml, "Value", parameter.getValue());
        xml.writeEndElement();
      }
      xml.writeEndElement();
      xml.writeEndElement();
      xml.writeEndDocument();
      xml.close();
    } catch (XMLStreamException e) {
      throw new IllegalStateException("Event-XML", e);
    }
    return out.toByteArray();
  }

  /**
   * TUC_KON_256 step 5c: {@code true} if {@code filter} is absent or, applied to {@code event},
   * yields a non-empty result (XPath 1.0, evaluated as boolean). Names without prefix are in the
   * namespace of the event, as is the prefix {@code EVT}; LIANA does not evaluate both mixed in one
   * expression.
   *
   * @throws FilterException expression or evaluation faulty (4095)
   */
  public static boolean matches(String filter, byte[] event) {
    if (filter == null) {
      return true;
    }
    boolean prefixed = filter.contains("EVT:");
    try {
      DocumentBuilderFactory factory = DocumentBuilderFactory.newDefaultInstance();
      factory.setNamespaceAware(prefixed);
      factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
      Document document = factory.newDocumentBuilder().parse(new ByteArrayInputStream(event));
      XPath xpath = XPathFactory.newDefaultInstance().newXPath();
      if (prefixed) {
        xpath.setNamespaceContext(new Evt());
      }
      return (Boolean) xpath.evaluate(filter, document, XPathConstants.BOOLEAN);
    } catch (XPathExpressionException e) {
      throw new FilterException(
          filter + ": " + (e.getCause() == null ? e.getMessage() : e.getCause().getMessage()));
    } catch (ParserConfigurationException | SAXException | IOException e) {
      throw new IllegalStateException("Event-XML", e);
    }
  }

  private static void element(XMLStreamWriter xml, String name, String text)
      throws XMLStreamException {
    xml.writeStartElement(NAMESPACE, name);
    xml.writeCharacters(text);
    xml.writeEndElement();
  }

  /** TAB_KON_571: prefix EVT for the EventService namespace. */
  private static final class Evt implements NamespaceContext {
    @Override
    public String getNamespaceURI(String prefix) {
      return "EVT".equals(prefix) ? NAMESPACE : XMLConstants.NULL_NS_URI;
    }

    @Override
    public String getPrefix(String namespaceUri) {
      return NAMESPACE.equals(namespaceUri) ? "EVT" : null;
    }

    @Override
    public Iterator<String> getPrefixes(String namespaceUri) {
      return NAMESPACE.equals(namespaceUri)
          ? List.of("EVT").iterator()
          : Collections.emptyIterator();
    }
  }

  /** Filter cannot be evaluated: TAB_KON_557, error code 4095, only for this subscription. */
  public static final class FilterException extends RuntimeException {
    FilterException(String message) {
      super(message);
    }
  }
}

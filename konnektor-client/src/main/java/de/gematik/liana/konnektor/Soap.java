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

import de.gematik.liana.contract.Schemas;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Marshaller;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * SOAP 1.1 by hand (decision-016): envelope around the JAXB element of the request; the body of the
 * response holds either the response element or a {@code soap:Fault}. {@code SOAPAction} comes per
 * operation from the WSDL in {@code liana-contract}, because it does not always follow the pattern
 * {@code <namespace>#<operation>} (DecryptDocument). DTDs and external entities are disabled.
 */
final class Soap {

  static final String ENVELOPE_NS = "http://schemas.xmlsoap.org/soap/envelope/";
  private static final String WSDL = "http://schemas.xmlsoap.org/wsdl/";
  private static final String WSDL_SOAP = "http://schemas.xmlsoap.org/wsdl/soap/";

  private static final Map<Binding, JAXBContext> CONTEXTS = new ConcurrentHashMap<>();
  private static final Map<Binding, Map<String, String>> ACTIONS = new ConcurrentHashMap<>();

  private Soap() {}

  static JAXBContext context(Binding binding) {
    return CONTEXTS.computeIfAbsent(
        binding,
        b -> {
          try {
            return JAXBContext.newInstance(b.javaPackage(), Soap.class.getClassLoader());
          } catch (JAXBException e) {
            throw new IllegalStateException("JAXB-Kontext für " + b + " nicht anlegbar", e);
          }
        });
  }

  /** {@code soap:operation/@soapAction} from the binding's WSDL. */
  static String action(Binding binding, Operation operation) {
    String action = ACTIONS.computeIfAbsent(binding, Soap::readActions).get(operation.wsdlName());
    if (action == null) {
      throw new IllegalStateException(binding + ": keine SOAPAction für " + operation.wsdlName());
    }
    return action;
  }

  private static Map<String, String> readActions(Binding binding) {
    try (InputStream in = Schemas.resource(binding.wsdl()).openStream()) {
      DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
      factory.setNamespaceAware(true);
      factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
      Document wsdl = factory.newDocumentBuilder().parse(in);
      Map<String, String> actions = new HashMap<>();
      NodeList operations = wsdl.getElementsByTagNameNS(WSDL, "operation");
      for (int i = 0; i < operations.getLength(); i++) {
        Element operation = (Element) operations.item(i);
        NodeList soap = operation.getElementsByTagNameNS(WSDL_SOAP, "operation");
        if (soap.getLength() > 0) {
          actions.put(
              operation.getAttribute("name"), ((Element) soap.item(0)).getAttribute("soapAction"));
        }
      }
      return actions;
    } catch (Exception e) {
      throw new IllegalStateException(binding.wsdl() + " nicht lesbar", e);
    }
  }

  static byte[] envelope(Binding binding, Object request) {
    try {
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      XMLStreamWriter writer = XMLOutputFactory.newFactory().createXMLStreamWriter(out, "UTF-8");
      writer.writeStartDocument("UTF-8", "1.0");
      writer.writeStartElement("soap", "Envelope", ENVELOPE_NS);
      writer.writeNamespace("soap", ENVELOPE_NS);
      writer.writeStartElement("soap", "Body", ENVELOPE_NS);
      Marshaller marshaller = context(binding).createMarshaller();
      marshaller.setProperty(Marshaller.JAXB_FRAGMENT, true);
      marshaller.marshal(request, writer);
      writer.writeEndElement();
      writer.writeEndElement();
      writer.writeEndDocument();
      writer.close();
      return out.toByteArray();
    } catch (JAXBException | XMLStreamException e) {
      throw new IllegalArgumentException(
          "Request für " + binding + " nicht serialisierbar: " + e.getMessage(), e);
    }
  }

  /**
   * Reads the body of the response.
   *
   * @throws SoapFaultException on {@code soap:Fault}
   * @throws KonnektorException if the response is not a SOAP envelope
   */
  static <T> T response(Binding binding, Operation operation, byte[] body, Class<T> type) {
    return response(binding, operation, body, type, java.util.Optional.empty());
  }

  /**
   * As above; {@code gap} is the product's gap for this operation according to the quirks table
   * (LIANA-137).
   */
  static <T> T response(
      Binding binding,
      Operation operation,
      byte[] body,
      Class<T> type,
      java.util.Optional<QuirksTable.Gap> gap) {
    try {
      XMLStreamReader reader = reader(body);
      nextElement(reader, new QName(ENVELOPE_NS, "Envelope"), operation);
      nextElement(reader, null, operation);
      if (new QName(ENVELOPE_NS, "Header").equals(reader.getName())) {
        skip(reader);
        nextElement(reader, null, operation);
      }
      if (!new QName(ENVELOPE_NS, "Body").equals(reader.getName())) {
        throw new KonnektorException(operation.wsdlName() + ": SOAP-Umschlag ohne Body");
      }
      nextElement(reader, null, operation);
      if (new QName(ENVELOPE_NS, "Fault").equals(reader.getName())) {
        throw fault(operation, reader, gap);
      }
      Object value = context(binding).createUnmarshaller().unmarshal(reader);
      if (value instanceof jakarta.xml.bind.JAXBElement<?> element) {
        value = element.getValue();
      }
      if (!type.isInstance(value)) {
        throw new KonnektorException(
            operation.wsdlName()
                + ": Antwort "
                + value.getClass().getSimpleName()
                + " statt "
                + type.getSimpleName());
      }
      return type.cast(value);
    } catch (XMLStreamException | JAXBException e) {
      throw new KonnektorException(
          operation.wsdlName() + ": Antwort nicht lesbar: " + e.getMessage(), e);
    }
  }

  private static SoapFaultException fault(
      Operation operation, XMLStreamReader reader, java.util.Optional<QuirksTable.Gap> gap)
      throws XMLStreamException {
    Map<String, String> parts = new HashMap<>();
    String detail = "";
    while (reader.hasNext()) {
      int event = reader.next();
      if (event == XMLStreamConstants.END_ELEMENT && reader.getLocalName().equals("Fault")) {
        break;
      }
      if (event == XMLStreamConstants.START_ELEMENT) {
        String name = reader.getLocalName();
        if (name.equals("detail")) {
          detail = inner(reader);
        } else {
          parts.put(name, reader.getElementText().trim());
        }
      }
    }
    return SoapFaultException.of(
        operation,
        parts.getOrDefault("faultcode", ""),
        parts.getOrDefault("faultstring", ""),
        detail,
        gap);
  }

  /** Content of the current element as XML text; afterwards the reader is positioned at its end. */
  private static String inner(XMLStreamReader reader) throws XMLStreamException {
    StringWriter text = new StringWriter();
    XMLStreamWriter writer = XMLOutputFactory.newFactory().createXMLStreamWriter(text);
    int depth = 0;
    while (reader.hasNext()) {
      int event = reader.next();
      if (event == XMLStreamConstants.START_ELEMENT) {
        depth++;
        writer.writeStartElement(
            reader.getPrefix(), reader.getLocalName(), reader.getNamespaceURI());
        for (int i = 0; i < reader.getNamespaceCount(); i++) {
          writer.writeNamespace(reader.getNamespacePrefix(i), reader.getNamespaceURI(i));
        }
        for (int i = 0; i < reader.getAttributeCount(); i++) {
          writer.writeAttribute(
              reader.getAttributePrefix(i) == null ? "" : reader.getAttributePrefix(i),
              reader.getAttributeNamespace(i) == null ? "" : reader.getAttributeNamespace(i),
              reader.getAttributeLocalName(i),
              reader.getAttributeValue(i));
        }
      } else if (event == XMLStreamConstants.END_ELEMENT) {
        if (depth == 0) {
          break;
        }
        depth--;
        writer.writeEndElement();
      } else if (event == XMLStreamConstants.CHARACTERS || event == XMLStreamConstants.CDATA) {
        writer.writeCharacters(reader.getText());
      }
    }
    writer.close();
    return text.toString().trim();
  }

  private static XMLStreamReader reader(byte[] body) throws XMLStreamException {
    XMLInputFactory factory = XMLInputFactory.newFactory();
    factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
    factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
    return factory.createXMLStreamReader(
        new ByteArrayInputStream(body), StandardCharsets.UTF_8.name());
  }

  private static void nextElement(XMLStreamReader reader, QName expected, Operation operation)
      throws XMLStreamException {
    while (reader.hasNext()) {
      int event = reader.next();
      if (event == XMLStreamConstants.START_ELEMENT) {
        if (expected != null && !expected.equals(reader.getName())) {
          throw new KonnektorException(
              operation.wsdlName() + ": " + reader.getName() + " statt " + expected);
        }
        return;
      }
    }
    throw new KonnektorException(operation.wsdlName() + ": SOAP-Umschlag unvollständig");
  }

  private static void skip(XMLStreamReader reader) throws XMLStreamException {
    int depth = 1;
    while (depth > 0 && reader.hasNext()) {
      int event = reader.next();
      if (event == XMLStreamConstants.START_ELEMENT) {
        depth++;
      } else if (event == XMLStreamConstants.END_ELEMENT) {
        depth--;
      }
    }
  }
}

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
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.io.StringReader;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.regex.Pattern;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.ls.LSInput;
import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

/**
 * Validation of incoming SOAP requests (LIANA-48): the operation (first element in the body)
 * against the XSD of its service and the SOAPAction against the {@code soapAction} of the WSDL
 * ([BasicProfile1.2] R2744, TIP1-A_4519-01). The value is compared; missing quotation marks are not
 * a violation, the gematik Konnektor PoPP Postman collections send without them. Per namespace, the
 * newest minor version from {@code support/schemas} (api-telematik) applies; minor versions are
 * backward compatible, so the newest allows everything an older one allows.
 *
 * <p>Only the operation is checked, not envelope and header. MTOM: {@code xop:Include} stands for
 * the content of a {@code base64Binary} element and is removed before validation.
 */
public final class RequestValidation {

  /** {@code liana.soap.request-validation}. */
  public enum Mode {
    /** No validation. */
    OFF,
    /** Violations logged as warnings, the request proceeds (measuring mode). */
    LOG,
    /** Reject violations with a SOAP fault. */
    REJECT
  }

  /** What a request violates: SOAPAction or schema. */
  record Violation(boolean soapAction, String text) {}

  /** Service namespace of the operations, XSD and WSDLs relative to {@code support/schemas}. */
  record Contract(String namespace, String xsd, List<String> wsdls) {}

  /** The services LIANA implements, per body namespace. */
  static final List<Contract> CONTRACTS =
      List.of(
          new Contract(
              "http://ws.gematik.de/conn/EventService/v7.2",
              "conn/EventService.xsd",
              List.of("conn/EventService.wsdl")),
          new Contract(
              "http://ws.gematik.de/conn/CardService/v8.1",
              "conn/CardService_v8_1_3.xsd",
              List.of("conn/CardService_v8_1_2.wsdl")),
          new Contract(
              "http://ws.gematik.de/conn/CardService/v8.2",
              "conn/CardService_v8_2_1.xsd",
              List.of("conn/CardService_v8_2_1.wsdl")),
          new Contract(
              "http://ws.gematik.de/conn/CardTerminalService/v1.1",
              "conn/CardTerminalService.xsd",
              List.of("conn/CardTerminalService.wsdl")),
          new Contract(
              "http://ws.gematik.de/conn/CertificateService/v6.0",
              "conn/CertificateService_v6_0_2.xsd",
              List.of("conn/CertificateService_v6_0_3.wsdl")),
          new Contract(
              "http://ws.gematik.de/conn/EncryptionService/v6.1",
              "conn/EncryptionService_v6_1_2.xsd",
              List.of("conn/EncryptionService_v6_1_1.wsdl")),
          new Contract(
              "http://ws.gematik.de/conn/SignatureService/v7.4",
              "conn/SignatureService_V7_4_5.xsd",
              List.of(
                  "conn/SignatureService_V7_4_3.wsdl", "conn/AuthSignatureService_v7_4_1.wsdl")),
          new Contract(
              "http://ws.gematik.de/conn/SignatureService/v7.5",
              "conn/SignatureService_V7_5_6.xsd",
              List.of("conn/SignatureService_V7_5_7.wsdl")),
          new Contract(
              "http://ws.gematik.de/conn/vsds/VSDService/v5.2",
              "conn/vsds/VSDService.xsd",
              List.of("conn/vsds/VSDService.wsdl")),
          new Contract(
              "http://ws.gematik.de/conn/vsds/KvkService/v4.0",
              "conn/vsds/KvkService.xsd",
              List.of("conn/vsds/KvkService.wsdl")));

  private static final String XOP = "http://www.w3.org/2004/08/xop/include";
  private static final String WSDL = "http://schemas.xmlsoap.org/wsdl/";
  private static final String WSDL_SOAP = "http://schemas.xmlsoap.org/wsdl/soap/";

  /** The W3C schemas (xmldsig, xenc) reference a non-pinned XMLSchema.dtd via DOCTYPE. */
  @SuppressWarnings("java:S5852") // only applied to the bundled W3C schemas, not to requests
  private static final Pattern DOCTYPE =
      Pattern.compile("<!DOCTYPE[^\\[>]*(\\[.*?\\])?\\s*>", Pattern.DOTALL);

  private static final int MAX_ERRORS = 10;

  private final Mode mode;
  private final Function<String, URL> schemas;
  private final Map<String, Contract> byNamespace = new HashMap<>();
  private final Map<String, Schema> compiled = new ConcurrentHashMap<>();
  private final Map<String, Map<String, String>> actions = new ConcurrentHashMap<>();

  /**
   * @param schemas file relative to {@code support/schemas} → URL (classpath, {@code
   *     liana-contract})
   */
  public RequestValidation(Mode mode, Function<String, URL> schemas) {
    this.mode = mode;
    this.schemas = schemas;
    CONTRACTS.forEach(contract -> byNamespace.put(contract.namespace(), contract));
  }

  public Mode mode() {
    return mode;
  }

  /**
   * Violations of {@code operation} (in the root part {@code message}) and {@code soapAction};
   * empty if the mode is {@link Mode#OFF} or the namespace is not a LIANA service (then the
   * resource rejects anyway).
   */
  List<Violation> violations(String soapAction, byte[] message, XmlNode operation) {
    Contract contract = byNamespace.get(operation.namespace());
    if (mode == Mode.OFF || contract == null) {
      return List.of();
    }
    List<Violation> violations = new ArrayList<>();
    String expected = actions(contract).get(operation.name());
    String action = soapAction == null ? null : soapAction.strip().replaceAll("^\"|\"$", "");
    if (expected != null && !expected.equals(action)) {
      violations.add(
          new Violation(
              true,
              action == null
                  ? "SOAPAction fehlt, erwartet " + expected
                  : "SOAPAction " + action + ", erwartet " + expected));
    }
    schemaErrors(contract, message).forEach(error -> violations.add(new Violation(false, error)));
    return violations;
  }

  /** Validator error messages for the operation, at most {@value #MAX_ERRORS}. */
  private List<String> schemaErrors(Contract contract, byte[] message) {
    Element element;
    try {
      element = operationElement(message);
    } catch (IOException | SAXException | ParserConfigurationException e) {
      // SoapEnvelope has read the message; only this parser rejects a DOCTYPE
      return List.of("nicht prüfbar: " + e.getMessage());
    }
    removeXopIncludes(element);
    List<String> errors = new ArrayList<>();
    var validator = schema(contract).newValidator();
    validator.setErrorHandler(
        new ErrorHandler() {
          @Override
          public void warning(SAXParseException e) {}

          @Override
          public void error(SAXParseException e) throws SAXException {
            errors.add(e.getMessage());
            if (errors.size() >= MAX_ERRORS) {
              throw e;
            }
          }

          @Override
          public void fatalError(SAXParseException e) throws SAXException {
            error(e);
          }
        });
    try {
      validator.validate(new DOMSource(element));
    } catch (SAXException e) {
      // aborted after MAX_ERRORS, the messages are in errors
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
    return errors;
  }

  private static Element operationElement(byte[] message)
      throws IOException, SAXException, ParserConfigurationException {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setNamespaceAware(true);
    factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    factory.setXIncludeAware(false);
    factory.setExpandEntityReferences(false);
    Document document = factory.newDocumentBuilder().parse(new ByteArrayInputStream(message));
    NodeList bodies = document.getElementsByTagNameNS(SoapEnvelope.SOAP_ENV, "Body");
    for (Node child = bodies.item(0).getFirstChild();
        child != null;
        child = child.getNextSibling()) {
      if (child instanceof Element operation) {
        return operation;
      }
    }
    throw new SAXException("SOAP-Body ohne Operation");
  }

  private static void removeXopIncludes(Element element) {
    NodeList includes = element.getElementsByTagNameNS(XOP, "Include");
    for (int i = includes.getLength() - 1; i >= 0; i--) {
      Node include = includes.item(i);
      include.getParentNode().removeChild(include);
    }
  }

  private Schema schema(Contract contract) {
    return compiled.computeIfAbsent(
        contract.namespace(), namespace -> compile(schemas.apply(contract.xsd())));
  }

  /**
   * Compiles a schema from {@code liana-contract} with its imports from the classpath, without
   * DOCTYPE and without external DTD (also for TUC_KON_080 (A) under a signature policy,
   * LIANA-112.09).
   */
  @SuppressWarnings(
      "java:S2755") // external DTDs are disabled, imports resolve from the classpath only
  public static Schema compile(URL xsd) {
    try {
      SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
      factory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
      factory.setResourceResolver(
          (type, ns, publicId, systemId, baseUri) ->
              systemId == null || baseUri == null ? null : new Input(resolve(baseUri, systemId)));
      return factory.newSchema(new StreamSource(new StringReader(read(xsd)), xsd.toString()));
    } catch (SAXException e) {
      throw new IllegalStateException("Schema " + xsd + " nicht ladbar: " + e.getMessage(), e);
    }
  }

  /** Operation → soapAction from the WSDLs of the service. */
  private Map<String, String> actions(Contract contract) {
    return actions.computeIfAbsent(
        contract.namespace(),
        namespace -> {
          Map<String, String> byOperation = new HashMap<>();
          for (String wsdl : contract.wsdls()) {
            byOperation.putAll(soapActions(schemas.apply(wsdl)));
          }
          return Map.copyOf(byOperation);
        });
  }

  /** {@code wsdl:binding/wsdl:operation/@name} → {@code soap:operation/@soapAction}. */
  static Map<String, String> soapActions(URL wsdl) {
    XMLInputFactory factory = XMLInputFactory.newFactory();
    factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
    factory.setProperty(XMLInputFactory.IS_NAMESPACE_AWARE, true);
    Map<String, String> result = new HashMap<>();
    try (InputStream in = wsdl.openStream()) {
      XMLStreamReader reader = factory.createXMLStreamReader(in);
      boolean inBinding = false;
      String operation = null;
      while (reader.hasNext()) {
        int event = reader.next();
        if (event == XMLStreamConstants.START_ELEMENT) {
          String ns = reader.getNamespaceURI();
          String name = reader.getLocalName();
          if (WSDL.equals(ns) && "binding".equals(name)) {
            inBinding = true;
          } else if (inBinding && WSDL.equals(ns) && "operation".equals(name)) {
            operation = reader.getAttributeValue(null, "name");
          } else if (operation != null && WSDL_SOAP.equals(ns) && "operation".equals(name)) {
            result.put(operation, reader.getAttributeValue(null, "soapAction"));
          }
        } else if (event == XMLStreamConstants.END_ELEMENT
            && WSDL.equals(reader.getNamespaceURI())) {
          if ("binding".equals(reader.getLocalName())) {
            inBinding = false;
          } else if ("operation".equals(reader.getLocalName())) {
            operation = null;
          }
        }
      }
      reader.close();
    } catch (IOException | XMLStreamException e) {
      throw new IllegalStateException("WSDL " + wsdl + " nicht lesbar: " + e.getMessage(), e);
    }
    return result;
  }

  private static String resolve(String baseUri, String systemId) {
    try {
      URI base = new URI(baseUri);
      if (base.isOpaque()) {
        // jar:file:…!/schemas/…: relative to the path after the "!"
        String spec = baseUri;
        int bang = spec.indexOf("!/");
        String inner = spec.substring(bang + 1);
        return spec.substring(0, bang + 1) + URI.create(inner).resolve(systemId);
      }
      return base.resolve(systemId).toString();
    } catch (URISyntaxException e) {
      throw new IllegalStateException("Schema-Verweis " + systemId + " von " + baseUri, e);
    }
  }

  private static String read(URL url) {
    try (InputStream in = url.openStream()) {
      return DOCTYPE
          .matcher(new String(in.readAllBytes(), StandardCharsets.UTF_8))
          .replaceFirst("");
    } catch (IOException e) {
      throw new UncheckedIOException("Schema " + url, e);
    }
  }

  /** An imported schema file from the classpath, without DOCTYPE. */
  private record Input(String systemId) implements LSInput {

    @Override
    public Reader getCharacterStream() {
      try {
        return new StringReader(read(URI.create(systemId).toURL()));
      } catch (IOException e) {
        throw new UncheckedIOException(e);
      }
    }

    @Override
    public String getSystemId() {
      return systemId;
    }

    @Override
    public void setCharacterStream(Reader characterStream) {}

    @Override
    public InputStream getByteStream() {
      return null;
    }

    @Override
    public void setByteStream(InputStream byteStream) {}

    @Override
    public String getStringData() {
      return null;
    }

    @Override
    public void setStringData(String stringData) {}

    @Override
    public void setSystemId(String systemId) {}

    @Override
    public String getPublicId() {
      return null;
    }

    @Override
    public void setPublicId(String publicId) {}

    @Override
    public String getBaseURI() {
      return systemId;
    }

    @Override
    public void setBaseURI(String baseURI) {}

    @Override
    public String getEncoding() {
      return null;
    }

    @Override
    public void setEncoding(String encoding) {}

    @Override
    public boolean getCertifiedText() {
      return false;
    }

    @Override
    public void setCertifiedText(boolean certifiedText) {}
  }
}

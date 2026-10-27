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
package de.gematik.liana.adapter.vsdm;

import de.gematik.liana.kern.vsdm.UpdateFlagService;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import javax.xml.XMLConstants;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;

/**
 * SOAP messages of the UFS ({@code cm/uf/UFS.wsdl}, [gemSpec_SST_FD_VSDM]): GetUpdateFlags with the
 * localisation in the header (Tab_FM_VSDM_20: Type UFS, Provider = ProviderID) and reading
 * GetUpdateFlagsResponse or a SOAP fault with GERROR:Error.
 */
final class UfsXml {

  static final String SOAP_ACTION = "http://ws.gematik.de/cm/uf/WSDL/v1.0#getupdateflags";
  static final String SOAP = "http://schemas.xmlsoap.org/soap/envelope/";
  static final String CM = "http://ws.gematik.de/cm/common/CmCommon/v2.0";
  static final String REQUEST_NS = "http://ws.gematik.de/cm/uf/CmUfServiceRequest/v2.0";
  static final String RESPONSE_NS = "http://ws.gematik.de/cm/uf/CmUfServiceResponse/v2.0";
  static final String GERROR = "http://ws.gematik.de/tel/error/v2.0";

  /** ServiceType of the UFS in the localisation (Tab_FM_VSDM_20). */
  static final String SERVICE_TYPE = "UFS";

  private UfsXml() {}

  /**
   * The GetUpdateFlags request for {@code iccsn}; {@code providerId} {@code null} yields an empty
   * provider.
   */
  static byte[] request(String iccsn, String providerId) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    try {
      XMLStreamWriter xml =
          XMLOutputFactory.newDefaultFactory().createXMLStreamWriter(out, "UTF-8");
      xml.writeStartDocument("UTF-8", "1.0");
      xml.writeStartElement("soap", "Envelope", SOAP);
      xml.writeNamespace("soap", SOAP);
      xml.writeNamespace("CM", CM);
      xml.writeNamespace("UFS", REQUEST_NS);
      xml.writeStartElement(SOAP, "Header");
      xml.writeStartElement(CM, "ServiceLocalization");
      element(xml, CM, "Type", SERVICE_TYPE);
      element(xml, CM, "Provider", providerId == null ? "" : providerId);
      xml.writeEndElement();
      xml.writeEndElement();
      xml.writeStartElement(SOAP, "Body");
      xml.writeStartElement(REQUEST_NS, "GetUpdateFlags");
      element(xml, CM, "Iccsn", iccsn);
      xml.writeEndElement();
      xml.writeEndElement();
      xml.writeEndElement();
      xml.writeEndDocument();
      xml.close();
    } catch (XMLStreamException e) {
      throw new IllegalStateException(e);
    }
    return out.toByteArray();
  }

  private static void element(XMLStreamWriter xml, String namespace, String name, String text)
      throws XMLStreamException {
    xml.writeStartElement(namespace, name);
    xml.writeCharacters(text);
    xml.writeEndElement();
  }

  /**
   * Reads the response: GetUpdateFlagsResponse with CM:UpdateFlag and the first
   * CM:ServiceReceipt/CM:Receipt, or a SOAP fault with the first GERROR:Trace/Code (without Trace,
   * the code from GERROR:Error).
   *
   * @throws IOException no SOAP envelope with either of the two responses
   */
  static UpdateFlagService.Answer response(byte[] body) throws IOException {
    XMLInputFactory factory = XMLInputFactory.newDefaultFactory();
    factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
    factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
    factory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
    try {
      XMLStreamReader xml = factory.createXMLStreamReader(new ByteArrayInputStream(body));
      boolean envelope = false;
      while (xml.hasNext()) {
        if (xml.next() != XMLStreamConstants.START_ELEMENT) {
          continue;
        }
        if (is(xml, SOAP, "Envelope")) {
          envelope = true;
        } else if (envelope && is(xml, RESPONSE_NS, "GetUpdateFlagsResponse")) {
          return flags(xml);
        } else if (envelope && is(xml, SOAP, "Fault")) {
          return fault(xml);
        }
      }
    } catch (XMLStreamException e) {
      throw new IOException("keine SOAP-Antwort: " + e.getMessage(), e);
    }
    throw new IOException("keine SOAP-Antwort mit GetUpdateFlagsResponse oder Fault");
  }

  /**
   * Reads to the end of GetUpdateFlagsResponse; {@code getElementText} consumes the end of the
   * leaves.
   */
  private static UpdateFlagService.Flags flags(XMLStreamReader xml) throws XMLStreamException {
    List<UpdateFlagService.UpdateFlag> flags = new ArrayList<>();
    byte[] receipt = null;
    String type = null;
    String provider = null;
    String updateId = null;
    String priority = null;
    boolean inFlag = false;
    int depth = 1;
    while (depth > 0) {
      int event = xml.next();
      if (event == XMLStreamConstants.END_ELEMENT) {
        depth--;
        if (is(xml, CM, "UpdateFlag")) {
          flags.add(
              new UpdateFlagService.UpdateFlag(
                  type, provider, updateId, !"OPTIONAL".equals(priority)));
          inFlag = false;
        }
      } else if (event == XMLStreamConstants.START_ELEMENT) {
        if (is(xml, CM, "UpdateFlag")) {
          inFlag = true;
          type = provider = updateId = priority = null;
          depth++;
        } else if (inFlag && is(xml, CM, "Type")) {
          type = xml.getElementText().trim();
        } else if (inFlag && is(xml, CM, "Provider")) {
          provider = xml.getElementText().trim();
        } else if (is(xml, CM, "UpdateId")) {
          updateId = xml.getElementText().trim();
        } else if (is(xml, CM, "UpdatePriority")) {
          priority = xml.getElementText().trim();
        } else if (is(xml, CM, "Receipt")) {
          String value = xml.getElementText();
          receipt = receipt != null ? receipt : Base64.getMimeDecoder().decode(value.trim());
        } else {
          depth++;
        }
      }
    }
    return new UpdateFlagService.Flags(flags, receipt);
  }

  private static UpdateFlagService.Fault fault(XMLStreamReader xml) throws XMLStreamException {
    String faultString = null;
    Integer code = null;
    int depth = 1;
    while (depth > 0) {
      int event = xml.next();
      if (event == XMLStreamConstants.END_ELEMENT) {
        depth--;
      } else if (event == XMLStreamConstants.START_ELEMENT) {
        if (xml.getNamespaceURI() == null || xml.getNamespaceURI().isEmpty()) {
          if (xml.getLocalName().equals("faultstring")) {
            faultString = xml.getElementText();
            continue;
          }
        } else if (is(xml, GERROR, "Code") && code == null) {
          String value = xml.getElementText().trim();
          code = value.matches("\\d{1,9}") ? Integer.valueOf(value) : null;
          continue;
        }
        depth++;
      }
    }
    return new UpdateFlagService.Fault(code, faultString == null ? "" : faultString.trim());
  }

  private static boolean is(XMLStreamReader xml, String namespace, String name) {
    return namespace.equals(xml.getNamespaceURI()) && name.equals(xml.getLocalName());
  }
}

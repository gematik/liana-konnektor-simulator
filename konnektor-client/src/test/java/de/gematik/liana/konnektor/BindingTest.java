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

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.gematik.liana.contract.Schemas;
import jakarta.xml.bind.annotation.XmlSchema;
import java.io.InputStream;
import java.util.EnumSet;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;
import javax.xml.parsers.DocumentBuilderFactory;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

class BindingTest {

  private static final String WSDL_NS = "http://schemas.xmlsoap.org/wsdl/";
  private static final String XSD_NS = "http://www.w3.org/2001/XMLSchema";

  private static Document wsdl(Binding binding) throws Exception {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setNamespaceAware(true);
    try (InputStream in = Schemas.resource(binding.wsdl()).openStream()) {
      return factory.newDocumentBuilder().parse(in);
    }
  }

  @Test
  @DisplayName(
      "LIANA-132: Operation listet je Binding genau die Operationen des portType seiner WSDL")
  void operationenWieWsdl() throws Exception {
    for (Binding binding : Binding.values()) {
      NodeList portTypes = wsdl(binding).getElementsByTagNameNS(WSDL_NS, "portType");
      Set<String> fromWsdl = new TreeSet<>();
      for (int i = 0; i < portTypes.getLength(); i++) {
        NodeList ops = ((Element) portTypes.item(i)).getElementsByTagNameNS(WSDL_NS, "operation");
        for (int j = 0; j < ops.getLength(); j++) {
          fromWsdl.add(((Element) ops.item(j)).getAttribute("name"));
        }
      }
      Set<String> fromEnum =
          EnumSet.allOf(Operation.class).stream()
              .filter(o -> o.bindings().contains(binding))
              .map(Operation::wsdlName)
              .collect(Collectors.toCollection(TreeSet::new));
      assertEquals(fromWsdl, fromEnum, binding.name());
    }
  }

  @Test
  @DisplayName(
      "LIANA-132: das Java-Paket jedes Bindings trägt den Schema-Namensraum, den seine WSDL importiert")
  void paketJeNamensraum() throws Exception {
    for (Binding binding : Binding.values()) {
      String serviceNs =
          "http://ws.gematik.de/conn/"
              + switch (binding.service()) {
                case AUTH_SIGNATURE_SERVICE -> "SignatureService";
                case VSD_SERVICE -> "vsds/VSDService";
                default -> binding.service().sdsName();
              }
              + "/v"
              + binding.version();
      NodeList imports = wsdl(binding).getElementsByTagNameNS(XSD_NS, "import");
      Set<String> imported = new TreeSet<>();
      for (int i = 0; i < imports.getLength(); i++) {
        imported.add(((Element) imports.item(i)).getAttribute("namespace"));
      }
      assertEquals(true, imported.contains(serviceNs), binding + " importiert " + imported);
      XmlSchema schema =
          Class.forName(binding.javaPackage() + ".ObjectFactory")
              .getPackage()
              .getAnnotation(XmlSchema.class);
      assertEquals(serviceNs, schema.namespace(), binding.name());
    }
  }

  @Test
  @DisplayName(
      "LIANA-132: PIN-Eingabe, Kartenkrypto und Warten am KT sind LONG, Verwaltung und Lesen SHORT")
  void timing() {
    assertEquals(
        EnumSet.of(
            Operation.VERIFY_PIN,
            Operation.CHANGE_PIN,
            Operation.UNBLOCK_PIN,
            Operation.ENABLE_PIN,
            Operation.DISABLE_PIN,
            Operation.SECURE_SEND_APDU,
            Operation.REQUEST_CARD,
            Operation.EJECT_CARD,
            Operation.EXTERNAL_AUTHENTICATE,
            Operation.SIGN_DOCUMENT,
            Operation.ACTIVATE_COMFORT_SIGNATURE,
            Operation.DECRYPT_DOCUMENT,
            Operation.READ_VSD),
        EnumSet.allOf(Operation.class).stream()
            .filter(o -> o.timing() == Timing.LONG)
            .collect(Collectors.toCollection(() -> EnumSet.noneOf(Operation.class))));
  }
}

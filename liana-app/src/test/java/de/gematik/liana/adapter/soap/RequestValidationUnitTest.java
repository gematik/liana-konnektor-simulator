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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.contract.Schemas;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** {@link RequestValidation} without Quarkus, schemas from liana-contract (LIANA-48). */
class RequestValidationUnitTest {

  private static final String READ_VSD =
      """
            <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>\
            <VSD:ReadVSD xmlns:VSD="http://ws.gematik.de/conn/vsds/VSDService/v5.2" \
            xmlns:CONN="http://ws.gematik.de/conn/ConnectorCommon/v5.0" \
            xmlns:CCTX="http://ws.gematik.de/conn/ConnectorContext/v2.0"><VSD:EhcHandle>e</VSD:EhcHandle>\
            <VSD:HpcHandle>s</VSD:HpcHandle><VSD:PerformOnlineCheck>false</VSD:PerformOnlineCheck>\
            <VSD:ReadOnlineReceipt>false</VSD:ReadOnlineReceipt><CCTX:Context><CONN:MandantId>M1</CONN:MandantId>\
            <CONN:ClientSystemId>CS1</CONN:ClientSystemId><CONN:WorkplaceId>WP1</CONN:WorkplaceId></CCTX:Context>\
            </VSD:ReadVSD></soap:Body></soap:Envelope>""";

  private static XmlNode operation(String xml) throws Exception {
    return SoapEnvelope.operation(xml.getBytes(StandardCharsets.UTF_8));
  }

  @Test
  @DisplayName(
      "VSDService.wsdl nennt als soapAction …/VSDService/v6.0#ReadVSD bei Body im Namensraum v5.2: das ist "
          + "kein Verstoß")
  void readVsdSoapActionAusDerWsdl() throws Exception {
    var validation = new RequestValidation(RequestValidation.Mode.REJECT, Schemas::resource);
    assertEquals(
        java.util.List.of(),
        validation.violations(
            "\"http://ws.gematik.de/conn/vsds/VSDService/v6.0#ReadVSD\"",
            READ_VSD.getBytes(StandardCharsets.UTF_8),
            operation(READ_VSD)));
    assertTrue(
        validation
            .violations(
                "\"http://ws.gematik.de/conn/vsds/VSDService/v5.2#ReadVSD\"",
                READ_VSD.getBytes(StandardCharsets.UTF_8),
                operation(READ_VSD))
            .getFirst()
            .soapAction());
  }

  @Test
  @DisplayName("Modus off: auch eine schemaverletzende Anfrage ohne SOAPAction hat keine Verstöße")
  void off() throws Exception {
    String broken = READ_VSD.replace("<VSD:HpcHandle>s</VSD:HpcHandle>", "");
    assertEquals(
        java.util.List.of(),
        new RequestValidation(RequestValidation.Mode.OFF, Schemas::resource)
            .violations(null, broken.getBytes(StandardCharsets.UTF_8), operation(broken)));
  }
}

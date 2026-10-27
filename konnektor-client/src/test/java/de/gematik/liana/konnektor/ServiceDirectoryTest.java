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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class ServiceDirectoryTest {

  private static ServiceDirectory sds(String name) throws IOException {
    try (InputStream in = ServiceDirectoryTest.class.getResourceAsStream("/sds/" + name)) {
      return ServiceDirectory.read(in);
    }
  }

  @Test
  @DisplayName(
      "LIANA-132 AC 3: connector.sds von LIANA wird gelesen, jede Operation des Clients löst auf")
  void liana() throws Exception {
    ServiceDirectory sds = sds("liana.xml");
    assertEquals("LIANA", sds.product().vendorId());
    assertEquals("6.0.4", sds.product().typeVersion());
    for (Operation operation : Operation.values()) {
      ServiceDirectory.Selection selection = sds.select(operation);
      assertTrue(selection.binding().serves(selection.offer().version()), operation.name());
    }
    ServiceDirectory.Selection verifyPin = sds.select(Operation.VERIFY_PIN);
    assertEquals(Binding.CARD_SERVICE_8_2, verifyPin.binding());
    assertEquals(Version.parse("8.2.1"), verifyPin.offer().version());
    assertEquals(
        URI.create("https://localhost:8443/ws/CardService"), verifyPin.offer().endpointTls());
    assertEquals(
        Optional.of(URI.create("http://localhost:8080/ws/CardService")),
        verifyPin.offer().endpoint());
    assertEquals("7.4.1", sds.select(Operation.EXTERNAL_AUTHENTICATE).offer().version().toString());
    assertEquals(
        Binding.AUTH_SIGNATURE_SERVICE_7_4, sds.select(Operation.EXTERNAL_AUTHENTICATE).binding());
    assertEquals("7.5.5", sds.select(Operation.SIGN_DOCUMENT).offer().version().toString());
  }

  @Test
  @DisplayName(
      "LIANA-132 AC 1, TIP1-A_4966: höchste angebotene Version mit Binding; Revision darf abweichen, 9.0 "
          + "ohne Binding wird übergangen, WSDL-Namensraum als TargetNamespace stört nicht")
  void mehrereVersionen() throws Exception {
    ServiceDirectory sds = sds("mehrere-versionen.xml");
    ServiceDirectory.Selection verifyPin = sds.select(Operation.VERIFY_PIN);
    assertEquals(Binding.CARD_SERVICE_8_2, verifyPin.binding());
    assertEquals("8.2.3", verifyPin.offer().version().toString());
    assertEquals(URI.create("https://kon/ws/CardService/82"), verifyPin.offer().endpointTls());
    assertEquals(Binding.CARD_SERVICE_8_2, sds.select(Operation.START_CARD_SESSION).binding());
    assertEquals(4, sds.offered(Service.CARD_SERVICE).size());
    assertEquals("8.1.2", sds.offered(Service.CARD_SERVICE).get(0).version().toString());
    assertEquals("TESTV", sds.product().vendorId());
    assertEquals("5.1.3", sds.product().fwVersion());
    assertTrue(sds.tlsMandatory());
    assertFalse(sds.clientAuthMandatory());
  }

  @Test
  @DisplayName(
      "LIANA-132: Operation nur in einer älteren Version mit Binding – die ältere wird gewählt")
  void aeltereVersion() throws Exception {
    ServiceDirectory sds = only("CardService", "8.1.2", "9.0.0");
    ServiceDirectory.Selection selection = sds.select(Operation.ENABLE_PIN);
    assertEquals(Binding.CARD_SERVICE_8_1, selection.binding());
    assertEquals("8.1.2", selection.offer().version().toString());
  }

  @Test
  @DisplayName(
      "LIANA-132 AC 2: kein Binding für die angebotenen Versionen – UnsupportedOperationException mit "
          + "Dienst, angebotenen und gebundenen Versionen")
  void keinBinding() throws Exception {
    UnsupportedOperationException e =
        assertThrows(
            UnsupportedOperationException.class,
            () -> only("CardService", "8.1.2", "9.0.0").select(Operation.START_CARD_SESSION));
    assertEquals(
        "CardService.StartCardSession: angeboten 8.1.2, 9.0.0, Client-Bindings 8.2",
        e.getMessage());

    UnsupportedOperationException missing =
        assertThrows(
            UnsupportedOperationException.class,
            () -> sds("mehrere-versionen.xml").select(Operation.ENCRYPT_DOCUMENT));
    assertEquals(
        "EncryptionService.EncryptDocument: angeboten keine Version, Client-Bindings 6.1",
        missing.getMessage());
  }

  @Test
  @DisplayName("LIANA-132: Endpoint fehlt (nur EndpointTLS ist Pflicht)")
  void ohneEndpoint() throws Exception {
    ServiceDirectory.Selection selection = sds("mehrere-versionen.xml").select(Operation.GET_CARDS);
    assertEquals(Optional.empty(), selection.offer().endpoint());
    assertEquals(URI.create("https://kon/ws/EventService"), selection.offer().endpointTls());
  }

  @Test
  @DisplayName("Kein Dienstverzeichnis: IOException; DTD wird nicht verarbeitet")
  void ungueltig() {
    assertThrows(IOException.class, () -> ServiceDirectory.read(stream("<html/>")));
    assertThrows(
        IOException.class,
        () ->
            ServiceDirectory.read(
                stream("<!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/passwd\">]><x>&e;</x>")));
  }

  private static ServiceDirectory only(String service, String... versions) throws IOException {
    StringBuilder xml =
        new StringBuilder(
            """
                <CONN:ConnectorServices xmlns:CONN="http://ws.gematik.de/conn/ServiceDirectory/v3.1"
                    xmlns:SI="http://ws.gematik.de/conn/ServiceInformation/v2.0">
                  <CONN:TLSMandatory>true</CONN:TLSMandatory>
                  <CONN:ClientAutMandatory>false</CONN:ClientAutMandatory>
                  <SI:ServiceInformation><SI:Service Name="%s"><SI:Abstract>x</SI:Abstract><SI:Versions>
                """
                .formatted(service));
    for (String version : versions) {
      xml.append("<SI:Version Version=\"")
          .append(version)
          .append("\"><SI:Abstract>x</SI:Abstract>")
          .append("<SI:EndpointTLS Location=\"https://kon/")
          .append(version)
          .append("\"/></SI:Version>");
    }
    xml.append("</SI:Versions></SI:Service></SI:ServiceInformation></CONN:ConnectorServices>");
    return ServiceDirectory.read(stream(xml.toString()));
  }

  private static InputStream stream(String xml) {
    return new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8));
  }
}

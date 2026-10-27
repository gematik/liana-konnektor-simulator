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
package de.gematik.liana.soap;

import static de.gematik.liana.soap.EventServiceTest.bodyElement;
import static de.gematik.liana.soap.EventServiceTest.xpath;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.sds.XsdValidator;
import io.quarkus.test.junit.QuarkusTest;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.w3c.dom.Element;

/**
 * decision-12: services and operations that LIANA does not implement answer with a SOAP fault
 * instead of 404.
 */
@QuarkusTest
class UnsupportedServiceTest {

  private final List<LogRecord> warnings = new ArrayList<>();
  private final Handler capture =
      new Handler() {
        @Override
        public void publish(LogRecord record) {
          if (record.getLevel().intValue() >= Level.WARNING.intValue()) {
            warnings.add(record);
          }
        }

        @Override
        public void flush() {}

        @Override
        public void close() {}
      };

  @BeforeEach
  void captureLog() {
    Logger.getLogger("de.gematik.liana.adapter.soap.SoapFaults").addHandler(capture);
  }

  @AfterEach
  void releaseLog() {
    Logger.getLogger("de.gematik.liana.adapter.soap.SoapFaults").removeHandler(capture);
  }

  private static String request(String namespace, String operation) {
    return """
                <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body>\
                <ns:%s xmlns:ns="%s"/></SOAP-ENV:Body></SOAP-ENV:Envelope>"""
        .formatted(operation, namespace);
  }

  private Element fault(String service, String namespace, String operation) throws Exception {
    String response =
        given()
            .contentType("text/xml; charset=utf-8")
            .body(request(namespace, operation))
            .post("/ws/" + service)
            .then()
            .statusCode(500)
            .contentType("text/xml")
            .extract()
            .asString();
    return bodyElement(response);
  }

  @ParameterizedTest(name = "{0} {2}")
  @CsvSource({"NFDService, http://ws.gematik.de/conn/nfds/NFDService/v1.0, ReadNFD"})
  @DisplayName(
      "decision-12 Dienst ohne Ressource unter /ws/ → SOAP-ENV:Client mit Dienst und Operation, Log-Warnung")
  void unknownService(String service, String namespace, String operation) throws Exception {
    Element fault = fault(service, namespace, operation);
    String reason = service + ": Operation " + operation + " wird von LIANA nicht unterstützt";
    assertEquals("SOAP-ENV:Client", xpath(fault, "faultcode"));
    assertEquals(reason, xpath(fault, "faultstring"));
    assertTrue(
        warnings.stream().anyMatch(r -> r.getMessage().equals(reason)),
        "Warnung im Log: " + reason);
  }

  @ParameterizedTest(name = "{0} {2}")
  @CsvSource({
    "EventService, http://ws.gematik.de/conn/EventService/v7.2, GetFoo",
    "CardService, http://ws.gematik.de/conn/CardService/v8.2, WriteCardData",
    "CertificateService, http://ws.gematik.de/conn/CertificateService/v6.0, VerifyCertificate",
    "AuthSignatureService, http://ws.gematik.de/conn/SignatureService/v7.4, GetJobNumber",
    "SignatureService, http://ws.gematik.de/conn/SignatureService/v7.5, ExternalAuthenticate",
    "EncryptionService, http://ws.gematik.de/conn/EncryptionService/v6.1, ExternalAuthenticate",
    "VSDService, http://ws.gematik.de/conn/vsds/VSDService/v5.2, ReadVSDAdV"
  })
  @DisplayName(
      "decision-12 unbekannte Operation in den Ressourcen → derselbe SOAP-Fault mit Dienst und Operation")
  void unknownOperation(String service, String namespace, String operation) throws Exception {
    Element fault = fault(service, namespace, operation);
    String reason = service + ": Operation " + operation + " wird von LIANA nicht unterstützt";
    assertEquals("SOAP-ENV:Client", xpath(fault, "faultcode"));
    assertEquals(reason, xpath(fault, "faultstring"));
    assertTrue(
        warnings.stream().anyMatch(r -> r.getMessage().equals(reason)),
        "Warnung im Log: " + reason);
  }

  @Test
  @DisplayName("Fault ist valide gegen den SOAP-1.1-Umschlag (ext/soap-envelope-1.1.xsd)")
  void faultValidAgainstSoapEnvelope() throws Exception {
    String response =
        given()
            .contentType("text/xml; charset=utf-8")
            .body(request("http://ws.gematik.de/conn/SignatureService/v7.5", "SignDocument"))
            .post("/ws/SignatureService")
            .then()
            .statusCode(500)
            .extract()
            .asString();
    XsdValidator.validate("ext/soap-envelope-1.1.xsd", response);
  }

  @ParameterizedTest(name = "{0}")
  @CsvSource({"VSDService", "SignatureService", "EncryptionService"})
  @DisplayName("Dienst mit und ohne Ressource, Body kein SOAP → SOAP-ENV:Client")
  void noSoap(String service) throws Exception {
    String response =
        given()
            .contentType("text/xml; charset=utf-8")
            .body("kein xml")
            .post("/ws/" + service)
            .then()
            .statusCode(500)
            .extract()
            .asString();
    assertEquals("SOAP-ENV:Client", xpath(bodyElement(response), "faultcode"));
  }
}

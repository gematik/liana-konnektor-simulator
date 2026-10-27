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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.admin.AdminServer;
import de.gematik.liana.kern.card.CardList;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import java.io.IOException;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import javax.xml.stream.XMLStreamException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;

/**
 * LIANA-164: every SOAP fault is in the log with all details (service, operation, detail text,
 * context, truncated request, MessageID/EventID, stack trace with cause); the response stays as it
 * was.
 */
@QuarkusTest
class SoapFaultLogTest {

  private static final String SIGNATURE_NS = "http://ws.gematik.de/conn/SignatureService/v7.4";
  private static final String CERTIFICATE_NS = "http://ws.gematik.de/conn/CertificateService/v6.0";

  @Inject CardList cards;

  @Inject AdminServer admin;

  private final List<LogRecord> warnings = new CopyOnWriteArrayList<>();
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
    given().port(admin.port()).post("/admin/reset").then().statusCode(200);
  }

  private static String envelope(String operation) {
    return "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\"><SOAP-ENV:Body>"
        + operation
        + "</SOAP-ENV:Body></SOAP-ENV:Envelope>";
  }

  private static String context() {
    return "<ns6:Context><ns3:MandantId>M1</ns3:MandantId><ns3:ClientSystemId>CS1</ns3:ClientSystemId>"
        + "<ns3:WorkplaceId>WP1</ns3:WorkplaceId></ns6:Context>";
  }

  private LogRecord only() {
    assertEquals(
        1, warnings.size(), () -> warnings.stream().map(LogRecord::getMessage).toList().toString());
    return warnings.get(0);
  }

  @Test
  @DisplayName(
      "TAB_KON_781 ExternalAuthenticate mit 16-Byte-Hash → 4000; Log mit Detailtext, Kontext, Anfrage und "
          + "MessageID, die Antwort ohne Detailtext")
  void detailNurImLog() throws Exception {
    String smcb = cards.card("KT-01", 2).orElseThrow().cardHandle();
    String hash = "AAECAwQFBgcICQoLDA0ODw==";
    String response =
        given()
            .contentType("text/xml; charset=utf-8")
            .header("SOAPAction", "\"" + SIGNATURE_NS + "#ExternalAuthenticate\"")
            .body(
                envelope(
                    "<ns5:ExternalAuthenticate xmlns:ns2=\"urn:oasis:names:tc:dss:1.0:core:schema\" "
                        + "xmlns:ns3=\"http://ws.gematik.de/conn/ConnectorCommon/v5.0\" xmlns:ns5=\""
                        + SIGNATURE_NS
                        + "\" xmlns:ns6=\"http://ws.gematik.de/conn/ConnectorContext/v2.0\"><ns3:CardHandle>"
                        + smcb
                        + "</ns3:CardHandle>"
                        + context()
                        + "<ns5:BinaryString><ns2:Base64Data MimeType="
                        + "\"application/octet-stream\">"
                        + hash
                        + "</ns2:Base64Data></ns5:BinaryString>"
                        + "</ns5:ExternalAuthenticate>"))
            .post("/ws/AuthSignatureService")
            .then()
            .statusCode(500)
            .extract()
            .asString();
    Element fault = bodyElement(response);
    assertEquals("Syntaxfehler", xpath(fault, "faultstring"));
    assertFalse(response.contains("16 Byte"), response);

    LogRecord record = only();
    String log = record.getMessage();
    assertTrue(log.contains("SOAP-Fault 4000 an SignatureService/v7.4#ExternalAuthenticate"), log);
    assertTrue(log.contains("BinaryString muss ein SHA-256-Hash (32 Byte) sein, ist 16 Byte"), log);
    assertTrue(log.contains("Context{MandantId=M1, ClientSystemId=CS1, WorkplaceId=WP1}"), log);
    assertTrue(log.contains("Base64Data[MimeType=application/octet-stream]=" + hash), log);
    assertTrue(log.contains("MessageID " + xpath(fault, "//*[local-name()='MessageID']")), log);
    assertTrue(log.contains("EventID " + xpath(fault, "//*[local-name()='EventID']")), log);
    assertTrue(record.getThrown() != null, "Stacktrace im Log");
  }

  @Test
  @DisplayName(
      "TUC_KON_200 ReadCardCertificate bei io-error am Slot → 4044; die IOException des Terminals ist die "
          + "Ursache im Log")
  void ursacheImStacktrace() {
    String smcb = cards.card("KT-01", 2).orElseThrow().cardHandle();
    given()
        .port(admin.port())
        .contentType("application/json")
        .body("{\"type\":\"io-error\"}")
        .put("/admin/terminals/KT-01/slots/2/fault")
        .then()
        .statusCode(200);
    given()
        .contentType("text/xml; charset=utf-8")
        .header("SOAPAction", "\"" + CERTIFICATE_NS + "#ReadCardCertificate\"")
        .body(
            envelope(
                "<ns4:ReadCardCertificate xmlns:ns3=\"http://ws.gematik.de/conn/ConnectorCommon/v5.0\" "
                    + "xmlns:ns4=\""
                    + CERTIFICATE_NS
                    + "\" xmlns:ns6=\"http://ws.gematik.de/conn/ConnectorContext/"
                    + "v2.0\"><ns3:CardHandle>"
                    + smcb
                    + "</ns3:CardHandle>"
                    + context()
                    + "<ns4:CertRefList>"
                    + "<ns4:CertRef>C.AUT</ns4:CertRef></ns4:CertRefList></ns4:ReadCardCertificate>"))
        .post("/ws/CertificateService")
        .then()
        .statusCode(500);

    LogRecord record = only();
    assertTrue(
        record
            .getMessage()
            .startsWith("SOAP-Fault 4044 an CertificateService/v6.0#ReadCardCertificate"),
        record.getMessage());
    assertInstanceOf(IOException.class, record.getThrown().getCause());
  }

  @Test
  @DisplayName(
      "Body kein wohlgeformtes XML → SOAP-ENV:Client; Log mit dem Fehler des XML-Parsers als Ursache")
  void keinXml() {
    given()
        .contentType("text/xml; charset=utf-8")
        .body("<kein")
        .post("/ws/CardService")
        .then()
        .statusCode(500);

    LogRecord record = only();
    assertTrue(
        record.getMessage().startsWith("SOAP-Fault Client: kein wohlgeformtes XML"),
        record.getMessage());
    assertInstanceOf(XMLStreamException.class, record.getThrown().getCause());
  }
}

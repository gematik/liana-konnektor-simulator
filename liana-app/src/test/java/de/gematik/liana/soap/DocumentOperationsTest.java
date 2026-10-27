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
import static de.gematik.liana.soap.EventServiceTest.serialize;
import static de.gematik.liana.soap.EventServiceTest.xpath;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.kern.card.CardList;
import de.gematik.liana.kern.vendor.Vendor;
import de.gematik.liana.kern.vendor.VendorProfile;
import de.gematik.liana.sds.XsdValidator;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.w3c.dom.Element;

/**
 * LIANA-60: SignatureService v7.5 and EncryptionService v6.1 up to TUC_KON_000, with the
 * Informationsmodell of Konnektor-QES: a second client entity (Mandant) M2 at WP1 and CS1 without
 * SMC-B (README of the suite: Mandant "m1" for KUC_1601_008), smcb-valid in KT-01/2 is
 * SM-B_Verwaltet of M1, hba-valid is inserted in KT-01/3. Requests like konnektor-service-client
 * 1.6.2.
 */
@QuarkusTest
@TestProfile(DocumentOperationsTest.QesInfomodel.class)
class DocumentOperationsTest {

  public static class QesInfomodel implements QuarkusTestProfile {
    @Override
    public Map<String, String> getConfigOverrides() {
      return Map.of(
          "liana.infomodel.mandants[0]",
          "M1",
          "liana.infomodel.mandants[1]",
          "M2",
          "liana.infomodel.workplaces[0].mandants[0]",
          "M1",
          "liana.infomodel.workplaces[0].mandants[1]",
          "M2",
          "liana.infomodel.smb-verwaltet[0].iccsn",
          "80276883110000168650",
          "liana.infomodel.smb-verwaltet[0].mandants[0]",
          "M1");
    }
  }

  private static final String SIG = "http://ws.gematik.de/conn/SignatureService/v7.5";
  private static final String SIG_V74 = "http://ws.gematik.de/conn/SignatureService/v7.4";
  private static final String CRYPT = "http://ws.gematik.de/conn/EncryptionService/v6.1";

  @Inject CardList cards;

  @Inject VendorProfile vendor;

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
  void reset() {
    Logger.getLogger("de.gematik.liana.adapter.soap.SoapFaults").removeHandler(capture);
    vendor.reset();
  }

  private String smcb() {
    return cards.card("KT-01", 2).orElseThrow().cardHandle();
  }

  private String hba() {
    return cards.card("KT-01", 3).orElseThrow().cardHandle();
  }

  static String context(String mandant, String clientSystem, String workplace, String userId) {
    return """
                <ns9:Context xmlns:ns9="http://ws.gematik.de/conn/ConnectorContext/v2.0">\
                <ns2:MandantId>%s</ns2:MandantId><ns2:ClientSystemId>%s</ns2:ClientSystemId>\
                <ns2:WorkplaceId>%s</ns2:WorkplaceId>%s</ns9:Context>"""
        .formatted(
            mandant,
            clientSystem,
            workplace,
            userId == null ? "" : "<ns2:UserId>" + userId + "</ns2:UserId>");
  }

  private static String envelope(String namespace, String operation, String inner) {
    return """
                <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Header/>\
                <SOAP-ENV:Body><ns4:%s xmlns:ns2="http://ws.gematik.de/conn/ConnectorCommon/v5.0" \
                xmlns:ns3="urn:oasis:names:tc:dss:1.0:core:schema" xmlns:ns4="%s">%s</ns4:%s></SOAP-ENV:Body>\
                </SOAP-ENV:Envelope>"""
        .formatted(operation, namespace, inner, operation);
  }

  static String signDocument(String cardHandle, String context) {
    return envelope(
        SIG,
        "SignDocument",
        "<ns2:CardHandle>"
            + cardHandle
            + "</ns2:CardHandle>"
            + context
            + "<ns4:TvMode>NONE</ns4:TvMode><ns4:JobNumber>ABC-123</ns4:JobNumber><ns4:SignRequest "
            + "RequestID=\"RequestID\"><ns4:OptionalInputs><ns3:SignatureType>urn:ietf:rfc:5652"
            + "</ns3:SignatureType><ns4:IncludeEContent>true</ns4:IncludeEContent></ns4:OptionalInputs>"
            + "<ns4:Document ShortText=\"shortText\"><ns3:Base64Data MimeType=\"text/plain; charset=utf-8\">"
            + "SGFsbG8=</ns3:Base64Data></ns4:Document><ns4:IncludeRevocationInfo>false</ns4:IncludeRevocationInfo>"
            + "</ns4:SignRequest>");
  }

  static String encryptDocument(String cardHandle, String context, String data) {
    return envelope(
        CRYPT,
        "EncryptDocument",
        context
            + "<ns4:RecipientKeys><ns4:CertificateOnCard><ns2:CardHandle>"
            + cardHandle
            + "</ns2:CardHandle><ns4:KeyReference>C.ENC</ns4:KeyReference></ns4:CertificateOnCard>"
            + "</ns4:RecipientKeys><ns2:Document><ns3:Base64Data MimeType=\"text/xml\">"
            + data
            + "</ns3:Base64Data></ns2:Document>");
  }

  static String decryptDocument(String cardHandle, String context) {
    return envelope(
        CRYPT,
        "DecryptDocument",
        context
            + "<ns4:PrivateKeyOnCard><ns2:CardHandle>"
            + cardHandle
            + "</ns2:CardHandle><ns4:KeyReference>C.ENC</ns4:KeyReference></ns4:PrivateKeyOnCard><ns2:Document>"
            + "<ns3:Base64Data MimeType=\"application/pkcs7-mime\">MIAGCSqGSIb3DQEHA6CAMIACAQI=</ns3:Base64Data>"
            + "</ns2:Document>");
  }

  static String verifyDocument(String context) {
    return envelope(
        SIG,
        "VerifyDocument",
        context
            + "<ns4:TvMode>CONFIRMED</ns4:TvMode><ns3:SignatureObject>"
            + "<ns3:Base64Signature Type=\"urn:ietf:rfc:5652\">MIAGCSqGSIb3DQEHAqCAMIACAQE=</ns3:Base64Signature>"
            + "</ns3:SignatureObject><ns4:IncludeRevocationInfo>false</ns4:IncludeRevocationInfo>");
  }

  private static Element post(
      String service, String namespace, String operation, String body, int status)
      throws Exception {
    String xml =
        given()
            .contentType("text/xml; charset=utf-8")
            .header("SOAPAction", "\"" + namespace + "#" + operation + "\"")
            .body(body)
            .post("/ws/" + service)
            .then()
            .statusCode(status)
            .extract()
            .asString();
    return bodyElement(xml);
  }

  /**
   * The nodes that Konnektor-QES checks in the fault ({@code $..Error.Trace.*}), and GERROR against
   * the XSD.
   */
  private static void assertGerror(Element fault, String code, String errorType, String text)
      throws Exception {
    assertEquals("SOAP-ENV:Server", xpath(fault, "faultcode"));
    assertEquals("Konnektor-Lokal", xpath(fault, "//*[local-name()='Instance']"));
    assertEquals("Konnektor", xpath(fault, "//*[local-name()='CompType']"));
    assertEquals(code, xpath(fault, "//*[local-name()='Code']"));
    assertEquals("Error", xpath(fault, "//*[local-name()='Severity']"));
    assertEquals(errorType, xpath(fault, "//*[local-name()='ErrorType']"));
    assertEquals(text, xpath(fault, "//*[local-name()='ErrorText']"));
    XsdValidator.validate(
        "tel/error/TelematikError.xsd",
        serialize(
            (Element)
                XPathFactory.newInstance()
                    .newXPath()
                    .evaluate("detail/*", fault, XPathConstants.NODE)));
  }

  @Test
  @DisplayName(
      "TIP1-A_5667 / TIP1-A_4643 GetJobNumber: Jobnummer ABC-123, Antwort gegen SignatureService_V7_5_6.xsd")
  void getJobNumber() throws Exception {
    Element response =
        post(
            "SignatureService",
            SIG,
            "GetJobNumber",
            envelope(SIG, "GetJobNumber", context("M1", "CS1", "WP1", null)),
            200);
    assertTrue(xpath(response, "//*[local-name()='JobNumber']").matches("[A-Z]{3}-[0-9]{3}"));
    XsdValidator.validate("conn/SignatureService_V7_5_6.xsd", serialize(response));
  }

  @Test
  @DisplayName(
      "LIANA-120 TIP1-A_4529-02 SignatureService 7.4.x: GetJobNumber im Namensraum v7.4, Antwort im selben "
          + "Namensraum gegen SignatureService_V7_4_5.xsd")
  void getJobNumberV74() throws Exception {
    Element response =
        post(
            "SignatureService",
            SIG_V74,
            "GetJobNumber",
            envelope(SIG_V74, "GetJobNumber", context("M1", "CS1", "WP1", null)),
            200);
    assertEquals(SIG_V74, response.getNamespaceURI());
    assertTrue(xpath(response, "//*[local-name()='JobNumber']").matches("[A-Z]{3}-[0-9]{3}"));
    XsdValidator.validate("conn/SignatureService_V7_4_5.xsd", serialize(response));
  }

  @Test
  @DisplayName(
      "LIANA-120 SignatureService 7.4.x: SignDocument im Namensraum v7.4 mit derselben Zugriffsprüfung "
          + "(TUC_KON_000 R7 / 4013)")
  void signDocumentV74() throws Exception {
    Element fault =
        post(
            "SignatureService",
            SIG_V74,
            "SignDocument",
            signDocument(smcb(), context("M2", "CS1", "WP1", "bert")).replace(SIG, SIG_V74),
            500);
    assertGerror(fault, "4013", "Security", "SM-B_Verwaltet ist dem Mandanten nicht zugeordnet");
  }

  @Test
  @DisplayName(
      "TUC_KON_000 R7 / 4013 SignDocument (KUC_1601_008): SMC-B ist SM-B_Verwaltet von M1, nicht von M2")
  void signDocumentSmbNichtImMandanten() throws Exception {
    Element fault =
        post(
            "SignatureService",
            SIG,
            "SignDocument",
            signDocument(smcb(), context("M2", "CS1", "WP1", "bert")),
            500);
    assertGerror(fault, "4013", "Security", "SM-B_Verwaltet ist dem Mandanten nicht zugeordnet");
  }

  @ParameterizedTest(name = "{0}")
  @CsvSource({"EncryptionService, EncryptDocument", "EncryptionService, DecryptDocument"})
  @DisplayName(
      "decision-12: gültiger Aufrufkontext ohne Fachlogik → SOAP-ENV:Client mit Dienst, Operation und "
          + "„nur bis zur Zugriffsprüfung“, dazu eine Log-Warnung")
  void ohneFachlogik(String service, String operation) throws Exception {
    String ctx = context("M1", "CS1", "WP1", "bert");
    String body =
        switch (operation) {
          case "EncryptDocument" -> encryptDocument(hba(), ctx, "PGE+PC9hPg==");
          case "DecryptDocument" -> decryptDocument(hba(), ctx);
          default -> verifyDocument(ctx);
        };
    Element fault =
        post(service, service.equals("SignatureService") ? SIG : CRYPT, operation, body, 500);
    String reason =
        service
            + ": Operation "
            + operation
            + " wird von LIANA nur bis zur Zugriffsprüfung "
            + "(TUC_KON_000) unterstützt, die Fachlogik ist nicht umgesetzt";
    assertEquals("SOAP-ENV:Client", xpath(fault, "faultcode"));
    assertEquals(reason, xpath(fault, "faultstring"));
    assertTrue(
        warnings.stream().anyMatch(r -> r.getMessage().equals(reason)),
        "Warnung im Log: " + reason);
  }

  @ParameterizedTest(name = "{0}")
  @CsvSource({"NEUTRAL, 4003", "KOCO, 4003", "SECUNET, 4003", "RISE, 4000"})
  @DisplayName(
      "TUC_KON_000 R9 / 4003 EncryptDocument (KUC_1701_008): HBA mit leerer UserId; RISE: 4000 Syntaxfehler")
  void encryptDocumentOhneUserId(Vendor profile, String code) throws Exception {
    vendor.switchTo(profile);
    Element fault =
        post(
            "EncryptionService",
            CRYPT,
            "EncryptDocument",
            encryptDocument(hba(), context("M1", "CS1", "WP1", ""), "PGE+PC9hPg=="),
            500);
    if (code.equals("4003")) {
      assertGerror(
          fault,
          "4003",
          "Technical",
          "Keine User-ID angegeben, die zur Identifikation der Kartensitzung_HBAx benötigt wird.");
    } else {
      assertGerror(fault, "4000", "Technical", "Syntaxfehler");
    }
  }

  @ParameterizedTest(name = "{0}")
  @ValueSource(strings = {"NEUTRAL", "KOCO", "SECUNET", "RISE"})
  @DisplayName(
      "TUC_KON_000 R9 / 4003 EncryptDocument als MTOM (KUC_1701_031): multipart/related mit XOP, Dokument "
          + "als Anhang; auch RISE 4003 (LIANA-167)")
  void encryptDocumentMtom(Vendor profile) throws Exception {
    vendor.switchTo(profile);
    String root =
        encryptDocument(
            hba(),
            context("M1", "CS1", "WP1", ""),
            "<xop:Include xmlns:xop=\"http://www.w3.org/2004/08/xop/include\" href=\"cid:doc-1@liana\"/>");
    String boundary = "----=_Part_0_1234567.1760000000000";
    String body =
        "--"
            + boundary
            + "\r\n"
            + "Content-Type: application/xop+xml; charset=utf-8; type=\"text/xml\"\r\n"
            + "Content-Transfer-Encoding: binary\r\n"
            + "Content-ID: <root.message@cxf.apache.org>\r\n\r\n"
            + root
            + "\r\n"
            + "--"
            + boundary
            + "\r\n"
            + "Content-Type: text/xml\r\n"
            + "Content-Transfer-Encoding: binary\r\n"
            + "Content-ID: <doc-1@liana>\r\n\r\n"
            + "<Sammelerklaerung/>\r\n"
            + "--"
            + boundary
            + "--\r\n";
    String xml =
        given()
            .contentType(
                "multipart/related; type=\"application/xop+xml\"; boundary=\""
                    + boundary
                    + "\"; start=\"<root.message@cxf.apache.org>\"; start-info=\"text/xml\"")
            .header("SOAPAction", "\"" + CRYPT + "#EncryptDocument\"")
            .body(body.getBytes(StandardCharsets.UTF_8))
            .post("/ws/EncryptionService")
            .then()
            .statusCode(500)
            .extract()
            .asString();
    assertGerror(
        bodyElement(xml),
        "4003",
        "Technical",
        "Keine User-ID angegeben, die zur Identifikation der Kartensitzung_HBAx benötigt wird.");
  }

  @ParameterizedTest(name = "{0}")
  @CsvSource({
    "NEUTRAL, 4021",
    "KOCO, 4005",
    "RISE, 4021",
    "SECUNET, 4021",
    "EHEX, 4021",
    "CGM, 4021"
  })
  @DisplayName(
      "TAB_KON_514-01 Hinweis 3 DecryptDocument (KUC_1702_007): falsche ClientSystemId → 4021, beim "
          + "Herstellerprofil KOCO der Protokollcode 4005")
  void decryptDocumentFalscheClientSystemId(Vendor profile, String code) throws Exception {
    vendor.switchTo(profile);
    Element fault =
        post(
            "EncryptionService",
            CRYPT,
            "DecryptDocument",
            decryptDocument(hba(), context("M1", "falscheCsId", "WP1", "bert")),
            500);
    if (code.equals("4005")) {
      assertGerror(fault, "4005", "Technical", "Ungültige Clientsystem-ID");
    } else {
      assertGerror(
          fault,
          "4021",
          "Technical",
          "Es sind nicht alle Pflichtparameter mandantId, clientSystemId, workplaceId gefüllt.");
    }
  }

  @ParameterizedTest(name = "{0}")
  @CsvSource({"NEUTRAL", "KOCO", "RISE", "SECUNET"})
  @DisplayName(
      "TAB_KON_514-01 / TAB_KON_760 VerifyDocument (KUC_1603_008): unbekannte MandantId → 4021 bei allen "
          + "Profilen")
  void verifyDocumentUnbekannterMandant(Vendor profile) throws Exception {
    vendor.switchTo(profile);
    Element fault =
        post(
            "SignatureService",
            SIG,
            "VerifyDocument",
            verifyDocument(context("unbekannteMandantid", "CS1", "WP1", "bert")),
            500);
    assertGerror(
        fault,
        "4021",
        "Technical",
        "Es sind nicht alle Pflichtparameter mandantId, clientSystemId, workplaceId gefüllt.");
  }

  @Test
  @DisplayName("TAB_KON_756 checkArguments: SignDocument ohne CardHandle → 4000")
  void signDocumentOhneCardHandle() throws Exception {
    Element fault =
        post(
            "SignatureService",
            SIG,
            "SignDocument",
            signDocument("", context("M1", "CS1", "WP1", "bert")),
            500);
    assertGerror(fault, "4000", "Technical", "Syntaxfehler");
  }
}

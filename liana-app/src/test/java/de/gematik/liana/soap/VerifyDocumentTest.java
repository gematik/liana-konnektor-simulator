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

import de.gematik.liana.kern.management.ManagementSettings;
import de.gematik.liana.kern.vendor.PeerDeviations;
import de.gematik.liana.kern.vendor.Vendor;
import de.gematik.liana.kern.vendor.VendorProfile;
import de.gematik.liana.sds.XsdValidator;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.cms.CMSSignedData;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.w3c.dom.Element;

/**
 * VerifyDocument CAdES (TIP1-A_5034-06, TAB_KON_760, LIANA-112.07), PAdES (LIANA-112.08) and XAdES
 * (LIANA-112.09) with Konnektor-QES files under {@code support/signatures} (originals) and {@code
 * support/vendor/signatures} (vendor signatures); requests like konnektor-service-client 1.6.2
 * (SignatureService 7.5).
 */
@QuarkusTest
@TestProfile(DocumentOperationsTest.QesInfomodel.class)
class VerifyDocumentTest {

  static final String SIG = "http://ws.gematik.de/conn/SignatureService/v7.5";
  private static final Path ORIGINALS = Path.of("support/signatures");
  private static final Path SIGNED = Path.of("support/vendor/signatures");
  private static final String CMS = "urn:ietf:rfc:5652";

  @Inject ManagementSettings settings;

  @Inject PeerDeviations deviations;

  @Inject VendorProfile vendor;

  @AfterEach
  void reset() {
    settings.online(false);
    deviations.reset();
    vendor.reset();
  }

  private static String base64(Path file) throws Exception {
    return Base64.getEncoder().encodeToString(Files.readAllBytes(file));
  }

  static String verifyDocument(
      String document,
      String signature,
      String type,
      String optionalInputs,
      boolean includeRevocationInfo) {
    return """
                <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Header/>\
                <SOAP-ENV:Body><ns4:VerifyDocument xmlns:ns2="http://ws.gematik.de/conn/ConnectorCommon/v5.0" \
                xmlns:ns3="urn:oasis:names:tc:dss:1.0:core:schema" \
                xmlns:vr="urn:oasis:names:tc:dss-x:1.0:profiles:verificationreport:schema#" xmlns:ns4="%s">%s\
                <ns4:TvMode>NONE</ns4:TvMode>%s%s%s<ns4:IncludeRevocationInfo>%s</ns4:IncludeRevocationInfo>\
                </ns4:VerifyDocument></SOAP-ENV:Body></SOAP-ENV:Envelope>"""
        .formatted(
            SIG,
            DocumentOperationsTest.context("M1", "CS1", "WP1", "bert"),
            optionalInputs == null
                ? ""
                : "<ns4:OptionalInputs>" + optionalInputs + "</ns4:OptionalInputs>",
            document == null
                ? ""
                : document.startsWith("<")
                    ? document
                    : "<ns4:Document><ns3:Base64Data MimeType=\"text/plain\">"
                        + document
                        + "</ns3:Base64Data></ns4:Document>",
            signature == null
                ? ""
                : "<ns3:SignatureObject><ns3:Base64Signature"
                    + (type == null ? "" : " Type=\"" + type + "\"")
                    + ">"
                    + signature
                    + "</ns3:Base64Signature></ns3:SignatureObject>",
            includeRevocationInfo);
  }

  /** SIG:Document with a PDF, like PSSIM: application/pdf-a. */
  private static String pdf(Path file) throws Exception {
    return "<ns4:Document ShortText=\"shortText\"><ns3:Base64Data MimeType=\"application/pdf-a\">"
        + Base64.getEncoder().encodeToString(Files.readAllBytes(file))
        + "</ns3:Base64Data></ns4:Document>";
  }

  static Element post(String body, int status) throws Exception {
    String xml =
        given()
            .contentType("text/xml; charset=utf-8")
            .header("SOAPAction", "\"" + SIG + "#VerifyDocument\"")
            .body(body)
            .post("/ws/SignatureService")
            .then()
            .statusCode(status)
            .extract()
            .asString();
    return bodyElement(xml);
  }

  private static Element verified(Element response) throws Exception {
    XsdValidator.validate("conn/SignatureService_V7_5_6.xsd", serialize(response));
    return response;
  }

  private static String at(Element element, String localNames) throws Exception {
    StringBuilder path = new StringBuilder();
    for (String name : localNames.split("/")) {
      path.append("//*[local-name()='").append(name).append("']");
    }
    return xpath(element, path.toString());
  }

  @Test
  @Tag("vendor-data")
  @DisplayName(
      "KUC_1607_200: CAdES enveloping von KOCO (QES, ECC) → OK, VALID, signingTime als "
          + "SIGNATURE_EMBEDDED_TIMESTAMP (TIP1-A_5545)")
  void enveloping() throws Exception {
    Element response =
        verified(
            post(
                verifyDocument(
                    null,
                    base64(
                        SIGNED.resolve("cades/IOP-ECC/Textdokument_standard.txt.koco.ecc.env.p7s")),
                    CMS,
                    null,
                    false),
                200));
    assertEquals("OK", at(response, "Status/Result"));
    assertEquals("VALID", at(response, "HighLevelResult"));
    assertEquals("SIGNATURE_EMBEDDED_TIMESTAMP", at(response, "TimestampType"));
    assertTrue(at(response, "VerificationResult/Timestamp").startsWith("20"));
  }

  @Test
  @Tag("vendor-data")
  @DisplayName(
      "KUC_1603_016, KUC_1607_216: Gegensignatur (HBA und SM-B) mit ReturnVerificationReport → VALID, "
          + "VerificationReport nach XSD mit je einem IndividualReport")
  void report() throws Exception {
    Element response =
        verified(
            post(
                verifyDocument(
                    null,
                    base64(
                        SIGNED.resolve(
                            "cades/IOP-ECC/Textdokument_standard.txt.koco.ecc.env.gegen.p7s")),
                    CMS,
                    "<vr:ReturnVerificationReport><vr:IncludeVerifier>false</vr:IncludeVerifier>"
                        + "<vr:IncludeCertificateValues>true</vr:IncludeCertificateValues>"
                        + "<vr:IncludeRevocationValues>true</vr:IncludeRevocationValues>"
                        + "<vr:ExpandBinaryValues>false</vr:ExpandBinaryValues>"
                        + "<vr:ReportDetailLevel>urn:oasis:names:tc:dss:1.0:profiles:verificationreport:reportdetail:"
                        + "allDetails</vr:ReportDetailLevel></vr:ReturnVerificationReport>",
                    false),
                200));
    assertEquals("VALID", at(response, "HighLevelResult"));
    assertEquals("2", xpath(response, "count(//*[local-name()='IndividualReport'])"));
    assertEquals(
        "urn:oasis:names:tc:dss:1.0:resultminor:valid:signature:OnAllDocuments",
        at(response, "IndividualReport/ResultMinor"));
  }

  @Test
  @Tag("vendor-data")
  @DisplayName(
      "KUC_1609_034, DETACHED_CONTENT_LF: detached mit dem Original aus dem Suite-Repo (LF) → VALID")
  void detached() throws Exception {
    Element response =
        verified(
            post(
                verifyDocument(
                    base64(ORIGINALS.resolve("cades/testwoche/Textdokument_standard.txt")),
                    base64(SIGNED.resolve("cades/testwoche/text.secu.ecc.det.sig")),
                    CMS,
                    null,
                    false),
                200));
    assertEquals("OK", at(response, "Status/Result"));
    assertEquals("VALID", at(response, "HighLevelResult"));
  }

  @Test
  @Tag("vendor-data")
  @DisplayName("KUC_1604_008: manipulierte CAdES → Warning, INVALID, 4115 Security Error")
  void manipulated() throws Exception {
    Element response =
        verified(
            post(
                verifyDocument(
                    null, base64(SIGNED.resolve("cades/CAdES_1_mod.bin")), CMS, null, false),
                200));
    assertEquals("Warning", at(response, "Status/Result"));
    assertEquals("INVALID", at(response, "HighLevelResult"));
    assertEquals("4115", at(response, "Trace/Code"));
    assertEquals("Security", at(response, "Trace/ErrorType"));
    assertEquals("Error", at(response, "Trace/Severity"));
    assertTrue(at(response, "Trace/ErrorText").startsWith("Signatur des Dokuments ungültig."));
  }

  @Test
  @Tag("vendor-data")
  @DisplayName(
      "TIP1-A_5545, UseVerificationTime: USER_DEFINED_TIMESTAMP mit dem Zeitpunkt; nach Ablauf des "
          + "Zertifikats INVALID mit 1021")
  void verificationTime() throws Exception {
    String signature =
        base64(SIGNED.resolve("cades/MedicationRequest_42.xml.koco.2.3.20.CAdES.enveloping.p7s"));
    Element valid =
        verified(
            post(
                verifyDocument(
                    null,
                    signature,
                    CMS,
                    "<ns4:UseVerificationTime>"
                        + "<ns3:SpecificTime>2023-12-01T16:02:00Z</ns3:SpecificTime></ns4:UseVerificationTime>",
                    false),
                200));
    assertEquals("VALID", at(valid, "HighLevelResult"));
    assertEquals("USER_DEFINED_TIMESTAMP", at(valid, "TimestampType"));
    assertEquals("2023-12-01T16:02:00Z", at(valid, "VerificationResult/Timestamp"));
    Element expired =
        verified(
            post(
                verifyDocument(
                    null,
                    signature,
                    CMS,
                    "<ns4:UseVerificationTime>"
                        + "<ns3:SpecificTime>2040-01-01T00:00:00Z</ns3:SpecificTime></ns4:UseVerificationTime>",
                    false),
                200));
    assertEquals("INVALID", at(expired, "HighLevelResult"));
    assertEquals("1021", at(expired, "Trace/Code"));
  }

  @Test
  @Tag("vendor-data")
  @DisplayName(
      "IncludeRevocationInfo online: dss:UpdatedSignature mit der OCSP-Antwort in crls.other "
          + "(decision-021)")
  void includeRevocationInfo() throws Exception {
    settings.online(true);
    Element response =
        verified(
            post(
                verifyDocument(
                    null,
                    base64(
                        SIGNED.resolve("cades/IOP-ECC/Textdokument_standard.txt.koco.ecc.env.p7s")),
                    CMS,
                    null,
                    true),
                200));
    assertEquals("VALID", at(response, "HighLevelResult"));
    CMSSignedData updated =
        new CMSSignedData(
            Base64.getDecoder().decode(at(response, "UpdatedSignature/Base64Signature")));
    assertEquals(
        1,
        updated
            .getOtherRevocationInfo(CMSObjectIdentifiers.id_ri_ocsp_response)
            .getMatches(null)
            .size());
  }

  @Test
  @DisplayName(
      "TAB_KON_760 Schritt 1 (KUC_1603_007, KUC_1604_006): leere Signatur und leeres Dokument → 4000")
  void syntax() throws Exception {
    Element fault = post(verifyDocument("", "", CMS, null, false), 500);
    assertEquals("4000", at(fault, "Trace/Code"));
  }

  @Test
  @Tag("vendor-data")
  @DisplayName(
      "TAB_KON_761: S/MIME bei KOCO → 4279 „SMIME-Funktionalität nicht unterstützt“ (KUC_1603_001), sonst "
          + "TUC_KON_080 (D) 4024 „Formatvalidierung fehlgeschlagen (MIME)“ für eine Nachricht ohne Content-Type "
          + "(KUC_1603_010); Dokument ohne Signatur → 4253")
  void smime() throws Exception {
    String message =
        Base64.getEncoder()
            .encodeToString(
                Files.readAllBytes(SIGNED.resolve("smime/SMimeMessage_without_ContentType.txt")));
    String smime = verifyDocument(null, message, "urn:ietf:rfc:5751", null, false);
    Element fault = post(smime, 500);
    assertEquals("4024", at(fault, "Trace/Code"));
    assertEquals("Security", at(fault, "Trace/ErrorType"));
    assertEquals("Formatvalidierung fehlgeschlagen (MIME)", at(fault, "Trace/ErrorText"));
    String document =
        verifyDocument(
            "<ns4:Document><ns3:Base64Data MimeType=\"application/pkcs7-mime\">"
                + message
                + "</ns3:Base64Data></ns4:Document>",
            null,
            null,
            null,
            false);
    assertEquals("4024", at(post(document, 500), "Trace/Code"));
    vendor.switchTo(Vendor.KOCO);
    for (String request : List.of(smime, document)) {
      Element koco = post(request, 500);
      assertEquals("4279", at(koco, "Trace/Code"));
      assertEquals("SMIME-Funktionalität nicht unterstützt", at(koco, "Trace/ErrorText"));
    }
    assertEquals(
        "4253", at(post(verifyDocument("SGFsbG8=", null, null, null, false), 500), "Trace/Code"));
  }

  @Test
  @Tag("vendor-data")
  @DisplayName(
      "KUC_1607_046, KUC_1604_005: PAdES von KOCO (QES, ECC) als PDF/A-Dokument ohne SignatureObject → OK, "
          + "VALID, Signaturzeitpunkt aus /M bzw. signingTime")
  void pades() throws Exception {
    Element response =
        verified(
            post(
                verifyDocument(
                    pdf(SIGNED.resolve("pades/IOP-ECC/sig.1149065825_A2A.koco.ecc.pdf")),
                    null,
                    null,
                    null,
                    false),
                200));
    assertEquals("OK", at(response, "Status/Result"));
    assertEquals("VALID", at(response, "HighLevelResult"));
    assertEquals("SIGNATURE_EMBEDDED_TIMESTAMP", at(response, "TimestampType"));
  }

  @Test
  @Tag("vendor-data")
  @DisplayName(
      "KUC_1607_229: PAdES von RISE mit RSA und IncludeRevocationInfo online → VALID, keine "
          + "UpdatedSignature (TUC_KON_159: bei PAdES nicht eingebettet)")
  void padesRsa() throws Exception {
    settings.online(true);
    Element response =
        verified(
            post(
                verifyDocument(
                    pdf(SIGNED.resolve("pades/sig.rsa.rise.1149065825_A2A.pdf")),
                    null,
                    null,
                    null,
                    true),
                200));
    assertEquals("VALID", at(response, "HighLevelResult"));
    assertEquals("0", xpath(response, "count(//*[local-name()='UpdatedSignature'])"));
  }

  @Test
  @DisplayName(
      "TUC_KON_080 (B), A_18780 (KUC_1604_013): PDF 1.7 ohne PDF/A-Kennung und PDF/A-3 → 4024 "
          + "„Formatvalidierung fehlgeschlagen (PDF/A)“; PDF/A ohne Signatur → 4253")
  void padesFormat() throws Exception {
    for (String file : new String[] {"pdf35k_PDF17.pdf", "1149065825_A3A.pdf"}) {
      Element fault =
          post(
              verifyDocument(
                  pdf(ORIGINALS.resolve("pades").resolve(file)), null, null, null, false),
              500);
      assertEquals("4024", at(fault, "Trace/Code"), file);
      assertEquals("Formatvalidierung fehlgeschlagen (PDF/A)", at(fault, "Trace/ErrorText"), file);
    }
    assertEquals(
        "4253",
        at(
            post(
                verifyDocument(
                    pdf(ORIGINALS.resolve("pades/1149065825_A2A.pdf")), null, null, null, false),
                500),
            "Trace/Code"));
  }

  /**
   * SIG:Document with Base64XML and dss:SignaturePtr to the NFD signature, like PSSIM „verifiziert
   * das XML-Dokument“ (KUC_1607_009).
   */
  private static String xml(byte[] content) {
    return "<ns4:Document ID=\"DocumentID\" ShortText=\"shortText\"><ns2:Base64XML>"
        + Base64.getEncoder().encodeToString(content)
        + "</ns2:Base64XML></ns4:Document>"
        + "<ns3:SignatureObject><ns3:SignaturePtr WhichDocument=\"DocumentID\" XPath=\"/*[local-name()="
        + "'NFD_Document']/*[local-name()='SignatureArzt']/*[local-name()='Signature']\"/></ns3:SignatureObject>";
  }

  @ParameterizedTest
  @Tag("vendor-data")
  @ValueSource(
      strings = {
        "IOP-ECC/nfdm.koco.ecc.xml.sig",
        "IOP-ECC/nfdm.rise.ecc.xml.sig",
        "IOP-ECC/nfdm.secu.ecc.xml.sig",
        "sig.NFDM_Beispiel_1.4.koco.4.2.1.20.NFDM.xml",
        "sig.NFDM_Beispiel_1.4.rise.2.0.12.NFDM.xml",
        "sig.NFDM_Beispiel_1.4.secu.4.10.1.NFDM.xml"
      })
  @DisplayName(
      "TIP1-A_5505 TUC_KON_162 (KUC_1607_009/010/014, 208/209/213): NFD-Signaturen der Hersteller (ECC, "
          + "RSASSA-PSS) → OK, VALID, SigningTime als SIGNATURE_EMBEDDED_TIMESTAMP")
  void xades(String file) throws Exception {
    Element response =
        verified(
            post(
                verifyDocument(
                    xml(Files.readAllBytes(SIGNED.resolve("xades").resolve(file))),
                    null,
                    null,
                    null,
                    false),
                200));
    assertEquals("OK", at(response, "Status/Result"));
    assertEquals("VALID", at(response, "HighLevelResult"));
    assertEquals("SIGNATURE_EMBEDDED_TIMESTAMP", at(response, "TimestampType"));
  }

  @Test
  @Tag("vendor-data")
  @DisplayName("TUC_KON_162: NFD nach der Signatur verändert → Warning, INVALID, 4115")
  void xadesManipulated() throws Exception {
    byte[] changed =
        new String(
                Files.readAllBytes(SIGNED.resolve("xades/IOP-ECC/nfdm.secu.ecc.xml.sig")),
                StandardCharsets.ISO_8859_1)
            .replace("<Vorname>Sarah</Vorname>", "<Vorname>Sahra</Vorname>")
            .getBytes(StandardCharsets.ISO_8859_1);
    Element response = verified(post(verifyDocument(xml(changed), null, null, null, false), 200));
    assertEquals("Warning", at(response, "Status/Result"));
    assertEquals("INVALID", at(response, "HighLevelResult"));
    assertEquals("4115", at(response, "Trace/Code"));
  }

  @Test
  @DisplayName(
      "TUC_KON_080 (A) (KUC_1604_011): PDF als Base64XML → 4022 Security „XML-Dokument nicht wohlgeformt“, "
          + "Profil RISE 4111 (VendorProfile reportsMalformedXmlAsSignatureType); XML ohne Signatur → 4253")
  void xadesFormat() throws Exception {
    String pdf =
        verifyDocument(
            xml(Files.readAllBytes(ORIGINALS.resolve("pades/pdf45k_PDFA-1B.pdf"))),
            null,
            null,
            null,
            false);
    Element fault = post(pdf, 500);
    assertEquals("4022", at(fault, "Trace/Code"));
    assertEquals("Security", at(fault, "Trace/ErrorType"));
    assertEquals("XML-Dokument nicht wohlgeformt", at(fault, "Trace/ErrorText"));
    vendor.switchTo(Vendor.RISE);
    assertEquals("4111", at(post(pdf, 500), "Trace/Code"));
    vendor.reset();
    assertEquals(
        "4253",
        at(
            post(
                verifyDocument(
                    xml("<a/>".getBytes(StandardCharsets.UTF_8)), null, null, null, false),
                500),
            "Trace/Code"));
  }
}

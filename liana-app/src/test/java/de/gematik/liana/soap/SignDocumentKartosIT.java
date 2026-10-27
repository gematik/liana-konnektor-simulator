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
import static de.gematik.liana.soap.VsdServiceTest.verifyPin;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.adapter.fake.FakeTerminals;
import de.gematik.liana.adapter.fake.Fault;
import de.gematik.liana.admin.AdminServer;
import de.gematik.liana.crypto.CountingRevocation;
import de.gematik.liana.crypto.PadesSignatures;
import de.gematik.liana.kern.card.CardList;
import de.gematik.liana.kern.management.ManagementSettings;
import de.gematik.liana.kern.signature.PdfSignatures;
import de.gematik.liana.kern.vendor.Vendor;
import de.gematik.liana.kern.vendor.VendorProfile;
import de.gematik.liana.sds.XsdValidator;
import de.gematik.liana.wiring.RecordedCardEngine;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.ess.ContentHints;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.w3c.dom.Element;

/**
 * SignDocument nonQES (LIANA-112.02) against kartos: smcb-valid in KT-01/2 signs with
 * PrK.HCI.OSIG.E256 (TAB_KON_900), BouncyCastle verifies the signatures with the embedded
 * C.HCI.OSIG. Requests like konnektor-service-client 1.6.2 in Konnektor-QES (KUC_1601_*), responses
 * against SignatureService_V7_5_6.xsd.
 */
@QuarkusTest
@TestProfile(SignDocumentKartosIT.Profile.class)
class SignDocumentKartosIT {

  public static class Profile implements QuarkusTestProfile {
    @Override
    public Map<String, String> getConfigOverrides() {
      return Map.of(RecordedCardEngine.KARTOS, "kartos");
    }

    @Override
    public Set<Class<?>> getEnabledAlternatives() {
      return Set.of(CountingRevocation.class);
    }
  }

  private static final String SIG = "http://ws.gematik.de/conn/SignatureService/v7.5";
  private static final String CMS = "urn:ietf:rfc:5652";
  static final String CONTEXT = DocumentOperationsTest.context("M1", "CS1", "WP1", "bert");
  static final byte[] TEXT = "Hallo LIANA\r\n".getBytes(StandardCharsets.UTF_8);
  static final String PADES = "<ns3:SignatureType>http://uri.etsi.org/02778/3</ns3:SignatureType>";

  /** PDF/A-2A of Konnektor-QES (KUC_1607_049). */
  static final byte[] PDFA = read("support/signatures/pades/1149065825_A2A.pdf");

  private static int jobs;

  /**
   * Own instance: also in the test JVM of {@link SignDocumentIT}, where Quarkus does not register
   * BC.
   */
  private static final BouncyCastleProvider BC = new BouncyCastleProvider();

  @Inject AdminServer admin;

  @Inject CardList cards;

  @Inject FakeTerminals terminals;

  @Inject ManagementSettings settings;

  @Inject VendorProfile vendor;

  @Inject CountingRevocation revocation;

  @BeforeEach
  void offline() {
    // Konnektor-QES: „TKQES stellt den Konnektor auf offline“ (KUC_1601_*)
    settings.online(false);
    revocation.takeRequests();
  }

  @AfterEach
  void reset() {
    terminals.terminal("KT-01").clearFault(2);
    given().port(admin.port()).post("/admin/reset").then().statusCode(200);
  }

  private static byte[] read(String file) {
    try {
      return Files.readAllBytes(Path.of(file));
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  private String smcb() {
    return cards.card("KT-01", 2).orElseThrow().cardHandle();
  }

  private static String jobNumber() {
    return "LIA-%03d".formatted(++jobs);
  }

  /**
   * SignDocument with one SignRequest; {@code optionalInputs} in SIG:OptionalInputs (dss = ns3, SIG
   * = ns4).
   */
  static String signDocument(
      String cardHandle,
      String jobNumber,
      String optionalInputs,
      String document,
      boolean includeRevocationInfo) {
    return """
                <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Header/>\
                <SOAP-ENV:Body><ns4:SignDocument xmlns:ns2="http://ws.gematik.de/conn/ConnectorCommon/v5.0" \
                xmlns:ns3="urn:oasis:names:tc:dss:1.0:core:schema" xmlns:ns4="%s"><ns2:CardHandle>%s</ns2:CardHandle>\
                %s<ns4:TvMode>NONE</ns4:TvMode><ns4:JobNumber>%s</ns4:JobNumber><ns4:SignRequest RequestID="RequestID">\
                %s<ns4:Document ID="DokumentID" ShortText="shortText">%s</ns4:Document>\
                <ns4:IncludeRevocationInfo>%s</ns4:IncludeRevocationInfo></ns4:SignRequest></ns4:SignDocument>\
                </SOAP-ENV:Body></SOAP-ENV:Envelope>"""
        .formatted(
            SIG,
            cardHandle,
            CONTEXT,
            jobNumber,
            optionalInputs.isEmpty()
                ? ""
                : "<ns4:OptionalInputs>" + optionalInputs + "</ns4:OptionalInputs>",
            document,
            includeRevocationInfo);
  }

  static String base64Data(String mimeType, byte[] content) {
    return "<ns3:Base64Data MimeType=\""
        + mimeType
        + "\">"
        + Base64.getEncoder().encodeToString(content)
        + "</ns3:Base64Data>";
  }

  /**
   * SignResponse of a PAdES signature against the XSD: the signed PDF, starting with the original.
   */
  static byte[] padesSigned(Element response, String result) throws Exception {
    XsdValidator.validate("conn/SignatureService_V7_5_6.xsd", serialize(response));
    assertEquals(result, xpath(response, "//*[local-name()='Status']/*[local-name()='Result']"));
    assertEquals("DokumentID", xpath(response, "//*[local-name()='DocumentWithSignature']/@ID"));
    assertEquals("DokumentID", xpath(response, "//*[local-name()='SignaturePtr']/@WhichDocument"));
    assertEquals("0", xpath(response, "count(//*[local-name()='Base64Signature'])"));
    assertEquals(
        "application/pdf-a",
        xpath(
            response,
            "//*[local-name()='DocumentWithSignature']"
                + "/*[local-name()='Base64Data']/@MimeType"));
    byte[] pdf =
        Base64.getDecoder()
            .decode(
                xpath(
                    response,
                    "//*[local-name()='DocumentWithSignature']" + "/*[local-name()='Base64Data']"));
    assertArrayEquals(PDFA, Arrays.copyOf(pdf, PDFA.length), "Incremental Update");
    return pdf;
  }

  /** Every signature in the PDF valid over its ByteRange ({@link #verify}). */
  static List<SignerInformation> verifyPdf(byte[] pdf) throws Exception {
    List<SignerInformation> signers = new ArrayList<>();
    for (PdfSignatures.Embedded embedded : new PadesSignatures(Clock.systemUTC()).signatures(pdf)) {
      try (ASN1InputStream in = new ASN1InputStream(embedded.cms())) {
        signers.addAll(
            verify(
                new CMSSignedData(
                    new CMSProcessableByteArray(embedded.signedContent()),
                    ContentInfo.getInstance(in.readObject()))));
      }
    }
    return signers;
  }

  static String cades(boolean includeEContent) {
    return "<ns3:SignatureType>"
        + CMS
        + "</ns3:SignatureType><ns4:IncludeEContent>"
        + includeEContent
        + "</ns4:IncludeEContent>";
  }

  static Element post(String body, int status) throws Exception {
    String xml =
        given()
            .contentType("text/xml; charset=utf-8")
            .header("SOAPAction", "\"" + SIG + "#SignDocument\"")
            .body(body)
            .post("/ws/SignatureService")
            .then()
            .statusCode(status)
            .extract()
            .asString();
    return bodyElement(xml);
  }

  /**
   * SignResponse with status OK or Warning, against the XSD; the CMS signature from
   * dss:Base64Signature.
   */
  static CMSSignedData signed(Element response, String result) throws Exception {
    XsdValidator.validate("conn/SignatureService_V7_5_6.xsd", serialize(response));
    assertEquals(result, xpath(response, "//*[local-name()='Status']/*[local-name()='Result']"));
    assertEquals("RequestID", xpath(response, "//*[local-name()='SignResponse']/@RequestID"));
    assertEquals(
        "shortText", xpath(response, "//*[local-name()='DocumentWithSignature']/@ShortText"));
    assertEquals(CMS, xpath(response, "//*[local-name()='Base64Signature']/@Type"));
    return new CMSSignedData(
        Base64.getDecoder().decode(xpath(response, "//*[local-name()='Base64Signature']")));
  }

  /**
   * Every SignerInfo valid with its certificate from the SignedData; ecdsa-with-SHA256
   * (SHA256ECDSA256), with an RSA certificate (HBA G2.0) RSASSA-PSS with SHA-256, MGF1-SHA-256 and
   * salt 32.
   */
  static List<SignerInformation> verify(CMSSignedData cms) throws Exception {
    List<SignerInformation> signers = new ArrayList<>(cms.getSignerInfos().getSigners());
    for (SignerInformation signer : signers) {
      @SuppressWarnings("unchecked")
      X509CertificateHolder certificate =
          (X509CertificateHolder)
              cms.getCertificates().getMatches(signer.getSID()).iterator().next();
      assertTrue(
          signer.verify(
              new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(certificate)),
          "Signatur gültig");
      ASN1ObjectIdentifier key =
          certificate.getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm();
      if (key.equals(PKCSObjectIdentifiers.rsaEncryption)
          || key.equals(PKCSObjectIdentifiers.id_RSASSA_PSS)) {
        assertEquals(PKCSObjectIdentifiers.id_RSASSA_PSS.getId(), signer.getEncryptionAlgOID());
        RSASSAPSSparams pss = RSASSAPSSparams.getInstance(signer.getEncryptionAlgParams());
        assertEquals(NISTObjectIdentifiers.id_sha256, pss.getHashAlgorithm().getAlgorithm());
        assertEquals(
            NISTObjectIdentifiers.id_sha256,
            AlgorithmIdentifier.getInstance(pss.getMaskGenAlgorithm().getParameters())
                .getAlgorithm());
        assertEquals(32, pss.getSaltLength().intValue());
      } else {
        assertEquals(X9ObjectIdentifiers.ecdsa_with_SHA256.getId(), signer.getEncryptionAlgOID());
      }
    }
    return signers;
  }

  /** Embedded OCSP responses from {@code SignedData.crls.other} (id-ri-ocsp-response, RFC 5940). */
  static List<Object> ocsp(CMSSignedData cms) {
    return new ArrayList<>(
        cms.getOtherRevocationInfo(CMSObjectIdentifiers.id_ri_ocsp_response).getMatches(null));
  }

  @Test
  @DisplayName(
      "TIP1-A_5010-11 / TUC_KON_160 / TUC_KON_166 CAdES enveloping (KUC_1601_211): IncludeEContent=true, "
          + "Signatur mit PrK.HCI.OSIG.E256 gültig, eContent ist das Dokument, signing-certificate-v2, signingTime, "
          + "ContentHints mit dem ShortText (TUC_KON_155)")
  void enveloping() throws Exception {
    verifyPin(smcb());
    CMSSignedData cms =
        signed(
            post(
                signDocument(
                    smcb(),
                    jobNumber(),
                    cades(true),
                    base64Data("text/plain; charset=utf-8", TEXT),
                    false),
                200),
            "OK");
    assertArrayEquals(TEXT, (byte[]) cms.getSignedContent().getContent());
    SignerInformation signer = verify(cms).get(0);
    assertNotNull(
        signer.getSignedAttributes().get(PKCSObjectIdentifiers.id_aa_signingCertificateV2));
    assertNotNull(signer.getSignedAttributes().get(CMSAttributes.signingTime));
    Attribute hints = signer.getSignedAttributes().get(PKCSObjectIdentifiers.id_aa_contentHint);
    assertEquals(
        "shortText",
        ContentHints.getInstance(hints.getAttrValues().getObjectAt(0))
            .getContentDescriptionUTF8()
            .getString());
  }

  @Test
  @DisplayName(
      "TIP1-A_4624 / TAB_KON_583 Default-Signaturverfahren (KUC_1605_003): ohne SignatureType, "
          + "IncludeEContent=false → CAdES detached, gültig mit dem Dokument")
  void detachedDefault() throws Exception {
    verifyPin(smcb());
    CMSSignedData cms =
        signed(
            post(
                signDocument(
                    smcb(),
                    jobNumber(),
                    "<ns4:IncludeEContent>false" + "</ns4:IncludeEContent>",
                    base64Data("text/plain; charset=iso-8859-15", TEXT),
                    false),
                200),
            "OK");
    assertNull(cms.getSignedContent());
    verify(new CMSSignedData(new CMSProcessableByteArray(TEXT), cms.getEncoded()));
  }

  @ParameterizedTest(name = "{0}")
  @CsvSource({
    "NEUTRAL, false, OK",
    "SECUNET, false, OK",
    "RISE, false, OK",
    "KOCO, false, Warning",
    "SECUNET, true, OK",
    "KOCO, true, Warning"
  })
  @DisplayName(
      "TAB_KON_065 ReturnUpdatedSignature parallel (KUC_1601_014, KUC/HSK_1601_019): zweiter SignerInfo in "
          + "der vorhandenen SignedData, beide gültig; KOCO offline wie online mit Warnung 1039")
  void parallel(Vendor profile, boolean online, String result) throws Exception {
    vendor.switchTo(profile);
    settings.online(online);
    verifyPin(smcb());
    CMSSignedData first =
        signed(
            post(
                signDocument(
                    smcb(),
                    jobNumber(),
                    cades(true),
                    base64Data("text/plain; charset=utf-8", TEXT),
                    false),
                200),
            "OK");
    Element response =
        post(
            signDocument(
                smcb(),
                jobNumber(),
                cades(true)
                    + "<ns3:ReturnUpdatedSignature Type=\""
                    + "http://ws.gematik.de/conn/sig/sigupdate/parallel\"/>",
                base64Data("application/octet-stream", first.getEncoded()),
                false),
            200);
    CMSSignedData both = signed(response, result);
    assertEquals(2, verify(both).size());
    assertArrayEquals(TEXT, (byte[]) both.getSignedContent().getContent());
    if (result.equals("Warning")) {
      assertEquals("1039", xpath(response, "//*[local-name()='Trace']/*[local-name()='Code']"));
      assertEquals(
          "Warnung, dass Offline-Modus aktiviert ist und keine OCSP-Statusabfrage durchgeführt wurde",
          xpath(response, "//*[local-name()='Trace']/*[local-name()='ErrorText']"));
    }
  }

  @ParameterizedTest(name = "{0}")
  @CsvSource({"NEUTRAL, OK", "RISE, OK", "SECUNET, OK", "KOCO, Warning"})
  @DisplayName(
      "TUC_KON_159 IncludeRevocationInfo offline (KUC_1601_026): keine Statusabfrage, keine OCSP-Antwort "
          + "eingebettet, KOCO mit Warnung 1039")
  void revocationOffline(Vendor profile, String result) throws Exception {
    vendor.switchTo(profile);
    verifyPin(smcb());
    Element response =
        post(
            signDocument(
                smcb(),
                jobNumber(),
                cades(true),
                base64Data("text/plain; charset=utf-8", TEXT),
                true),
            200);
    CMSSignedData cms = signed(response, result);
    verify(cms);
    assertTrue(ocsp(cms).isEmpty());
    assertEquals(0, revocation.takeRequests(), "offline keine Statusabfrage");
  }

  @ParameterizedTest(name = "{0}")
  @CsvSource({"NEUTRAL", "RISE", "SECUNET", "KOCO"})
  @DisplayName(
      "TUC_KON_159 Schritt 5 IncludeRevocationInfo online (KUC_1601_022, decision-021): OCSP-Antwort des "
          + "Simulators in crls.other (RFC 5940), good für das Signaturzertifikat, gültig signiert, producedAt nicht "
          + "vor signingTime")
  void revocationOnline(Vendor profile) throws Exception {
    vendor.switchTo(profile);
    settings.online(true);
    verifyPin(smcb());
    CMSSignedData cms =
        signed(
            post(
                signDocument(
                    smcb(),
                    jobNumber(),
                    cades(true),
                    base64Data("text/plain; charset=utf-8", TEXT),
                    true),
                200),
            "OK");
    SignerInformation signer = verify(cms).get(0);
    List<Object> embedded = ocsp(cms);
    assertEquals(1, embedded.size());
    assertEquals(1, revocation.takeRequests());
    OCSPResp ocsp = new OCSPResp(OCSPResponse.getInstance(embedded.get(0)));
    assertEquals(OCSPResp.SUCCESSFUL, ocsp.getStatus());
    BasicOCSPResp basic = (BasicOCSPResp) ocsp.getResponseObject();
    assertTrue(
        basic.isSignatureValid(
            new JcaContentVerifierProviderBuilder().setProvider(BC).build(basic.getCerts()[0])),
        "OCSP-Antwort gültig signiert");
    @SuppressWarnings("unchecked")
    X509CertificateHolder certificate =
        (X509CertificateHolder) cms.getCertificates().getMatches(signer.getSID()).iterator().next();
    SingleResp single = basic.getResponses()[0];
    assertEquals(certificate.getSerialNumber(), single.getCertID().getSerialNumber());
    assertNull(single.getCertStatus(), "good");
    Date signingTime =
        Time.getInstance(
                signer
                    .getSignedAttributes()
                    .get(CMSAttributes.signingTime)
                    .getAttrValues()
                    .getObjectAt(0))
            .getDate();
    assertFalse(
        basic.getProducedAt().before(signingTime),
        "producedAt " + basic.getProducedAt() + " vor signingTime " + signingTime);
  }

  @Test
  @DisplayName(
      "TUC_KON_159 online ohne IncludeRevocationInfo: Statusabfrage, aber keine eingebettete Antwort")
  void onlineWithoutRevocationInfo() throws Exception {
    settings.online(true);
    verifyPin(smcb());
    CMSSignedData cms =
        signed(
            post(
                signDocument(
                    smcb(),
                    jobNumber(),
                    cades(true),
                    base64Data("text/plain; charset=utf-8", TEXT),
                    false),
                200),
            "OK");
    verify(cms);
    assertTrue(ocsp(cms).isEmpty());
    assertEquals(1, revocation.takeRequests());
  }

  @Test
  @DisplayName(
      "TAB_KON_757 4197 SignaturePlacement bei CMS (KUC_1601_007): Warnung, Signatur trotzdem gültig")
  void signaturePlacement() throws Exception {
    verifyPin(smcb());
    Element response =
        post(
            signDocument(
                smcb(),
                jobNumber(),
                cades(true)
                    + "<ns3:SignaturePlacement "
                    + "CreateEnvelopedSignature=\"true\" WhichDocument=\"DokumentID\"><ns3:XPathFirstChildOf>/*"
                    + "</ns3:XPathFirstChildOf></ns3:SignaturePlacement>",
                "<ns3:Base64Data>JVBERi0xLjQ=</ns3:Base64Data>",
                false),
            200);
    verify(signed(response, "Warning"));
    assertEquals("4197", xpath(response, "//*[local-name()='Trace']/*[local-name()='Code']"));
    assertEquals(
        "Warning", xpath(response, "//*[local-name()='Trace']/*[local-name()='Severity']"));
    assertEquals(
        "Technical", xpath(response, "//*[local-name()='Trace']/*[local-name()='ErrorType']"));
    assertEquals(
        "Parameter SignaturePlacement wurde ignoriert",
        xpath(response, "//*[local-name()='Trace']/*[local-name()='ErrorText']"));
  }

  @Test
  @DisplayName("TAB_KON_757 4252 (KUC_1601_016): dieselbe Jobnummer im zweiten SignDocument")
  void jobNumberTwice() throws Exception {
    verifyPin(smcb());
    String job = jobNumber();
    String body =
        signDocument(smcb(), job, cades(true), base64Data("text/xml; charset=utf-8", TEXT), false);
    signed(post(body, 200), "OK");
    assertFault(
        post(body, 500),
        "4252",
        "Technical",
        "Jobnummer wurde in den letzten 1.000 Aufrufen bereits verwendet und ist nicht zulässig");
  }

  @Test
  @DisplayName("TUC_KON_166 Schritt 3 / 4120 (KUC_1601_010): Karte liefert eine ungültige Signatur")
  void cardSignatureInvalid() throws Exception {
    verifyPin(smcb());
    terminals
        .terminal("KT-01")
        .fault(
            2,
            Fault.response(
                    "5BF94E873DB24297AECB972564517B6606FBCB63D133652AEB9BD88F"
                        + "551E9A8CA3FBE1B8B4FAF7FE390BBA9CB92E10EC0BF33C14F6BC96B5E2F649D26DE16F2D9000")
                .onlyFor("002A9E9A"));
    assertFault(
        post(
            signDocument(smcb(), jobNumber(), cades(true), base64Data("text/plain", TEXT), false),
            500),
        "4120",
        "Security",
        "Kartenfehler");
  }

  @Test
  @DisplayName("TUC_KON_160 (3) / 4126 (KUC_1601_006): eGK als Signaturkarte")
  void egk() throws Exception {
    String egk = cards.card("KT-01", 1).orElseThrow().cardHandle();
    assertFault(
        post(
            signDocument(
                egk, jobNumber(), cades(false), base64Data("application/pdf-a", TEXT), false),
            500),
        "4126",
        "Security",
        "Kartentyp nicht zulässig für Signatur");
  }

  @ParameterizedTest(name = "{0}")
  @CsvSource(
      delimiter = '|',
      value = {
        "A_18756 XAdES mit der SM-B (KUC_1601_002)|<ns3:SignatureType>urn:ietf:rfc:3275</ns3:SignatureType>",
        "TAB_KON_583 Default XML → XAdES (KUC_1605_008)|",
        "unbekannter SignatureType|<ns3:SignatureType>urn:liana:unbekannt</ns3:SignatureType>"
      })
  @DisplayName("TAB_KON_127 / 4111 ungültiger Signaturtyp für nonQES")
  void invalidSignatureType(String name, String optionalInputs) throws Exception {
    verifyPin(smcb());
    String document =
        name.contains("unbekannt")
            ? base64Data("text/plain", TEXT)
            : "<ns2:Base64XML>"
                + Base64.getEncoder().encodeToString("<a/>".getBytes(StandardCharsets.UTF_8))
                + "</ns2:Base64XML>";
    Element fault =
        post(
            signDocument(
                smcb(), jobNumber(), optionalInputs == null ? "" : optionalInputs, document, false),
            500);
    assertFault(fault, "4111", "Technical", "Ungültiger Signaturtyp oder Signaturvariante");
    if (!name.contains("unbekannt")) {
      // Konnektor-QES KUC_1601_003: „enthält Knoten $..Detail.text“
      assertEquals(
          "nonQES-XAdES wird nicht unterstützt (A_18756)",
          xpath(fault, "//*[local-name()='Trace']/*[local-name()='Detail']"));
    }
    XsdValidator.validate(
        "tel/error/TelematikError.xsd",
        serialize(
            (Element)
                javax.xml.xpath.XPathFactory.newInstance()
                    .newXPath()
                    .evaluate("detail/*", fault, javax.xml.xpath.XPathConstants.NODE)));
  }

  @Test
  @DisplayName("TUC_KON_218 Schritt 3 / 4085: PIN.SMC nicht verifiziert")
  void pinNotVerified() throws Exception {
    assertFault(
        post(
            signDocument(smcb(), jobNumber(), cades(true), base64Data("text/plain", TEXT), false),
            500),
        "4085",
        "Security",
        "Zugriffsbedingungen nicht erfüllt");
  }

  @Test
  @DisplayName(
      "TIP1-A_5010-11 / TUC_KON_160 PAdES mit der SM-B (KUC_1601_004): Incremental Update, das signierte PDF "
          + "in DocumentWithSignature, SignaturePtr auf DokumentID, Signatur mit PrK.HCI.OSIG.E256 gültig, ShortText "
          + "in /Reason (TUC_KON_155)")
  void pades() throws Exception {
    verifyPin(smcb());
    byte[] pdf =
        padesSigned(
            post(
                signDocument(
                    smcb(), jobNumber(), PADES, base64Data("application/pdf-a", PDFA), false),
                200),
            "OK");
    assertEquals(1, verifyPdf(pdf).size());
    try (PDDocument document = Loader.loadPDF(pdf)) {
      assertEquals("shortText", document.getLastSignatureDictionary().getReason());
    }
  }

  @Test
  @DisplayName("TAB_KON_779-01 / 4111: PAdES als Parallelsignatur und PAdES für Text mit der SM-B")
  void padesVariante() throws Exception {
    verifyPin(smcb());
    assertFault(
        post(
            signDocument(
                smcb(),
                jobNumber(),
                PADES
                    + "<ns3:ReturnUpdatedSignature Type=\""
                    + "http://ws.gematik.de/conn/sig/sigupdate/parallel\"/>",
                base64Data("application/pdf-a", PDFA),
                false),
            500),
        "4111",
        "Technical",
        "Ungültiger Signaturtyp oder Signaturvariante");
    assertFault(
        post(signDocument(smcb(), jobNumber(), PADES, base64Data("text/plain", TEXT), false), 500),
        "4111",
        "Technical",
        "Ungültiger Signaturtyp oder Signaturvariante");
  }

  @Test
  @DisplayName(
      "TIP1-A_5010-11 SignDocument als MTOM (KUC_1601_019): Dokument als XOP-Anhang, CAdES enveloping")
  void mtom() throws Exception {
    verifyPin(smcb());
    String root =
        signDocument(
            smcb(),
            jobNumber(),
            cades(true),
            "<ns3:Base64Data MimeType=\"text/xml; "
                + "charset=utf-8\"><xop:Include xmlns:xop=\"http://www.w3.org/2004/08/xop/include\" "
                + "href=\"cid:8d74ba8f-6174-4dbc-ab9d-3a35aaf9bd07%40null\"/></ns3:Base64Data>",
            false);
    String boundary = "uuid:6b62cda8-ef2a-4e0c-8f31-ad9a0aa1c3fe";
    byte[] body =
        ("--"
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
                + "Content-Type: application/octet-stream\r\n"
                + "Content-Transfer-Encoding: binary\r\n"
                + "Content-ID: <8d74ba8f-6174-4dbc-ab9d-3a35aaf9bd07@null>\r\n\r\n"
                + new String(TEXT, StandardCharsets.UTF_8)
                + "\r\n"
                + "--"
                + boundary
                + "--\r\n")
            .getBytes(StandardCharsets.UTF_8);
    String xml =
        given()
            .contentType(
                "multipart/related; type=\"application/xop+xml\"; boundary=\""
                    + boundary
                    + "\"; start=\"<root.message@cxf.apache.org>\"; start-info=\"text/xml\"")
            .header("SOAPAction", "\"" + SIG + "#SignDocument\"")
            .body(body)
            .post("/ws/SignatureService")
            .then()
            .statusCode(200)
            .extract()
            .asString();
    CMSSignedData cms = signed(bodyElement(xml), "OK");
    assertArrayEquals(TEXT, (byte[]) cms.getSignedContent().getContent());
    verify(cms);
  }

  /** eMail10k.txt of Konnektor-QES (KUC_1601_001), CRLF. */
  static final byte[] MAIL = read("support/signatures/smime/eMail10k.txt");

  private static final String SMIME =
      "<ns3:SignatureType>urn:ietf:rfc:5751</ns3:SignatureType>"
          + "<ns4:IncludeEContent>true</ns4:IncludeEContent>";

  /**
   * SignResponse of an S/MIME signature against the XSD: the S/MIME message from
   * DocumentWithSignature.
   */
  static byte[] smimeSigned(Element response) throws Exception {
    XsdValidator.validate("conn/SignatureService_V7_5_6.xsd", serialize(response));
    assertEquals("OK", xpath(response, "//*[local-name()='Status']/*[local-name()='Result']"));
    assertEquals("DokumentID", xpath(response, "//*[local-name()='SignaturePtr']/@WhichDocument"));
    assertEquals(
        "application/pkcs7-mime",
        xpath(
            response,
            "//*[local-name()='DocumentWithSignature']"
                + "/*[local-name()='Base64Data']/@MimeType"));
    return Base64.getDecoder()
        .decode(
            xpath(
                response,
                "//*[local-name()='DocumentWithSignature']" + "/*[local-name()='Base64Data']"));
  }

  @Test
  @DisplayName(
      "TIP1-A_5010-11 / TUC_KON_160 S/MIME mit der SM-B (KUC_1601_001): application/pkcs7-mime; "
          + "smime-type=signed-data, Header der Nachricht übernommen, eContent die MIME-Entität mit CRLF (RFC 5751 "
          + "3.1.1), Signatur mit PrK.HCI.OSIG.E256 gültig; VerifyDocument → VALID (KUC_1603_001)")
  void smime() throws Exception {
    verifyPin(smcb());
    byte[] smime =
        smimeSigned(
            post(
                signDocument(smcb(), jobNumber(), SMIME, base64Data("text/plain", MAIL), false),
                200));
    String text = new String(smime, StandardCharsets.ISO_8859_1);
    String headers = text.substring(0, text.indexOf("\r\n\r\n"));
    assertTrue(
        headers.startsWith(
            "From: Tim Tester <tim.tester@gematik.de>\r\nTo: josef@jedermann.de\r\n"),
        headers);
    assertTrue(
        headers.contains(
            "\r\nMIME-Version: 1.0\r\nContent-Type: application/pkcs7-mime; "
                + "smime-type=signed-data; name=\"smime.p7m\"\r\nContent-Transfer-Encoding: base64\r\n"
                + "Content-Disposition: attachment; filename=\"smime.p7m\""),
        headers);
    CMSSignedData cms =
        new CMSSignedData(
            Base64.getMimeDecoder().decode(text.substring(text.indexOf("\r\n\r\n") + 4)));
    verify(cms);
    String entity =
        new String((byte[]) cms.getSignedContent().getContent(), StandardCharsets.UTF_8);
    String mail = new String(MAIL, StandardCharsets.UTF_8);
    assertEquals(
        "Content-Type: text/plain; charset=us-ascii;\r\nContent-Transfer-Encoding: 8bit\r\n\r\n"
            + mail.substring(mail.indexOf("\r\n\r\n") + 4),
        entity);
    Element verified =
        VerifyDocumentTest.post(
            VerifyDocumentTest.verifyDocument(
                "<ns4:Document><ns3:Base64Data "
                    + "MimeType=\"application/pkcs7-mime\">"
                    + Base64.getEncoder().encodeToString(smime)
                    + "</ns3:Base64Data></ns4:Document>",
                null,
                null,
                null,
                false),
            200);
    assertEquals("VALID", xpath(verified, "//*[local-name()='HighLevelResult']"));
  }

  @Test
  @DisplayName(
      "TUC_KON_159 Schritt 5 S/MIME online mit IncludeRevocationInfo: OCSP-Antwort in der SignedData")
  void smimeRevocationOnline() throws Exception {
    settings.online(true);
    verifyPin(smcb());
    byte[] smime =
        smimeSigned(
            post(
                signDocument(smcb(), jobNumber(), SMIME, base64Data("text/plain", MAIL), true),
                200));
    String text = new String(smime, StandardCharsets.ISO_8859_1);
    CMSSignedData cms =
        new CMSSignedData(
            Base64.getMimeDecoder().decode(text.substring(text.indexOf("\r\n\r\n") + 4)));
    verify(cms);
    assertEquals(1, ocsp(cms).size());
  }

  @ParameterizedTest(name = "{0}")
  @CsvSource({"NEUTRAL, 4024", "RISE, 4024", "SECUNET, 4024", "KOCO, 4279"})
  @DisplayName(
      "TUC_KON_080 (D) S/MIME für ein PDF (KUC_1601_009): 4024 „Formatvalidierung fehlgeschlagen (MIME)“, "
          + "KOCO 4279 „SMIME-Funktionalität nicht unterstützt“ (KUC_1601_001)")
  void smimeKeinMime(Vendor profile, String code) throws Exception {
    vendor.switchTo(profile);
    verifyPin(smcb());
    Element fault =
        post(
            signDocument(smcb(), jobNumber(), SMIME, base64Data("application/pdf-a", PDFA), false),
            500);
    if (code.equals("4024")) {
      assertFault(fault, "4024", "Security", "Formatvalidierung fehlgeschlagen (MIME)");
    } else {
      assertFault(fault, "4279", "Technical", "SMIME-Funktionalität nicht unterstützt");
      assertFault(
          post(
              signDocument(smcb(), jobNumber(), SMIME, base64Data("text/plain", MAIL), false), 500),
          "4279",
          "Technical",
          "SMIME-Funktionalität nicht unterstützt");
    }
  }

  @Test
  @DisplayName("TAB_KON_065 / 4111: S/MIME als Parallelsignatur")
  void smimeVariante() throws Exception {
    verifyPin(smcb());
    assertFault(
        post(
            signDocument(
                smcb(),
                jobNumber(),
                SMIME
                    + "<ns3:ReturnUpdatedSignature Type=\""
                    + "http://ws.gematik.de/conn/sig/sigupdate/parallel\"/>",
                base64Data("text/plain", MAIL),
                false),
            500),
        "4111",
        "Technical",
        "Ungültiger Signaturtyp oder Signaturvariante");
  }

  static void assertFault(Element fault, String code, String errorType, String text)
      throws Exception {
    assertEquals("SOAP-ENV:Server", xpath(fault, "faultcode"));
    assertEquals(code, xpath(fault, "//*[local-name()='Code']"));
    assertEquals(errorType, xpath(fault, "//*[local-name()='ErrorType']"));
    assertEquals(text, xpath(fault, "//*[local-name()='ErrorText']"));
  }
}

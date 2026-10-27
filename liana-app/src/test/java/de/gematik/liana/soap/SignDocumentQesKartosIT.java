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

import static de.gematik.liana.soap.EventServiceTest.serialize;
import static de.gematik.liana.soap.EventServiceTest.xpath;
import static de.gematik.liana.soap.SignDocumentKartosIT.PADES;
import static de.gematik.liana.soap.SignDocumentKartosIT.PDFA;
import static de.gematik.liana.soap.SignDocumentKartosIT.TEXT;
import static de.gematik.liana.soap.SignDocumentKartosIT.assertFault;
import static de.gematik.liana.soap.SignDocumentKartosIT.base64Data;
import static de.gematik.liana.soap.SignDocumentKartosIT.cades;
import static de.gematik.liana.soap.SignDocumentKartosIT.ocsp;
import static de.gematik.liana.soap.SignDocumentKartosIT.padesSigned;
import static de.gematik.liana.soap.SignDocumentKartosIT.post;
import static de.gematik.liana.soap.SignDocumentKartosIT.signDocument;
import static de.gematik.liana.soap.SignDocumentKartosIT.signed;
import static de.gematik.liana.soap.SignDocumentKartosIT.verify;
import static de.gematik.liana.soap.SignDocumentKartosIT.verifyPdf;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.adapter.fake.FakeTerminal;
import de.gematik.liana.adapter.fake.FakeTerminals;
import de.gematik.liana.adapter.fake.Fault;
import de.gematik.liana.adapter.fake.PinInput;
import de.gematik.liana.admin.AdminServer;
import de.gematik.liana.crypto.CountingRevocation;
import de.gematik.liana.crypto.XadesSignatures;
import de.gematik.liana.kern.card.CardList;
import de.gematik.liana.kern.management.ManagementSettings;
import de.gematik.liana.kern.vendor.Vendor;
import de.gematik.liana.kern.vendor.VendorProfile;
import de.gematik.liana.sds.XsdValidator;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.w3c.dom.Element;

/**
 * SignDocument QES (LIANA-112.04) against kartos: hba-valid in KT-01/3 signs after PIN.QES at the
 * PIN pad of the fake KT with PrK.HP.QES.E256 in DF.QES (TAB_KON_900), BouncyCastle verifies the
 * signatures with the embedded C.HP.QES. Online as in Konnektor-QES („TKQES stellt den Konnektor
 * auf online“, KUC_1602_*), requests like konnektor-service-client 1.6.2, responses against
 * SignatureService_V7_5_6.xsd.
 */
@QuarkusTest
@TestProfile(SignDocumentKartosIT.Profile.class)
class SignDocumentQesKartosIT {

  private static final String SIG = "http://ws.gematik.de/conn/SignatureService/v7.5";
  private static final String SIGN_RESPONSE = "(//*[local-name()='SignResponse'])[%d]";

  /** HBA G2.0 of Konnektor-QES with PrK.HP.QES.R2048 (support/images/README.md). */
  private static final Path HBA_G20 = Path.of("support/images/g20/hba-g20.xml");

  private static int jobs;

  @Inject AdminServer admin;

  @Inject CardList cards;

  @Inject FakeTerminals terminals;

  @Inject ManagementSettings settings;

  @Inject VendorProfile vendor;

  @Inject CountingRevocation revocation;

  @BeforeEach
  void online() {
    settings.online(true);
    revocation.takeRequests();
  }

  @AfterEach
  void reset() {
    kt().clearFault(3);
    kt().awaitPinInput(false);
    given().port(admin.port()).post("/admin/reset").then().statusCode(200);
  }

  private FakeTerminal kt() {
    return terminals.terminal("KT-01");
  }

  private String hba() {
    return cards.card("KT-01", 3).orElseThrow().cardHandle();
  }

  private static String jobNumber() {
    return "QES-%03d".formatted(++jobs);
  }

  private Element sign(
      String optionalInputs, String document, boolean includeRevocationInfo, int status)
      throws Exception {
    return post(
        signDocument(hba(), jobNumber(), optionalInputs, document, includeRevocationInfo), status);
  }

  /**
   * SignDocument with {@code n} SignRequests R1…Rn over the same text, CAdES enveloping
   * (KUC_1602_070).
   */
  private String batch(String job, int n) {
    String one =
        signDocument(hba(), job, cades(true), base64Data("text/plain; charset=utf-8", TEXT), false);
    int start = one.indexOf("<ns4:SignRequest ");
    int end = one.indexOf("</ns4:SignRequest>") + "</ns4:SignRequest>".length();
    StringBuilder requests = new StringBuilder();
    for (int i = 1; i <= n; i++) {
      requests.append(
          one.substring(start, end)
              .replace("RequestID=\"RequestID\"", "RequestID=\"R" + i + "\"")
              .replace("ID=\"DokumentID\"", "ID=\"D" + i + "\""));
    }
    return one.substring(0, start) + requests + one.substring(end);
  }

  private static CompletableFuture<Element> async(String body) {
    return CompletableFuture.supplyAsync(
        () -> {
          try {
            return post(body, 200);
          } catch (Exception e) {
            throw new IllegalStateException(e);
          }
        });
  }

  /** StopSignature (TAB_KON_840) with the context of SignDocument. */
  private static Element stop(String job, int status) throws Exception {
    String body =
        """
                <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Header/>\
                <SOAP-ENV:Body><ns4:StopSignature xmlns:ns2="http://ws.gematik.de/conn/ConnectorCommon/v5.0" \
                xmlns:ns4="%s">%s<ns4:JobNumber>%s</ns4:JobNumber></ns4:StopSignature></SOAP-ENV:Body>\
                </SOAP-ENV:Envelope>"""
            .formatted(SIG, SignDocumentKartosIT.CONTEXT, job);
    String xml =
        given()
            .contentType("text/xml; charset=utf-8")
            .header("SOAPAction", "\"" + SIG + "#StopSignature\"")
            .body(body)
            .post("/ws/SignatureService")
            .then()
            .statusCode(status)
            .extract()
            .asString();
    return EventServiceTest.bodyElement(xml);
  }

  /** Waits until the PIN pad shows the PIN.QES of {@code job} (mode await). */
  private void awaitPinQes(String job) throws InterruptedException {
    long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
    while (kt().display().isEmpty() && System.nanoTime() < deadline) {
      Thread.sleep(20);
    }
    assertEquals(
        job + " \u000BEingabe \u000BSignaturPIN \u000BHBA\u000FPIN.QES:",
        kt().display().orElse(null));
  }

  /**
   * The SignResponses against the XSD: RequestID R1…Rn, the valid signatures up to {@code signed},
   * after that without signature with Warning and 4049.
   */
  private static void assertBatch(Element response, int n, int signed) throws Exception {
    XsdValidator.validate("conn/SignatureService_V7_5_6.xsd", serialize(response));
    assertEquals(String.valueOf(n), xpath(response, "count(//*[local-name()='SignResponse'])"));
    for (int i = 1; i <= n; i++) {
      String r = SIGN_RESPONSE.formatted(i);
      assertEquals("R" + i, xpath(response, r + "/@RequestID"));
      if (i <= signed) {
        assertEquals("OK", xpath(response, r + "//*[local-name()='Result']"));
        CMSSignedData cms =
            new CMSSignedData(
                Base64.getDecoder()
                    .decode(xpath(response, r + "//*[local-name()='Base64Signature']")));
        assertQesSigner(cms, verify(cms).get(0));
      } else {
        assertEquals("Warning", xpath(response, r + "//*[local-name()='Result']"));
        assertEquals("4049", xpath(response, r + "//*[local-name()='Code']"));
        assertEquals(
            "Abbruch durch den Benutzer", xpath(response, r + "//*[local-name()='ErrorText']"));
        assertEquals("", xpath(response, r + "//*[local-name()='Base64Signature']"));
      }
    }
  }

  /** The signer is C.HP.QES: nonRepudiation (gemSpec_PKI, QES certificate of the HBA). */
  private static void assertQesSigner(CMSSignedData cms, SignerInformation signer) {
    @SuppressWarnings("unchecked")
    X509CertificateHolder certificate =
        (X509CertificateHolder) cms.getCertificates().getMatches(signer.getSID()).iterator().next();
    assertTrue(
        KeyUsage.fromExtensions(certificate.getExtensions()).hasUsages(KeyUsage.nonRepudiation),
        "C.HP.QES mit nonRepudiation: " + certificate.getSubject());
  }

  @Test
  @DisplayName(
      "TIP1-A_4655-04 TUC_KON_150 / TIP1-A_4652-03 TUC_KON_168 CAdES enveloping mit dem HBA (KUC_1602_003): "
          + "PIN.QES am KT, Signatur mit PrK.HP.QES.E256 gültig, Signer C.HP.QES, eine Statusauskunft (TUC_KON_159)")
  void enveloping() throws Exception {
    CMSSignedData cms =
        signed(sign(cades(true), base64Data("text/plain; charset=utf-8", TEXT), false, 200), "OK");
    assertArrayEquals(TEXT, (byte[]) cms.getSignedContent().getContent());
    assertQesSigner(cms, verify(cms).get(0));
    assertEquals(1, revocation.takeRequests());
    assertTrue(ocsp(cms).isEmpty(), "ohne IncludeRevocationInfo keine eingebettete OCSP-Antwort");
  }

  @Test
  @DisplayName("TUC_KON_150 CAdES detached mit dem HBA (KUC_1602_004): gültig mit dem Dokument")
  void detached() throws Exception {
    CMSSignedData cms =
        signed(sign(cades(false), base64Data("text/plain; charset=utf-8", TEXT), false, 200), "OK");
    assertNull(cms.getSignedContent());
    assertQesSigner(
        cms, verify(new CMSSignedData(new CMSProcessableByteArray(TEXT), cms.getEncoded())).get(0));
  }

  @Test
  @DisplayName(
      "TUC_KON_150 Schritt 10 / TUC_KON_159 IncludeRevocationInfo (KUC_1602_006): OCSP-Antwort eingebettet")
  void includeRevocationInfo() throws Exception {
    CMSSignedData cms =
        signed(sign(cades(true), base64Data("text/plain; charset=utf-8", TEXT), true, 200), "OK");
    verify(cms);
    assertEquals(1, ocsp(cms).size());
  }

  @Test
  @DisplayName(
      "TAB_KON_090 PIN.QES (Signatur auslösen): Anzeige mit der Jobnummer, Signatur erst nach der Eingabe")
  void pinQesAnzeige() throws Exception {
    kt().awaitPinInput(true);
    String job = jobNumber();
    String body = signDocument(hba(), job, cades(true), base64Data("text/plain", TEXT), false);
    CompletableFuture<Element> response =
        CompletableFuture.supplyAsync(
            () -> {
              try {
                return post(body, 200);
              } catch (Exception e) {
                throw new IllegalStateException(e);
              }
            });
    long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
    while (kt().display().isEmpty() && System.nanoTime() < deadline) {
      Thread.sleep(20);
    }
    assertEquals(
        job + " \u000BEingabe \u000BSignaturPIN \u000BHBA\u000FPIN.QES:",
        kt().display().orElse(null));
    kt().enterPin(3, PinInput.of(PinInput.Outcome.CORRECT));
    verify(signed(response.get(10, TimeUnit.SECONDS), "OK"));
  }

  @Test
  @DisplayName(
      "TUC_KON_150 Schritt 6 / TUC_KON_218: falsche PIN.QES (REJECTED) → die Karte verweigert die Signatur, "
          + "4085; danach signiert der HBA wieder, die PIN.QES gilt nur für einen Auftrag (Schritt 8)")
  void falschePinQes() throws Exception {
    kt().enterPin(3, PinInput.of(PinInput.Outcome.WRONG));
    assertFault(
        sign(cades(true), base64Data("text/plain", TEXT), false, 500),
        "4085",
        "Security",
        "Zugriffsbedingungen nicht erfüllt");
    verify(signed(sign(cades(true), base64Data("text/plain", TEXT), false, 200), "OK"));
    kt().enterPin(3, PinInput.of(PinInput.Outcome.CANCEL));
    assertFault(
        sign(cades(true), base64Data("text/plain", TEXT), false, 500),
        "4049",
        "Technical",
        "Abbruch durch den Benutzer");
  }

  @Test
  @DisplayName(
      "TUC_KON_200 / 4094 (KUC_1602_034): Karte antwortet nicht innerhalb von CARD_TIMEOUT_CARD")
  void kartenTimeout() throws Exception {
    kt().fault(3, Fault.delay(Duration.ofSeconds(2)));
    assertFault(
        sign(cades(true), base64Data("text/plain", TEXT), false, 500),
        "4094",
        "Technical",
        "Timeout beim Kartenzugriff aufgetreten");
  }

  @Test
  @DisplayName(
      "TIP1-A_4651-03 TUC_KON_154 Stapel (KUC_1602_070): eine PIN.QES für drei SignRequests, je eine "
          + "gültige SignResponse mit RequestID, je eine Statusauskunft")
  void stapel() throws Exception {
    kt().awaitPinInput(true);
    String job = jobNumber();
    CompletableFuture<Element> response = async(batch(job, 3));
    awaitPinQes(job);
    kt().enterPin(3, PinInput.of(PinInput.Outcome.CORRECT));
    assertBatch(response.get(20, TimeUnit.SECONDS), 3, 3);
    assertEquals(3, revocation.takeRequests());
  }

  @Test
  @DisplayName(
      "TIP1-A_5666-03 StopSignature während der PIN-Eingabe (TAB_KON_192 Nr. 3): OK, keine Signatur, "
          + "jede SignResponse 4049")
  void stopWaehrendPinEingabe() throws Exception {
    kt().awaitPinInput(true);
    String job = jobNumber();
    CompletableFuture<Element> response = async(batch(job, 3));
    awaitPinQes(job);
    assertEquals("OK", xpath(stop(job, 200), "//*[local-name()='Result']"));
    kt().enterPin(3, PinInput.of(PinInput.Outcome.CORRECT));
    assertBatch(response.get(20, TimeUnit.SECONDS), 3, 0);
    assertEquals(0, revocation.takeRequests());
  }

  @Test
  @DisplayName(
      "TIP1-A_5666-03 StopSignature während der Signaturen (KUC_1602_072, TAB_KON_192 Nr. 5): OK, die "
          + "Signaturen des Teilstapels sind verworfen, jede SignResponse 4049")
  void stopWaehrendSignatur() throws Exception {
    kt().awaitPinInput(true);
    kt().fault(3, Fault.delay(Duration.ofMillis(150)));
    String job = jobNumber();
    CompletableFuture<Element> response = async(batch(job, 20));
    awaitPinQes(job);
    kt().enterPin(3, PinInput.of(PinInput.Outcome.CORRECT));
    Thread.sleep(600);
    assertEquals("OK", xpath(stop(job, 200), "//*[local-name()='Result']"));
    assertBatch(response.get(30, TimeUnit.SECONDS), 20, 0);
  }

  @Test
  @DisplayName(
      "TAB_KON_842 StopSignature (KUC_1602_073): unbekannte bzw. abgeschlossene Jobnummer → 4243, ohne "
          + "JobNumber → 4000")
  void stopUnbekannt() throws Exception {
    assertFault(stop("UNK-696", 500), "4243", "Technical", "Jobnummer unbekannt");
    String job = jobNumber();
    assertBatch(post(batch(job, 2), 200), 2, 2);
    assertFault(stop(job, 500), "4243", "Technical", "Jobnummer unbekannt");
    assertFault(stop("", 500), "4000", "Technical", "Syntaxfehler");
  }

  @Test
  @DisplayName(
      "TUC_KON_154 Schritt 3: Nutzungszähler der PIN.QES im SE #2 abgelaufen (startSsec 2) → PIN.QES erneut "
          + "für den nächsten Teilstapel, wieder im Remote-PIN-Verfahren (LIANA-112.13); Abbruch dieser Eingabe "
          + "(TAB_KON_192 Nr. 4) behält den ersten Teilstapel")
  void teilstapel(@TempDir Path dir) throws Exception {
    Path original = kt().image(3).orElseThrow();
    Path image = dir.resolve("hba-ssec2.xml");
    Files.writeString(
        image, Files.readString(original).replace("{(1,00fa),(2,00fa)}", "{(1,02),(2,02)}"));
    swap(image);
    try {
      kt().enterPin(
              List.of(
                  new FakeTerminal.ScriptedPinInput(3, PinInput.of(PinInput.Outcome.CORRECT)),
                  new FakeTerminal.ScriptedPinInput(3, PinInput.of(PinInput.Outcome.CORRECT))));
      assertBatch(post(batch(jobNumber(), 3), 200), 3, 3);
      assertTrue(kt().pinScript().isEmpty(), "zwei PIN-Eingaben: " + kt().pinScript());
      kt().enterPin(
              List.of(
                  new FakeTerminal.ScriptedPinInput(3, PinInput.of(PinInput.Outcome.CORRECT)),
                  new FakeTerminal.ScriptedPinInput(3, PinInput.of(PinInput.Outcome.CANCEL))));
      assertBatch(post(batch(jobNumber(), 3), 200), 3, 2);
    } finally {
      swap(original);
    }
  }

  @Test
  @DisplayName(
      "A_17768-01 TAB_KON_900 HBA G2.0 (KUC_1602_080/081): QES mit PrK.HP.QES.R2048, Signer C.HP.QES.R2048, "
          + "RSASSA-PSS mit SHA-256, MGF1 und Salt 32 (gemSpec_COS G2_N088.600.a); als Stapel im SE #2 mit einer "
          + "PIN.QES (startSSecList (2,00fa), LIANA-112.13; im SE #1 nur eine Signatur je Eingabe); PAdES ebenso; XAdES "
          + "mit RSA → SOAP-ENV:Client (decision-12)")
  void hbaG20() throws Exception {
    Path original = kt().image(3).orElseThrow();
    swap(HBA_G20);
    try {
      CMSSignedData cms =
          signed(
              sign(cades(true), base64Data("text/plain; charset=utf-8", TEXT), false, 200), "OK");
      SignerInformation signer = verify(cms).get(0);
      assertQesSigner(cms, signer);
      assertEquals(PKCSObjectIdentifiers.id_RSASSA_PSS.getId(), signer.getEncryptionAlgOID());

      kt().enterPin(
              List.of(
                  new FakeTerminal.ScriptedPinInput(3, PinInput.of(PinInput.Outcome.CORRECT)),
                  new FakeTerminal.ScriptedPinInput(3, PinInput.of(PinInput.Outcome.CORRECT))));
      assertBatch(post(batch(jobNumber(), 2), 200), 2, 2);
      assertEquals(
          1, kt().pinScript().size(), "eine PIN.QES für den Stapel im SE #2: " + kt().pinScript());

      assertEquals(
          1,
          verifyPdf(
                  padesSigned(sign(PADES, base64Data("application/pdf-a", PDFA), false, 200), "OK"))
              .size());

      Element fault =
          post(
              signDocument(
                      hba(),
                      jobNumber(),
                      XadesIT.NFDM,
                      "<ns2:Base64XML>"
                          + Base64.getEncoder()
                              .encodeToString(
                                  Files.readAllBytes(
                                      Path.of("support/signatures/xades/NFDM_Beispiel_1.4.xml")))
                          + "</ns2:Base64XML>",
                      false)
                  .replace(
                      "<ns4:Document ID=\"DokumentID\" ",
                      "<ns4:Document ID=\"DokumentID\" RefURI=\"#Notfalldaten\" "),
              500);
      assertEquals("SOAP-ENV:Client", xpath(fault, "//*[local-name()='faultcode']"));
      String reason = xpath(fault, "//*[local-name()='faultstring']");
      assertTrue(reason.contains("XAdES mit PrK.HP.QES.R2048"), reason);
    } finally {
      swap(original);
    }
  }

  /** Inserts {@code image} instead of the HBA into KT-01/3 and waits for its CardHandle. */
  private void swap(Path image) throws InterruptedException {
    String before = hba();
    kt().eject(3);
    kt().insert(3, image);
    long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
    while (cards.card("KT-01", 3).map(c -> c.cardHandle().equals(before)).orElse(true)
        && System.nanoTime() < deadline) {
      Thread.sleep(20);
    }
  }

  @Test
  @DisplayName("TAB_KON_065 SignaturePlacement (KUC_1602_015): Warnung 4197, Signatur gültig")
  void signaturePlacement() throws Exception {
    String placement =
        cades(true)
            + "<ns3:SignaturePlacement WhichDocument=\"DokumentID\" "
            + "CreateEnvelopedSignature=\"true\"><ns3:XPathAfter>TODO</ns3:XPathAfter></ns3:SignaturePlacement>";
    Element response = sign(placement, base64Data("text/plain; charset=utf-8", TEXT), false, 200);
    verify(signed(response, "Warning"));
    assertEquals("4197", xpath(response, "//*[local-name()='Trace']/*[local-name()='Code']"));
  }

  @Test
  @DisplayName(
      "TIP1-A_4655-04 TUC_KON_150 PAdES mit dem HBA (KUC_1602_005, KUC_1609_006): PIN.QES am KT, Signer "
          + "C.HP.QES, eine Statusauskunft, mit IncludeRevocationInfo keine OCSP-Antwort im CMS (TUC_KON_159)")
  void pades() throws Exception {
    byte[] pdf = padesSigned(sign(PADES, base64Data("application/pdf-a", PDFA), true, 200), "OK");
    List<SignerInformation> signers = verifyPdf(pdf);
    assertEquals(1, signers.size());
    assertEquals(1, revocation.takeRequests());
    try (PDDocument document = Loader.loadPDF(pdf)) {
      PDSignature signature = document.getLastSignatureDictionary();
      CMSSignedData cms;
      try (ASN1InputStream in = new ASN1InputStream(signature.getContents(pdf))) {
        cms = new CMSSignedData(ContentInfo.getInstance(in.readObject()));
      }
      assertQesSigner(cms, cms.getSignerInfos().getSigners().iterator().next());
      assertTrue(
          cms.getCRLs().getMatches(null).isEmpty()
              && cms.getOtherRevocationInfo(CMSObjectIdentifiers.id_ri_ocsp_response)
                  .getMatches(null)
                  .isEmpty());
    }
  }

  @Test
  @DisplayName("TIP1-A_4628 / TAB_KON_583 Default PDF/A → PAdES (KUC_1605_009): ohne SignatureType")
  void padesDefault() throws Exception {
    verifyPdf(padesSigned(sign("", base64Data("application/pdf-a", PDFA), false, 200), "OK"));
  }

  @ParameterizedTest(name = "{0}")
  @CsvSource({
    "KUC_1602_030 XML als PDF/A, xml",
    "KUC_1602_090 A_18780 PDF/A-3A, 1149065825_A3A.pdf",
    "KUC_1604_013 PDF 1.7 ohne PDF/A-Kennung, pdf35k_PDF17.pdf"
  })
  @DisplayName(
      "TIP1-A_4527-04 TUC_KON_080 (B) / 4024: PAdES für ein Dokument, das sich nicht als PDF/A-1 oder -2 "
          + "ausweist")
  void padesKeinPdfA(String name, String file) throws Exception {
    byte[] document =
        file.equals("xml")
            ? "<sammelerklaerung/>".getBytes(StandardCharsets.UTF_8)
            : Files.readAllBytes(Path.of("support/signatures/pades", file));
    assertFault(
        sign(PADES, base64Data("application/pdf-a", document), false, 500),
        "4024",
        "Security",
        "Formatvalidierung fehlgeschlagen (PDF/A)");
    assertEquals(0, revocation.takeRequests(), "abgewiesen vor der Signatur");
  }

  @Test
  @DisplayName(
      "TIP1-A_4527-04 TUC_KON_080 / 4024 (KUC_1602_031): Text in UTF-16, als UTF-8 deklariert")
  void textNichtImZeichensatz() throws Exception {
    byte[] utf16 = "Hallo LIANA".getBytes(StandardCharsets.UTF_16);
    assertFault(
        sign(cades(true), base64Data("text/plain; charset=utf-8", utf16), false, 500),
        "4024",
        "Security",
        "Formatvalidierung fehlgeschlagen (Text)");
  }

  @Test
  @DisplayName("TUC_KON_150 (->1) / 4110 (KUC_1602_017): Binär gehört nicht zu den QES_DocFormate")
  void binaer() throws Exception {
    assertFault(
        sign(
            "<ns4:IncludeEContent>true</ns4:IncludeEContent>",
            base64Data("application/octet-stream", TEXT),
            false,
            500),
        "4110",
        "Technical",
        "ungültiges Dokumentformat (Binär)");
  }

  @ParameterizedTest(name = "{0} {1}")
  @CsvSource(
      delimiter = '|',
      value = {
        // KUC_1602_018: S/MIME
        "NEUTRAL|smime|4111",
        "KOCO|smime|4279",
        "RISE|smime|4110",
        "SECUNET|smime|4111",
        // KUC_1602_018 (SECUNET): S/MIME without MIME type, the signature type takes precedence
        // over the
        // format
        "SECUNET|smime-binary|4111",
        "RISE|smime-binary|4110",
        // KUC_1602_019: PAdES for text
        "NEUTRAL|pades-text|4111",
        "KOCO|pades-text|4111",
        "RISE|pades-text|4110",
        // KUC_1602_021: PAdES with IncludeEContent, without MIME type (RISE scenario)
        "KOCO|pades-econtent|4111",
        "RISE|pades-econtent|4110",
        // KUC_1602_022: PAdES with IncludeObjects
        "KOCO|pades-object|4111",
        "SECUNET|pades-object|4111",
        // KUC_1602_045: document-including countersignature (RISE and SECUNET check the format
        // first)
        "KOCO|counter|4111",
        "SECUNET|counter|4110",
        "RISE|counter|4110",
        // KUC_1602_020: unknown SignatureType
        "KOCO|unknown|4111",
        "RISE|unknown|4111"
      })
  @DisplayName(
      "TUC_KON_150 (->1) 4111/4110 je Herstellerprofil (VendorProfile checksQesFormatFirst, rejectsSmime)")
  void ungueltigeVariante(Vendor profile, String fall, String code) throws Exception {
    vendor.switchTo(profile);
    String pdf = base64Data("application/pdf-a", TEXT);
    Element fault =
        switch (fall) {
          case "smime" ->
              sign("<ns3:SignatureType>urn:ietf:rfc:5751</ns3:SignatureType>", pdf, false, 500);
          case "smime-binary" ->
              sign(
                  "<ns3:SignatureType>urn:ietf:rfc:5751</ns3:SignatureType>",
                  "<ns3:Base64Data>"
                      + Base64.getEncoder().encodeToString(TEXT)
                      + "</ns3:Base64Data>",
                  false,
                  500);
          case "pades-text" ->
              sign(PADES, base64Data("text/plain; charset=utf-8", TEXT), false, 500);
          case "pades-econtent" ->
              sign(
                  PADES + "<ns4:IncludeEContent>true</ns4:IncludeEContent>",
                  base64Data("", TEXT),
                  false,
                  500);
          case "pades-object" ->
              sign(
                  PADES
                      + "<ns4:IncludeObjects><ns3:IncludeObject WhichDocument=\"DokumentID\" "
                      + "createReference=\"true\" hasObjectTagsAndAttributesSet=\"false\"/></ns4:IncludeObjects>",
                  pdf,
                  false,
                  500);
          case "counter" ->
              sign(
                  cades(true)
                      + "<ns3:ReturnUpdatedSignature Type=\"http://ws.gematik.de/conn/sig/"
                      + "sigupdate/counter/documentincluding\"/>",
                  base64Data("application/octet-stream", Base64.getEncoder().encode(TEXT)),
                  false,
                  500);
          default ->
              sign("<ns3:SignatureType>urn:ietf:rfc:3075</ns3:SignatureType>", pdf, false, 500);
        };
    String text =
        switch (code) {
          case "4279" -> "SMIME-Funktionalität nicht unterstützt";
          case "4110" -> xpath(fault, "//*[local-name()='ErrorText']");
          default -> "Ungültiger Signaturtyp oder Signaturvariante";
        };
    assertFault(fault, code, "Technical", text);
    if (code.equals("4110")) {
      assertTrue(text.startsWith("ungültiges Dokumentformat ("), text);
    }
    assertEquals(0, revocation.takeRequests(), "abgewiesen vor der Signatur");
  }

  private static final String SIGNATURE_ARZT =
      "/*[local-name()='NFD_Document']/*[local-name()='SignatureArzt']";
  private static final String XADES = "<ns3:SignatureType>urn:ietf:rfc:3275</ns3:SignatureType>";
  private static final String NFDM_POLICY =
      "<sp:GenerateUnderSignaturePolicy "
          + "xmlns:sp=\"urn:oasis:names:tc:dss-x:1.0:profiles:SignaturePolicy:schema#\"><sp:SignaturePolicyIdentifier>"
          + "urn:gematik:fa:sak:nfdm:r1:v1</sp:SignaturePolicyIdentifier></sp:GenerateUnderSignaturePolicy>";

  /** SignaturePlacement like PSSIM createNfdRequest (KUC_1602_044). */
  private static String placement(boolean enveloped, String xPath) {
    return "<ns3:SignaturePlacement WhichDocument=\"DokumentID\" CreateEnvelopedSignature=\""
        + enveloped
        + "\">"
        + "<ns3:XPathFirstChildOf>"
        + xPath
        + "</ns3:XPathFirstChildOf></ns3:SignaturePlacement>";
  }

  /** OptionalInputs of an NFD signing request (PSSIM createNfdRequest). */
  private static final String NFDM = XADES + placement(false, SIGNATURE_ARZT) + NFDM_POLICY;

  private static byte[] nfd() throws Exception {
    return Files.readAllBytes(Path.of("support/signatures/xades/NFDM_Beispiel_1.4.xml"));
  }

  private static String base64Xml(byte[] xml) {
    return "<ns2:Base64XML>" + Base64.getEncoder().encodeToString(xml) + "</ns2:Base64XML>";
  }

  /**
   * SignDocument with the HBA, the document with {@code RefURI} (KUC_1602_044: „#Notfalldaten“).
   */
  private Element signXml(
      String optionalInputs, byte[] xml, String refUri, boolean includeRevocationInfo, int status)
      throws Exception {
    String body =
        signDocument(hba(), jobNumber(), optionalInputs, base64Xml(xml), includeRevocationInfo);
    if (refUri != null) {
      body =
          body.replace(
              "<ns4:Document ID=\"DokumentID\" ",
              "<ns4:Document ID=\"DokumentID\" RefURI=\"" + refUri + "\" ");
    }
    return post(body, status);
  }

  @Test
  @DisplayName(
      "TIP1-A_5538, TIP1-A_4655-04 XAdES unter der Richtlinie NFDM mit dem HBA (KUC_1602_044, KUC_1609_001): "
          + "DocumentWithSignature mit ID, RefURI, ShortText und Base64XML, SignaturePtr mit WhichDocument und XPath, "
          + "Signatur in SignatureArzt gültig mit C.HP.QES, IncludeRevocationInfo → OCSP in RevocationValues")
  void nfdm() throws Exception {
    Element response = signXml(NFDM, nfd(), "#Notfalldaten", true, 200);
    XsdValidator.validate("conn/SignatureService_V7_5_6.xsd", serialize(response));
    assertEquals("OK", xpath(response, "//*[local-name()='Status']/*[local-name()='Result']"));
    String document = "//*[local-name()='DocumentWithSignature']";
    assertEquals("DokumentID", xpath(response, document + "/@ID"));
    assertEquals("#Notfalldaten", xpath(response, document + "/@RefURI"));
    assertEquals("shortText", xpath(response, document + "/@ShortText"));
    assertEquals("DokumentID", xpath(response, "//*[local-name()='SignaturePtr']/@WhichDocument"));
    assertEquals(
        SIGNATURE_ARZT + "/*[local-name()='Signature'][1]",
        xpath(response, "//*[local-name()='SignaturePtr']/@XPath"));
    assertEquals("0", xpath(response, "count(//*[local-name()='Base64Signature'])"));
    byte[] signed =
        Base64.getDecoder().decode(xpath(response, document + "/*[local-name()='Base64XML']"));

    XadesSignatures xades = new XadesSignatures(java.time.Clock.systemUTC());
    List<de.gematik.liana.kern.signature.SignatureVerifier.Signer> signers = xades.verify(signed);
    assertEquals(1, signers.size());
    assertEquals(List.of(), signers.get(0).problems());
    assertTrue(signers.get(0).qualified(), "C.HP.QES mit QCStatement");
    xades.validate(signed, "urn:gematik:fa:sak:nfdm:r1:v1");
    assertTrue(new String(signed, StandardCharsets.ISO_8859_1).contains("EncapsulatedOCSPValue"));
    assertEquals(1, revocation.takeRequests());
  }

  @ParameterizedTest(name = "{0}")
  @CsvSource(
      delimiter = '|',
      value = {
        "KUC_1602_001 enveloped ohne Richtlinie|enveloped",
        "KUC_1602_002 enveloping ohne Richtlinie|enveloping",
        "KUC_1602_016 internally detached ohne Richtlinie|detached",
        "KUC_1605_008 Default XML → XAdES enveloped|default",
        "unbekannte Richtlinie|unknown-policy",
        "NFDM mit CreateEnvelopedSignature=true|nfdm-enveloped",
        "NFDM ohne RefURI|nfdm-no-refuri",
        "XAdES für Text|text"
      })
  @DisplayName(
      "TIP1-A_5538, TAB_KON_778, TAB_KON_065: QES-XAdES nur unter NFDM als internally detached, sonst 4111 "
          + "vor der PIN-Eingabe")
  void xadesUngueltig(String name, String fall) throws Exception {
    byte[] nfd = nfd();
    Element fault =
        switch (fall) {
          case "enveloped" -> signXml(XADES + placement(true, "/*"), nfd, null, false, 500);
          case "enveloping" ->
              signXml(
                  XADES
                      + "<ns4:IncludeObjects><ns3:IncludeObject WhichDocument=\"DokumentID\" "
                      + "createReference=\"true\" hasObjectTagsAndAttributesSet=\"false\"/></ns4:IncludeObjects>",
                  nfd,
                  null,
                  false,
                  500);
          case "detached" ->
              signXml(XADES + placement(false, SIGNATURE_ARZT), nfd, "#Notfalldaten", false, 500);
          case "default" -> signXml("", nfd, null, false, 500);
          case "unknown-policy" ->
              signXml(
                  XADES
                      + placement(false, SIGNATURE_ARZT)
                      + NFDM_POLICY.replace("nfdm", "unbekannt"),
                  nfd,
                  "#Notfalldaten",
                  false,
                  500);
          case "nfdm-enveloped" ->
              signXml(
                  XADES + placement(true, SIGNATURE_ARZT) + NFDM_POLICY,
                  nfd,
                  "#Notfalldaten",
                  false,
                  500);
          case "nfdm-no-refuri" -> signXml(NFDM, nfd, null, false, 500);
          default -> sign(NFDM, base64Data("text/plain; charset=utf-8", TEXT), false, 500);
        };
    assertFault(fault, "4111", "Technical", "Ungültiger Signaturtyp oder Signaturvariante");
    assertEquals(0, revocation.takeRequests(), "abgewiesen vor der Signatur");
  }

  @Test
  @DisplayName(
      "TIP1-A_4527-04 TUC_KON_080 (A): NFD nicht wohlgeformt → 4022, nicht valide gegen NFD_Document_v1_4.xsd "
          + "→ 4023")
  void nfdmNichtValide() throws Exception {
    assertFault(
        signXml(NFDM, PDFA, "#Notfalldaten", false, 500),
        "4022",
        "Security",
        "XML-Dokument nicht wohlgeformt");
    byte[] invalid =
        new String(nfd(), StandardCharsets.ISO_8859_1)
            .replace("<Geschlecht>W</Geschlecht>", "<Unbekannt>W</Unbekannt>")
            .getBytes(StandardCharsets.ISO_8859_1);
    assertFault(
        signXml(NFDM, invalid, "#Notfalldaten", false, 500),
        "4023",
        "Security",
        "XML-Dokument nicht valide in Bezug auf XML-Schema");
    assertEquals(0, revocation.takeRequests(), "abgewiesen vor der Signatur");
  }
}

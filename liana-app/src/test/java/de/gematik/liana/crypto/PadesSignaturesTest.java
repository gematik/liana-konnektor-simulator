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
package de.gematik.liana.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.kern.error.ConnectorError;
import de.gematik.liana.kern.event.SystemLog;
import de.gematik.liana.kern.signature.PdfSignatures;
import de.gematik.liana.kern.signature.SignatureVerifier.Signer;
import de.gematik.liana.kern.vendor.PeerDeviations;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.OptionalInt;
import java.util.function.UnaryOperator;
import java.util.stream.Stream;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * PAdES with PDFBox (decision-020, LIANA-112.08) with Konnektor-QES files under {@code
 * support/signatures/pades} (originals) and {@code support/vendor/signatures/pades} (vendor
 * signatures): PDF/A identification (TUC_KON_080 (B)), vendor PAdES (KUC_1607_046–060, 229–243),
 * signing as incremental update.
 */
class PadesSignaturesTest {

  static final Path PADES = Path.of("support/signatures/pades");
  static final Path SIGNED = Path.of("support/vendor/signatures/pades");
  private static final Instant NOW = Instant.parse("2026-10-19T12:00:00Z");
  private static final PadesSignatures PDF = new PadesSignatures(Clock.fixed(NOW, ZoneOffset.UTC));
  private static CmsVerifier verifier;

  @BeforeAll
  static void load() {
    if (Security.getProvider(CryptoProviders.BC) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
    verifier =
        new CmsVerifier(
            TrustSpace.load(
                ScenarioSignerCheckTest.TSL, List.of(), Path.of("support/pki/tsl/BNetzA-VL.xml")),
            new PeerDeviations(false, new SystemLog(Clock.systemUTC(), 100)),
            Clock.systemUTC());
  }

  private static byte[] read(String file) throws Exception {
    return Files.readAllBytes(PADES.resolve(file));
  }

  private static byte[] readSigned(String file) throws Exception {
    return Files.readAllBytes(SIGNED.resolve(file));
  }

  @ParameterizedTest
  @CsvSource({
    "1149065825_A1A.pdf, 1",
    "1149065825_A2A.pdf, 2",
    "pdf45k_PDFA-1B.pdf, 1",
    "1149065825_A3A.pdf, 3"
  })
  @DisplayName(
      "TUC_KON_080 (B): pdfaid:part aus den XMP-Metadaten, auch PDF/A-3 (A_18780 lehnt der Kern ab)")
  void pdfaPart(String file, int part) throws Exception {
    assertEquals(OptionalInt.of(part), PDF.pdfaPart(read(file)));
  }

  @Test
  @DisplayName("TUC_KON_080 (B): PDF 1.7 ohne PDF/A-Kennung und kein PDF → keine Kennung")
  void noPdfaPart() throws Exception {
    assertEquals(OptionalInt.empty(), PDF.pdfaPart(read("pdf35k_PDF17.pdf")));
    assertEquals(OptionalInt.empty(), PDF.pdfaPart("<xml/>".getBytes()));
  }

  static Stream<String> interop() {
    return Stream.of("koco", "rise", "secu")
        .flatMap(
            v ->
                Stream.of(
                    "IOP-ECC/sig.1149065825_A1A." + v + ".ecc.pdf",
                        "IOP-ECC/sig.1149065825_A2A." + v + ".ecc.pdf",
                    "sig.rsa." + v + ".1149065825_A1A.pdf",
                        "sig.rsa." + v + ".1149065825_A2A.pdf"));
  }

  /** The signers of all signature fields, without signingTime with {@code /M}. */
  private static List<Signer> signers(byte[] pdf) {
    List<Signer> signers = new ArrayList<>();
    for (PdfSignatures.Embedded embedded : PDF.signatures(pdf)) {
      verifier.pdf(embedded.cms(), embedded.signedContent()).stream()
          .map(s -> s.orSigningTime(embedded.signingTime()))
          .forEach(signers::add);
    }
    return signers;
  }

  @Tag("vendor-data")
  @ParameterizedTest
  @MethodSource("interop")
  @DisplayName(
      "TIP1-A_4654-05, TIP1-A_4672-06, [PAdES-3] 4.6: PAdES der Hersteller (ECC und RSA), jede Signatur und "
          + "ihr Zertifikat gültig")
  void interopValid(String file) throws Exception {
    List<Signer> signers = signers(readSigned(file));
    assertFalse(signers.isEmpty());
    List<String> problems = new ArrayList<>();
    for (Signer signer : signers) {
      signer.problems().forEach(p -> problems.add(p.error().code() + " " + p.detail()));
      verifier
          .checkCertificate(
              signer.certificate(), signer.qualified(), signer.signingTime().orElseThrow())
          .ifPresent(p -> problems.add(p.error().code() + " " + p.detail()));
    }
    assertEquals(List.of(), problems);
  }

  @Test
  @Tag("vendor-data")
  @DisplayName("[PAdES-3] 4.6: ein Byte im signierten Bereich verändert → 4115")
  void manipulated() throws Exception {
    byte[] pdf = readSigned("IOP-ECC/sig.1149065825_A2A.koco.ecc.pdf");
    // in the first part of the ByteRange, before the signature field
    pdf[pdf.length / 4] ^= 0x01;
    List<Signer> signers = signers(pdf);
    assertEquals(
        ConnectorError.DOCUMENT_SIGNATURE_INVALID, signers.get(0).problems().get(0).error());
  }

  /** {@code /Contents} is padded with zero bytes: only the first ASN.1 object. */
  private static ContentInfo contentInfo(byte[] der) throws Exception {
    try (ASN1InputStream in = new ASN1InputStream(der)) {
      return ContentInfo.getInstance(in.readObject());
    }
  }

  /** TEST-ONLY: software key instead of a card, self-signed. */
  record Key(byte[] certificate, UnaryOperator<byte[]> signHash) {
    static Key generate() throws Exception {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", CryptoProviders.BC);
      generator.initialize(new ECGenParameterSpec("brainpoolP256r1"));
      KeyPair pair = generator.generateKeyPair();
      X500Name name = new X500Name("CN=TEST-ONLY PAdES");
      X509CertificateHolder certificate =
          new JcaX509v3CertificateBuilder(
                  name,
                  BigInteger.ONE,
                  Date.from(NOW.minus(Duration.ofDays(1))),
                  Date.from(NOW.plus(Duration.ofDays(1))),
                  name,
                  pair.getPublic())
              .build(
                  new JcaContentSignerBuilder("SHA256withECDSA")
                      .setProvider(CryptoProviders.BC)
                      .build(pair.getPrivate()));
      return new Key(
          certificate.getEncoded(),
          hash -> {
            try {
              Signature ecdsa = Signature.getInstance("NONEwithECDSA", CryptoProviders.BC);
              ecdsa.initSign(pair.getPrivate());
              ecdsa.update(hash);
              return ecdsa.sign();
            } catch (Exception e) {
              throw new IllegalStateException(e);
            }
          });
    }
  }

  @Test
  @DisplayName(
      "TAB_KON_779-01, [PDF/A-2] 7.5.6: Incremental Update, das Original bleibt unverändert vorn, "
          + "ETSI.CAdES.detached über das ganze Dokument außer /Contents, /M und /Reason, signing-certificate-v2 "
          + "([PAdES-3] 4.4.3), ohne signingTime ([PAdES Baseline Profile] 6.2.1), PDF/A-Kennung erhalten")
  void sign() throws Exception {
    byte[] original = read("1149065825_A2A.pdf");
    Key key = Key.generate();
    byte[] signed =
        PDF.sign(
            new PdfSignatures.Request(original, key.certificate(), "shortText"), key.signHash());

    assertArrayEquals(original, Arrays.copyOf(signed, original.length), "Incremental Update");
    assertEquals(OptionalInt.of(2), PDF.pdfaPart(signed));
    try (PDDocument pdf = Loader.loadPDF(signed)) {
      PDSignature signature = pdf.getLastSignatureDictionary();
      assertEquals("ETSI.CAdES.detached", signature.getSubFilter());
      assertEquals("Adobe.PPKLite", signature.getFilter());
      assertEquals("shortText", signature.getReason());
      assertEquals(NOW, signature.getSignDate().toInstant());
      int[] range = signature.getByteRange();
      assertEquals(0, range[0]);
      assertEquals(signed.length, range[2] + range[3], "ByteRange bis zum Dateiende");
    }
    List<PdfSignatures.Embedded> embedded = PDF.signatures(signed);
    assertEquals(1, embedded.size());
    CMSSignedData cms =
        new CMSSignedData(
            new CMSProcessableByteArray(embedded.get(0).signedContent()),
            contentInfo(embedded.get(0).cms()));
    SignerInformation signer = cms.getSignerInfos().getSigners().iterator().next();
    assertNull(signer.getSignedAttributes().get(CMSAttributes.signingTime));
    assertTrue(
        signer.getSignedAttributes().get(PKCSObjectIdentifiers.id_aa_signingCertificateV2) != null);
    assertEquals(
        List.of(),
        verifier.pdf(embedded.get(0).cms(), embedded.get(0).signedContent()).get(0).problems());
  }
}

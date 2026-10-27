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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.kern.error.ConnectorError;
import de.gematik.liana.kern.event.SystemLog;
import de.gematik.liana.kern.signature.SignatureVerifier.Problem;
import de.gematik.liana.kern.signature.SignatureVerifier.Signer;
import de.gematik.liana.kern.vendor.PeerDeviations;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * CAdES files of Konnektor-QES (KUC_1607, KUC_1609, KUC_1604_008): vendor signatures under {@code
 * support/vendor/signatures/cades}, originals under {@code support/signatures/cades}.
 */
@Tag("vendor-data")
class CmsVerifierTest {

  static final Path CADES = Path.of("support/signatures/cades");
  static final Path SIGNED = Path.of("support/vendor/signatures/cades");
  private static final Path VL = Path.of("support/pki/tsl/BNetzA-VL.xml");
  private static final PeerDeviations DEVIATIONS =
      new PeerDeviations(false, new SystemLog(Clock.systemUTC(), 100));
  private static TrustSpace trustSpace;
  private static CmsVerifier verifier;

  @BeforeAll
  static void load() {
    if (Security.getProvider(CryptoProviders.BC) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
    trustSpace = TrustSpace.load(ScenarioSignerCheckTest.TSL, List.of(), VL);
    verifier = new CmsVerifier(trustSpace, DEVIATIONS, Clock.systemUTC());
  }

  /** Signature and, if detached, the original. */
  record Case(String signature, String document) {
    @Override
    public String toString() {
      return signature;
    }
  }

  static Stream<Case> interop() {
    return Stream.of(
        // KUC_1607_001/002/011 enveloping, 003/004/012 detached (RSA, qCA24)
        new Case("MedicationRequest_42.xml.koco.2.3.20.CAdES.enveloping.p7s", null),
        new Case("MedicationRequest_42.xml.secu.3.4.0.CAdES.enveloping.p7s", null),
        new Case("MedicationRequest_42.xml.rise.3.5.2.CAdES.enveloping.p7s", null),
        new Case(
            "MedicationRequest_42.secu.3.4.0.CAdES.detached.xml.p7s", "MedicationRequest_42.xml"),
        new Case(
            "MedicationRequest_42.koco.2.3.20.CAdES.detached.xml.p7s", "MedicationRequest_42.xml"),
        new Case(
            "MedicationRequest_42.rise.2.0.12.CAdES.detached.xml.p7s", "MedicationRequest_42.xml"),
        // 005/006/015 countersignature, 016/017/018 parallel (HBA and SM-B)
        new Case("MedicationRequest_42.xml.koco.4.2.1.CAdES.enveloping.gegen.p7s", null),
        new Case("MedicationRequest_42.secu.4.10.1.CAdES.enveloping.gegen.p7s", null),
        new Case("MedicationRequest_42.xml.rise.3.5.2.CAdES.enveloping.gegen.p7s", null),
        new Case("MedicationRequest_42.xml.koco.4.2.1.CAdES.enveloping.parallel.p7s", null),
        new Case("MedicationRequest_42.secu.4.10.1.CAdES.enveloping.parallel.p7s", null),
        new Case("MedicationRequest_42.xml.rise.3.5.2.CAdES.enveloping.parallel.p7s", null),
        // 019/020/021 ZIP nonQES (SM-B)
        new Case("MedicationRequest_42.zip.koco.4.2.1.CAdES.enveloping.p7s", null),
        new Case("MedicationRequest_42.zip.rise.3.5.2.CAdES.enveloping.p7s", null),
        new Case("MedicationRequest_42.zip.secu.4.10.1.CAdES.enveloping.p7s", null),
        // 031/032/033 eRezept (BER)
        new Case("erezept.xml.koco.4.2.17.CMS.enveloping.p7s", null),
        new Case("erezept.xml.secunet.5.0.5.CMS.enveloping.p7s", null),
        new Case("erezept.xml.rise.4.2.8.CMS.enveloping.p7s", null),
        // KUC_1607_200–220 ECC (qCA6, SMCB-CA51)
        new Case("IOP-ECC/Textdokument_standard.txt.koco.ecc.env.p7s", null),
        new Case("IOP-ECC/Textdokument_standard.txt.secu.ecc.env.p7s", null),
        new Case("IOP-ECC/Textdokument_standard.txt.rise.ecc.env.p7s", null),
        new Case(
            "IOP-ECC/Textdokument_standard.txt.koco.ecc.det.p7s",
            "IOP-ECC/Textdokument_standard.txt"),
        new Case(
            "IOP-ECC/Textdokument_standard.txt.secu.ecc.det.p7s",
            "IOP-ECC/Textdokument_standard.txt"),
        new Case(
            "IOP-ECC/Textdokument_standard.txt.rise.ecc.det.p7s",
            "IOP-ECC/Textdokument_standard.txt"),
        new Case("IOP-ECC/Textdokument_standard.txt.koco.ecc.env.gegen.p7s", null),
        new Case("IOP-ECC/Textdokument_standard.txt.secu.ecc.env.gegen.p7s", null),
        new Case("IOP-ECC/Textdokument_standard.txt.rise.ecc.env.gegen.p7s", null),
        new Case("IOP-ECC/Textdokument_standard.txt.koco.ecc.env.parallel.p7s", null),
        new Case("IOP-ECC/Textdokument_standard.txt.secu.ecc.env.parallel.p7s", null),
        new Case("IOP-ECC/Textdokument_standard.txt.rise.ecc.env.parallel.p7s", null),
        new Case("IOP-ECC/Textdokument_standard.txt.zip.koco.env.p7s", null),
        new Case("IOP-ECC/Textdokument_standard.txt.zip.secu.env.p7s", null),
        new Case("IOP-ECC/Textdokument_standard.txt.zip.rise.env.p7s", null),
        // KUC_1609_013–024 enveloping, 028–036 detached (ECC)
        new Case("testwoche/ab.koco.ecc.xml.sig", null),
        new Case("testwoche/ab.secu.ecc.xml.sig", null),
        new Case("testwoche/ab.rise.ecc.xml.sig", null),
        new Case("testwoche/eau.koco.ecc.sig", null),
        new Case("testwoche/eau.secu.ecc.env.sig", null),
        new Case("testwoche/eau.rise.ecc.sig", null),
        new Case("testwoche/eRezept.koco.ecc.sig", null),
        new Case("testwoche/eRezept.secu.ecc.env.sig", null),
        new Case("testwoche/eRezept.rise.ecc.sig", null),
        new Case("testwoche/json.koco.ecc.sig", null),
        new Case("testwoche/json.secu.ecc.sig", null),
        new Case("testwoche/json.rise.ecc.sig", null),
        new Case("testwoche/xml.koco.ecc.det.sig", "testwoche/eRezept_real.xml"),
        new Case("testwoche/xml.secu.ecc.det.sig", "testwoche/eRezept_real.xml"),
        new Case("testwoche/xml.rise.ecc.det.sig", "testwoche/eRezept_real.xml"),
        new Case(
            "testwoche/json.koco.ecc.det.sig", "testwoche/Medication-SumatripanMedication.json"),
        new Case(
            "testwoche/json.secu.ecc.det.sig", "testwoche/Medication-SumatripanMedication.json"),
        new Case(
            "testwoche/json.rise.ecc.det.sig", "testwoche/Medication-SumatripanMedication.json"),
        new Case("testwoche/text.koco.ecc.det.sig", "testwoche/Textdokument_standard.txt"),
        new Case("testwoche/text.secu.ecc.det.sig", "testwoche/Textdokument_standard.txt"),
        new Case("testwoche/text.rise.ecc.det.sig", "testwoche/Textdokument_standard.txt"));
  }

  private static List<Signer> verify(Case c) throws Exception {
    return verifier.cms(
        Files.readAllBytes(SIGNED.resolve(c.signature())),
        c.document() == null ? null : Files.readAllBytes(CADES.resolve(c.document())));
  }

  @ParameterizedTest
  @MethodSource("interop")
  @DisplayName(
      "TIP1-A_4654-05, TIP1-A_4672-06: CAdES der Hersteller, jede Signatur und ihr Zertifikat gültig")
  void interopValid(Case c) throws Exception {
    List<Signer> signers = verify(c);
    assertFalse(signers.isEmpty());
    List<String> problems = new ArrayList<>();
    for (Signer signer : signers) {
      signer.problems().forEach(p -> problems.add(p.error().code() + " " + p.detail()));
      Instant baseTime = signer.signingTime().orElseThrow();
      verifier
          .checkCertificate(signer.certificate(), signer.qualified(), baseTime)
          .ifPresent(p -> problems.add(p.error().code() + " " + p.detail()));
    }
    assertEquals(List.of(), problems);
  }

  @Test
  @DisplayName(
      "TUC_KON_161 Parallel- und Gegensignaturen: HBA (QES) und SM-B (nonQES) je eine Signatur")
  void counterAndParallel() throws Exception {
    List<Signer> gegen =
        verify(new Case("IOP-ECC/Textdokument_standard.txt.koco.ecc.env.gegen.p7s", null));
    assertEquals(2, gegen.size());
    assertEquals(1, gegen.stream().filter(Signer::counterSignature).count());
    List<Signer> parallel =
        verify(new Case("IOP-ECC/Textdokument_standard.txt.koco.ecc.env.parallel.p7s", null));
    assertEquals(2, parallel.size());
    assertTrue(parallel.stream().noneMatch(Signer::counterSignature));
    assertEquals(1, parallel.stream().filter(Signer::qualified).count());
  }

  @Test
  @DisplayName("KUC_1604_008: manipulierte CAdES (CAdES_1_mod.bin) → 4115")
  void manipulated() throws Exception {
    List<Signer> signers = verify(new Case("CAdES_1_mod.bin", null));
    assertEquals(
        List.of(ConnectorError.DOCUMENT_SIGNATURE_INVALID),
        signers.stream().flatMap(s -> s.problems().stream()).map(Problem::error).toList());
  }

  @Test
  @DisplayName(
      "TUC_PKI_002/030: zum Prüfzeitpunkt nach Ablauf ist das Signaturzertifikat ungültig (1021)")
  void expiredAtVerificationTime() throws Exception {
    Signer signer =
        verify(new Case("MedicationRequest_42.xml.koco.2.3.20.CAdES.enveloping.p7s", null)).get(0);
    assertTrue(signer.qualified());
    Optional<Problem> problem =
        verifier.checkCertificate(
            signer.certificate(), true, Instant.parse("2040-01-01T00:00:00Z"));
    assertEquals(ConnectorError.CERTIFICATE_NOT_VALID_TIME, problem.orElseThrow().error());
  }

  @Test
  @DisplayName("TUC_PKI_030: ohne BNetzA-VL hat die QES keinen Aussteller (1027)")
  void qesWithoutVl() throws Exception {
    CmsVerifier withoutVl =
        new CmsVerifier(
            TrustSpace.load(ScenarioSignerCheckTest.TSL, List.of()), DEVIATIONS, Clock.systemUTC());
    Signer signer =
        verify(new Case("IOP-ECC/Textdokument_standard.txt.koco.ecc.env.p7s", null)).get(0);
    assertEquals(
        ConnectorError.CA_CERT_MISSING,
        withoutVl
            .checkCertificate(signer.certificate(), true, signer.signingTime().orElseThrow())
            .orElseThrow()
            .error());
  }

  @Test
  @DisplayName(
      "DETACHED_CONTENT_LF: Original mit LF, signiert mit CRLF – VALID mit Deviation, strict 4115")
  void detachedLf() throws Exception {
    Case c =
        new Case(
            "IOP-ECC/Textdokument_standard.txt.koco.ecc.det.p7s",
            "IOP-ECC/Textdokument_standard.txt");
    assertEquals(List.of(), verify(c).get(0).problems());
    PeerDeviations strict = new PeerDeviations(true, new SystemLog(Clock.systemUTC(), 100));
    List<Signer> signers =
        new CmsVerifier(trustSpace, strict, Clock.systemUTC())
            .cms(
                Files.readAllBytes(SIGNED.resolve(c.signature())),
                Files.readAllBytes(CADES.resolve(c.document())));
    assertEquals(
        ConnectorError.DOCUMENT_SIGNATURE_INVALID, signers.get(0).problems().get(0).error());
  }
}

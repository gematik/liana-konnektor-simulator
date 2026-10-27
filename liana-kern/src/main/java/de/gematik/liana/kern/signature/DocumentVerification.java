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
package de.gematik.liana.kern.signature;

import de.gematik.liana.kern.access.Context;
import de.gematik.liana.kern.access.Infomodel;
import de.gematik.liana.kern.error.ConnectorError;
import de.gematik.liana.kern.error.ConnectorException;
import de.gematik.liana.kern.management.ManagementSettings;
import de.gematik.liana.kern.signature.SignatureVerifier.Problem;
import de.gematik.liana.kern.signature.SignatureVerifier.Signer;
import de.gematik.liana.kern.vendor.VendorProfile;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

/**
 * VerifyDocument (TIP1-A_5034-06) per TAB_KON_760 for CMS (CAdES enveloping and detached, also
 * parallel and countersignatures, LIANA-112.07): each signature per TUC_KON_151 (TIP1-A_4672-06) if
 * its signature certificate carries a QCStatement id-etsi-qcs-QcCompliance, otherwise per
 * TUC_KON_161 (TIP1-A_4654-05).
 *
 * <p>Verification time per signature per TIP1-A_5545 and TIP1-A_5540-01: UseVerificationTime,
 * otherwise signingTime, otherwise the system time. The overall result follows
 * TAB_KON_754/TAB_KON_593: VALID if all signatures are valid, otherwise INVALID with the findings
 * as a warning in the status. LIANA queries the revocation status only for IncludeRevocationInfo;
 * with the simulator it is always good (decision-021).
 *
 * <p>PAdES (LIANA-112.08): a document {@code application/pdf-a} without SignatureObject or with
 * Type PDF is checked by TUC_KON_080 (B) for the PDF/A identification (4024), then every signature
 * in the document like CMS via {@code /ByteRange}; without signingTime the field {@code /M}
 * provides the signing time. IncludeRevocationInfo leaves PAdES without UpdatedSignature
 * (TUC_KON_159: not embedded for PAdES).
 *
 * <p>XAdES (LIANA-112.09): an XML document ({@code Base64XML}) without Base64Signature is checked
 * by TUC_KON_080 (A) for well-formedness (4022, profile RISE 4111) and, if a signature names the
 * policy NFDM, against its schema (4023, TIP1-A_5538), then every {@code ds:Signature} per
 * TUC_KON_162 (TIP1-A_5505); without signature 4253. {@code SigningTime} is the embedded signing
 * time. IncludeRevocationInfo leaves XAdES without UpdatedSignature.
 *
 * <p>S/MIME (LIANA-112.10): a message {@code application/pkcs7-mime} as document or as
 * Base64Signature with Type S/MIME is checked by TUC_KON_080 (D) (4024 MIME, also without
 * Content-Type), then the SignedData per TUC_KON_161 or TUC_KON_151 like CAdES enveloping; without
 * UpdatedSignature. Profile KOCO reports S/MIME as 4279 (TAB_KON_761, KUC_1603_001/010).
 *
 * <p>LIANA does not implement detached XML signatures (Base64Signature with Type XML), {@code
 * multipart/signed} and checking the embedded document of a CMS signature per TUC_KON_080.
 */
public final class DocumentVerification {

  /** dss:Base64Signature/@Type for CMS (TAB_KON_759). */
  public static final String CMS = "urn:ietf:rfc:5652";

  /** dss:Base64Signature/@Type for S/MIME (TAB_KON_759, KANN). */
  public static final String SMIME = "urn:ietf:rfc:5751";

  /** dss:Base64Signature/@Type for PDF (TAB_KON_759). */
  public static final String PDF = "http://uri.etsi.org/02778/3";

  private static final String MIME_SMIME = "application/pkcs7-mime";
  private static final String MIME_PDF_A = "application/pdf-a";

  /**
   * SIG:Document: Base64Data with MimeType or Base64XML; {@code content} empty if the value is
   * empty.
   */
  public record Document(byte[] content, String mimeType, boolean xml) {}

  /** dss:SignatureObject/dss:Base64Signature. */
  public record Signature(byte[] value, String type) {}

  /**
   * Call parameters of VerifyDocument (TAB_KON_759), as far as LIANA evaluates them.
   *
   * @param document {@code null} without SIG:Document
   * @param signature {@code null} without dss:SignatureObject
   * @param verificationTime SIG:UseVerificationTime/dss:SpecificTime
   *     (Benutzerdefinierter_Zeitpunkt)
   */
  public record Request(
      Context context,
      Document document,
      Signature signature,
      boolean includeRevocationInfo,
      Optional<Instant> verificationTime) {}

  public enum HighLevelResult {
    VALID,
    INCONCLUSIVE,
    INVALID
  }

  public enum TimestampType {
    SIGNATURE_EMBEDDED_TIMESTAMP,
    USER_DEFINED_TIMESTAMP,
    SYSTEM_TIMESTAMP
  }

  /** Result of one signature (VerificationReport/IndividualReport). */
  public record SignatureResult(
      byte[] signatureValue,
      boolean counterSignature,
      boolean qualified,
      Instant verificationTime,
      List<Problem> problems) {
    public boolean valid() {
      return problems.isEmpty();
    }
  }

  /**
   * @param updatedSignature the signature with embedded OCSP responses (dss:UpdatedSignature),
   *     {@code null} without IncludeRevocationInfo or offline
   */
  public record Result(
      HighLevelResult highLevelResult,
      TimestampType timestampType,
      Instant timestamp,
      List<SignatureResult> signatures,
      byte[] updatedSignature) {

    /** The findings of all invalid signatures, for CONN:Status (Result Warning). */
    public List<Problem> problems() {
      return signatures.stream().flatMap(s -> s.problems().stream()).toList();
    }
  }

  private final Infomodel infomodel;
  private final SignatureVerifier verifier;
  private final PdfSignatures pdfSignatures;
  private final XmlSignatures xml;
  private final RevocationSource revocation;
  private final ManagementSettings settings;
  private final VendorProfile vendor;
  private final Clock clock;

  public DocumentVerification(
      Infomodel infomodel,
      SignatureVerifier verifier,
      PdfSignatures pdf,
      XmlSignatures xml,
      RevocationSource revocation,
      ManagementSettings settings,
      VendorProfile vendor,
      Clock clock) {
    this.infomodel = infomodel;
    this.pdfSignatures = pdf;
    this.xml = xml;
    this.vendor = vendor;
    this.verifier = verifier;
    this.revocation = revocation;
    this.settings = settings;
    this.clock = clock;
  }

  /** TAB_KON_760 steps 1–5. */
  public Result verify(Request request) {
    checkArguments(request);
    // step 2: TUC_KON_000 with needCardSession=false
    infomodel.checkAccess(request.context(), false);
    Instant now = clock.instant();
    if (pades(request)) {
      return result(request, padesSigners(request), now, null);
    }
    Optional<byte[]> smime = smimeMessage(request);
    if (smime.isPresent()) {
      return result(request, verifier.cms(Smime.signedData(smime.get()), null), now, null);
    }
    if (request.signature() == null && request.document().xml()) {
      return result(request, xadesSigners(request.document().content()), now, null);
    }
    byte[] signature = cmsSignature(request);
    byte[] detached =
        request.signature() == null || request.document() == null
            ? null
            : request.document().content();
    List<Signer> signers = verifier.cms(signature, detached);
    return result(
        request,
        signers,
        now,
        request.includeRevocationInfo() ? withRevocationInfo(signature, signers) : null);
  }

  /** TAB_KON_760 steps 3–5 for the signatures of the call. */
  private Result result(
      Request request, List<Signer> signers, Instant now, byte[] updatedSignature) {
    List<SignatureResult> results = new ArrayList<>();
    for (Signer signer : signers) {
      List<Problem> problems = new ArrayList<>(signer.problems());
      // TIP1-A_5545, TIP1-A_5540-01: assumed signing time
      Instant baseTime = request.verificationTime().or(signer::signingTime).orElse(now);
      if (signer.certificate() != null) {
        verifier
            .checkCertificate(signer.certificate(), signer.qualified(), baseTime)
            .ifPresent(problems::add);
      }
      results.add(
          new SignatureResult(
              signer.signatureValue(),
              signer.counterSignature(),
              signer.qualified(),
              baseTime,
              List.copyOf(problems)));
    }
    HighLevelResult highLevel =
        results.stream().allMatch(SignatureResult::valid)
            ? HighLevelResult.VALID
            : HighLevelResult.INVALID;
    TimestampType timestampType;
    Instant timestamp;
    Optional<Instant> embedded =
        signers.stream().flatMap(s -> s.signingTime().stream()).max(Comparator.naturalOrder());
    if (request.verificationTime().isPresent()) {
      timestampType = TimestampType.USER_DEFINED_TIMESTAMP;
      timestamp = request.verificationTime().get();
    } else if (embedded.isPresent()) {
      // TAB_KON_759: with several signatures the time of the most recent one
      timestampType = TimestampType.SIGNATURE_EMBEDDED_TIMESTAMP;
      timestamp = embedded.get();
    } else {
      timestampType = TimestampType.SYSTEM_TIMESTAMP;
      timestamp = now;
    }
    return new Result(highLevel, timestampType, timestamp, List.copyOf(results), updatedSignature);
  }

  /** PAdES: Type PDF or a PDF/A document without SignatureObject (TAB_KON_759, TAB_KON_583). */
  private static boolean pades(Request request) {
    if (request.signature() != null) {
      return PDF.equals(request.signature().type());
    }
    return !request.document().xml() && MIME_PDF_A.equals(request.document().mimeType());
  }

  /**
   * TUC_KON_080 (B), then per signature field the SignerInfos via {@code /ByteRange}; without
   * signature field 4253.
   */
  private List<Signer> padesSigners(Request request) {
    byte[] document =
        request.document() != null ? request.document().content() : request.signature().value();
    DocumentFormat.validatePdfA(document, pdfSignatures);
    List<PdfSignatures.Embedded> embedded = pdfSignatures.signatures(document);
    if (embedded.isEmpty()) {
      throw ConnectorError.NO_SIGNATURE.exception("PDF/A ohne Signaturfeld");
    }
    List<Signer> signers = new ArrayList<>();
    for (PdfSignatures.Embedded signature : embedded) {
      verifier.pdf(signature.cms(), signature.signedContent()).stream()
          .map(s -> s.orSigningTime(signature.signingTime()))
          .forEach(signers::add);
    }
    return signers;
  }

  /**
   * TUC_KON_080 (A) with the signature policy from SigPolicyId, then TUC_KON_162 per signature;
   * without signature 4253.
   */
  private List<Signer> xadesSigners(byte[] document) {
    try {
      xml.validate(document, null);
    } catch (ConnectorException e) {
      if (e.error() == ConnectorError.XML_NOT_WELL_FORMED
          && vendor.reportsMalformedXmlAsSignatureType()) {
        throw ConnectorError.INVALID_SIGNATURE_TYPE
            .exception("XML nicht wohlgeformt (Profil RISE)")
            .causedBy(e);
      }
      throw e;
    }
    String policy = xml.signaturePolicy(document);
    if (XmlSignatures.NFDM_POLICY.equals(policy)) {
      xml.validate(document, policy);
    }
    List<Signer> signers = xml.verify(document);
    if (signers.isEmpty()) {
      throw ConnectorError.NO_SIGNATURE.exception("XML-Dokument ohne ds:Signature");
    }
    return signers;
  }

  /** TAB_KON_760 step 1: empty values are a syntax error (KUC_1603_007, KUC_1604_006). */
  private static void checkArguments(Request request) {
    if (request.signature() != null && request.signature().value().length == 0) {
      throw ConnectorError.SYNTAX.exception("dss:Base64Signature leer");
    }
    if (request.document() != null && request.document().content().length == 0) {
      throw ConnectorError.SYNTAX.exception("SIG:Document ohne Inhalt");
    }
    if (request.document() == null && request.signature() == null) {
      throw ConnectorError.SYNTAX.exception("weder SIG:Document noch dss:SignatureObject");
    }
  }

  /** The CMS signature of the call; LIANA does not implement other signature formats (yet). */
  private byte[] cmsSignature(Request request) {
    Signature signature = request.signature();
    if (signature != null) {
      String type = signature.type();
      if (SignatureType.XML.uri().equals(type)) {
        throw new DocumentSigning.Unsupported("VerifyDocument mit detached XML-Signatur");
      }
      if (type != null && !CMS.equals(type)) {
        throw ConnectorError.INVALID_SIGNATURE_TYPE.exception(type);
      }
      return signature.value();
    }
    Document document = request.document();
    // TUC_KON_161/151 (->1): a document without embedded signature and without SignatureObject
    throw ConnectorError.NO_SIGNATURE.exception(
        "SIG:Document " + document.mimeType() + " ohne SignatureObject");
  }

  /**
   * The S/MIME message of the call: Base64Signature with Type S/MIME or a document {@code
   * application/pkcs7-mime} without SignatureObject; empty if there is none. Profile KOCO reports
   * S/MIME as 4279 with the text without slash (as for SignDocument, KUC_1603_001/010).
   */
  private Optional<byte[]> smimeMessage(Request request) {
    byte[] message = null;
    String detail = null;
    if (request.signature() != null && SMIME.equals(request.signature().type())) {
      message = request.signature().value();
      detail = request.signature().type();
    } else if (request.signature() == null
        && !request.document().xml()
        && MIME_SMIME.equals(request.document().mimeType())) {
      message = request.document().content();
      detail = request.document().mimeType();
    }
    if (message != null && vendor.rejectsSmime()) {
      throw ConnectorError.SMIME_UNSUPPORTED.exception(
          "SMIME-Funktionalität nicht unterstützt", detail);
    }
    return Optional.ofNullable(message);
  }

  /**
   * TAB_KON_759 IncludeRevocationInfo: online embed one OCSP response per signature certificate,
   * none for countersignatures; offline the signature stays as it is.
   */
  private byte[] withRevocationInfo(byte[] signature, List<Signer> signers) {
    if (!settings.online()) {
      return null;
    }
    byte[] updated = signature;
    for (Signer signer : signers) {
      if (!signer.counterSignature() && signer.certificate() != null) {
        updated =
            verifier.embedOcsp(updated, revocation.status(signer.certificate()).ocspResponse());
      }
    }
    return updated;
  }
}

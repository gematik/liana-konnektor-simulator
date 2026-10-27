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

import de.gematik.liana.kern.error.ConnectorError;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Port for the cryptographic check of a document signature (decision-022): TUC_KON_161 or
 * TUC_KON_151 step 2 „CoreValidation“ and step 3 parts 1–2 for CMS ([RFC5652] 5.6) and PDF
 * ([PAdES-3] 4.6), plus the certificate check of part 3 without revocation status (TUC_KON_037 with
 * TUC_PKI_018 or TUC_PKI_030). The flow and the result are determined by {@link
 * DocumentVerification}.
 */
public interface SignatureVerifier {

  /** A finding with error code, {@code detail} for log and tests. */
  record Problem(ConnectorError error, String detail) {}

  /**
   * A signature (SignerInfo) with the result of the CoreValidation.
   *
   * @param signatureValue the signature value, identifies the signature in the verification report
   * @param counterSignature countersignature (unsigned attribute countersignature of another
   *     signature)
   * @param certificate the signature certificate (DER), {@code null} if it could not be determined
   *     (then 4206 in {@code problems})
   * @param qualified signature certificate with QCStatement id-etsi-qcs-QcCompliance (TAB_KON_760
   *     step 3)
   * @param signingTime the signed attribute signingTime, for PAdES otherwise {@code /M}
   *     (Ermittelter_Signaturzeitpunkt_Eingebettet)
   * @param problems findings of the CoreValidation, empty if it succeeded
   */
  record Signer(
      byte[] signatureValue,
      boolean counterSignature,
      byte[] certificate,
      boolean qualified,
      Optional<Instant> signingTime,
      List<Problem> problems) {

    /** The same signature with {@code signingTime} if it carries none itself. */
    public Signer orSigningTime(Optional<Instant> time) {
      return signingTime.isPresent()
          ? this
          : new Signer(signatureValue, counterSignature, certificate, qualified, time, problems);
    }
  }

  /**
   * All signatures of a CMS SignedData, including parallel and countersignatures.
   *
   * @param detachedContent the signed document for a detached signature, otherwise {@code null}
   * @throws de.gematik.liana.kern.error.ConnectorException 4000 if {@code signature} is not a CMS
   *     SignedData; 4253 without SignerInfo
   */
  List<Signer> cms(byte[] signature, byte[] detachedContent);

  /**
   * The signatures of a PDF signature ([PAdES-3] 4.6): {@code cms} from {@code /Contents} over
   * {@code signedContent} from {@code /ByteRange}, without the CRLF fallback.
   *
   * @throws de.gematik.liana.kern.error.ConnectorException 4000 if {@code cms} is not a CMS
   *     SignedData
   */
  List<Signer> pdf(byte[] cms, byte[] signedContent);

  /**
   * TUC_KON_037 without revocation status at verification time {@code baseTime}: for a QES
   * TUC_PKI_030 against the BNetzA-VL, otherwise TUC_PKI_018 against the TSL with the certificate
   * types from TAB_KON_786.
   *
   * @return the first finding, empty if the certificate is valid
   */
  Optional<Problem> checkCertificate(byte[] certificate, boolean qualified, Instant baseTime);

  /**
   * IncludeRevocationInfo: {@code ocspResponse} (DER) in {@code SignedData.crls.other} (RFC 5940).
   */
  byte[] embedOcsp(byte[] signature, byte[] ocspResponse);
}

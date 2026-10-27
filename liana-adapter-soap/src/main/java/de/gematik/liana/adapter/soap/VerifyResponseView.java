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
package de.gematik.liana.adapter.soap;

import de.gematik.liana.kern.error.ConnectorError;
import de.gematik.liana.kern.signature.DocumentVerification;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;

/**
 * Content of {@code SIG:VerifyDocumentResponse} (TAB_KON_759): status OK or, if INVALID, Warning
 * with the findings as {@code GERROR:Trace} (KUC_1604_008), VerificationResult and in
 * OptionalOutputs {@code dss:UpdatedSignature} (IncludeRevocationInfo) and a lean {@code
 * vr:VerificationReport} (ReturnVerificationReport, decision-022): per signature the signature
 * value and ResultMajor/ResultMinor according to TAB_KON_754.
 */
public record VerifyResponseView(
    String result,
    List<GerrorView> traces,
    String highLevelResult,
    String timestampType,
    String timestamp,
    String updatedSignature,
    boolean report,
    String verificationTime,
    List<Individual> signatures) {

  static final String SUCCESS = "urn:oasis:names:tc:dss:1.0:resultmajor:Success";
  static final String INSUFFICIENT_INFORMATION =
      "urn:oasis:names:tc:dss:1.0:resultmajor:InsufficientInformation";
  static final String VALID =
      "urn:oasis:names:tc:dss:1.0:resultminor:valid:signature:OnAllDocuments";
  static final String INCORRECT_SIGNATURE =
      "urn:oasis:names:tc:dss:1.0:resultminor:invalid:IncorrectSignature";
  static final String CHAIN_NOT_COMPLETE =
      "urn:oasis:names:tc:dss:1.0:resultminor:CertificateChainNotComplete";

  /** {@code vr:IndividualReport} of a signature. */
  public record Individual(String signatureValue, String resultMajor, String resultMinor) {}

  static VerifyResponseView of(DocumentVerification.Result result, boolean report, Instant now) {
    List<GerrorView> traces =
        result.problems().stream().map(p -> GerrorView.of(p.error(), p.error().text())).toList();
    return new VerifyResponseView(
        traces.isEmpty() ? "OK" : "Warning",
        traces,
        result.highLevelResult().name(),
        result.timestampType().name(),
        time(result.timestamp()),
        result.updatedSignature() == null
            ? null
            : Base64.getEncoder().encodeToString(result.updatedSignature()),
        report,
        time(now),
        result.signatures().stream().map(VerifyResponseView::individual).toList());
  }

  private static Individual individual(DocumentVerification.SignatureResult signature) {
    String value = Base64.getEncoder().encodeToString(signature.signatureValue());
    if (signature.valid()) {
      return new Individual(value, SUCCESS, VALID);
    }
    // TAB_KON_754: signature value wrong or certificate check failed
    boolean incorrect =
        signature.problems().stream()
            .anyMatch(p -> p.error() == ConnectorError.DOCUMENT_SIGNATURE_INVALID);
    return incorrect
        ? new Individual(value, SUCCESS, INCORRECT_SIGNATURE)
        : new Individual(value, INSUFFICIENT_INFORMATION, CHAIN_NOT_COMPLETE);
  }

  private static String time(Instant instant) {
    return DateTimeFormatter.ISO_INSTANT.format(instant.truncatedTo(ChronoUnit.MILLIS));
  }
}

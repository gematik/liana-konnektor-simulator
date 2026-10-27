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

/**
 * {@code SIG:SignRequest} of SignDocument (TAB_KON_065): a signature job for one document.
 *
 * @param requestId {@code @RequestID}
 * @param document {@code SIG:Document}
 * @param signatureType {@code dss:SignatureType} as URI, {@code null} if not given (default per
 *     TAB_KON_583)
 * @param includeEContent {@code SIG:IncludeEContent}, {@code null} if not given
 * @param includeRevocationInfo {@code SIG:IncludeRevocationInfo}
 * @param placement {@code dss:SignaturePlacement}, {@code null} if not given
 * @param includeObject whether {@code SIG:IncludeObject} was passed
 * @param updateType {@code dss:ReturnUpdatedSignature/@Type}, {@code null} if not given
 * @param signaturePolicy {@code sp:GenerateUnderSignaturePolicy/sp:SignaturePolicyIdentifier},
 *     {@code null} if absent
 */
public record SignRequest(
    String requestId,
    Document document,
    String signatureType,
    Boolean includeEContent,
    boolean includeRevocationInfo,
    Placement placement,
    boolean includeObject,
    String updateType,
    String signaturePolicy) {

  /** {@code dss:ReturnUpdatedSignature/@Type} for a parallel signature. */
  public static final String PARALLEL = "http://ws.gematik.de/conn/sig/sigupdate/parallel";

  /** {@code dss:ReturnUpdatedSignature/@Type} for a document-excluding countersignature. */
  public static final String COUNTER =
      "http://ws.gematik.de/conn/sig/sigupdate/counter/documentexcluding";

  /** Whether {@code dss:SignaturePlacement} was passed. */
  public boolean signaturePlacement() {
    return placement != null;
  }

  /**
   * {@code SIG:Document}: attributes {@code ID}, {@code RefURI}, {@code ShortText}, the MIME type
   * of {@code dss:Base64Data} and the content; {@code xml} for {@code CONN:Base64XML}.
   */
  public record Document(
      String id, String refUri, String shortText, String mimeType, byte[] content, boolean xml) {}

  /**
   * {@code dss:SignaturePlacement} ([OASIS-DSS] 3.5.8): {@code WhichDocument}, {@code
   * XPathFirstChildOf} or {@code XPathAfter} (one of them, otherwise {@code null}) and {@code
   * CreateEnvelopedSignature} (default true).
   */
  public record Placement(
      String whichDocument,
      String xPathFirstChildOf,
      String xPathAfter,
      boolean createEnvelopedSignature) {}
}

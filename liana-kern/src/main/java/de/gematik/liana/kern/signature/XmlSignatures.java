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

import de.gematik.liana.kern.signature.SignatureVerifier.Signer;
import java.util.List;
import java.util.function.UnaryOperator;

/**
 * Port for XML documents and XAdES (decision-023, LIANA-112.09): TUC_KON_080 (A), XAdES signatures
 * under a signature policy (TIP1-A_5538) and the check of the embedded signatures per TUC_KON_162.
 */
public interface XmlSignatures {

  /** The signature policy of the NFDM Fachmodul (SR_DF_NFDM_NOTFALLDATEN). */
  String NFDM_POLICY = "urn:gematik:fa:sak:nfdm:r1:v1";

  /**
   * TUC_KON_080 (A) „XML-Dokumentvalidierung“: well-formed (otherwise 4022), with {@code
   * signaturePolicy} valid against its schema (otherwise 4023), without schema unique ID attribute
   * values (otherwise 4022).
   *
   * @param signaturePolicy the URI of the signature policy, {@code null} for none
   */
  void validate(byte[] document, String signaturePolicy);

  /**
   * An XAdES signature job: internally detached, the signature as first child of {@code
   * xPathFirstChildOf}.
   *
   * @param document the XML document
   * @param certificate the signature certificate (DER)
   * @param shortText for {@code DataObjectFormat/Description} (TUC_KON_155), {@code null} for none
   * @param referenceUri {@code RefURI} of the document, the reference to the signed element ({@code
   *     #ID})
   * @param xPathFirstChildOf the element that receives the signature
   * @param signaturePolicy the URI for {@code SigPolicyId}
   */
  record Request(
      byte[] document,
      byte[] certificate,
      String shortText,
      String referenceUri,
      String xPathFirstChildOf,
      String signaturePolicy) {}

  /**
   * Signs per [XAdES] as XAdES-EPES (TIP1-A_5402): canonicalize {@code SignedInfo}, have the hash
   * signed with {@code signHash} and check it mathematically (TUC_KON_166 step 3: otherwise 4120).
   * An XPath that matches no element, or a reference that does not resolve, is 4111.
   *
   * @return the document with the signature
   */
  byte[] sign(Request request, UnaryOperator<byte[]> signHash);

  /**
   * TUC_KON_159 step 5: {@code ocspResponse} (DER) in {@code RevocationValues/OCSPValues} of the
   * signature that is the first child of {@code xPathFirstChildOf} (unsigned property).
   */
  byte[] embedOcsp(byte[] document, String xPathFirstChildOf, byte[] ocspResponse);

  /**
   * The first {@code SigPolicyId/Identifier} of a signature in the document (TIP1-A_5538), {@code
   * null} if none.
   */
  String signaturePolicy(byte[] document);

  /**
   * TUC_KON_162 „Kryptographische Prüfung der XML-Dokumentensignatur“: every {@code ds:Signature}
   * of the document with core validation per [XMLDSig] 3.2 and the comparison of {@code
   * SigningCertificate}; {@code SigningTime} as the embedded signing time. Empty without signature.
   */
  List<Signer> verify(byte[] document);
}

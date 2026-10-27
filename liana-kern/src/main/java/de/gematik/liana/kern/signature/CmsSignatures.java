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

import java.util.function.UnaryOperator;

/**
 * Port for CMS signatures (CAdES-BES, [RFC5652]): TUC_KON_155 for signatureType CMS and steps 1, 3
 * and 4 of TUC_KON_166. The signature itself comes from the card (TUC_KON_218, step 2).
 */
public interface CmsSignatures {

  /**
   * A CMS signature job.
   *
   * @param content the document to sign
   * @param encapsulate enveloping ({@code IncludeEContent=true}) instead of detached
   * @param certificate the signature certificate (DER), TUC_KON_165 step 2
   * @param shortText {@code ShortText} for the attribute ContentHints (TUC_KON_155), {@code null}
   *     for none
   * @param parallelTo an existing CMS signature (enveloping) to which a parallel signature is
   *     added; otherwise {@code null}
   */
  record Request(
      byte[] content,
      boolean encapsulate,
      byte[] certificate,
      String shortText,
      byte[] parallelTo) {}

  /**
   * Builds the SignedData, has the hash of the signed attributes signed with {@code signHash}
   * (SHA-256, result ECDSA-Sig-Value) and checks the signature mathematically (TUC_KON_166 step 3:
   * otherwise 4120).
   *
   * @return the DER-encoded ContentInfo with SignedData
   */
  byte[] sign(Request request, UnaryOperator<byte[]> signHash);

  /**
   * TUC_KON_159 step 5 for CAdES: {@code ocspResponse} (DER OCSPResponse) in {@code
   * SignedData.crls.other} (id-ri-ocsp-response 1.3.6.1.5.5.7.16.2, RFC 5940); the signature itself
   * stays unchanged.
   */
  byte[] embedOcsp(byte[] signedData, byte[] ocspResponse);
}

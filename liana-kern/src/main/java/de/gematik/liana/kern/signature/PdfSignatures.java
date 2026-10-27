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

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.function.UnaryOperator;

/**
 * Port for PDF documents (decision-020, LIANA-112.08): the PDF/A identification for TUC_KON_080
 * (B), PAdES signatures per [PAdES-3] as incremental update (TAB_KON_779-01) and the embedded
 * signatures for VerifyDocument.
 */
public interface PdfSignatures {

  /**
   * {@code pdfaid:part} from the XMP metadata of the document catalog; empty if the document is not
   * a readable PDF or does not identify itself as PDF/A.
   */
  OptionalInt pdfaPart(byte[] document);

  /**
   * A PAdES signature job.
   *
   * @param document the PDF/A document
   * @param certificate the signature certificate (DER)
   * @param reason the ShortText for the field Reason (TUC_KON_155), {@code null} for none
   */
  record Request(byte[] document, byte[] certificate, String reason) {}

  /**
   * Appends a signature field as incremental update (SubFilter ETSI.CAdES.detached, without
   * appearance), has the hash of the signed attributes signed with {@code signHash} and checks the
   * signature mathematically (TUC_KON_166 step 3: otherwise 4120).
   *
   * @return the signed document
   */
  byte[] sign(Request request, UnaryOperator<byte[]> signHash);

  /**
   * A signature in the document.
   *
   * @param cms {@code /Contents}, the CMS signature
   * @param signedContent the bytes from {@code /ByteRange}
   * @param signingTime {@code /M} of the signature dictionary ([PAdES Baseline Profile] 6.2.1)
   */
  record Embedded(byte[] cms, byte[] signedContent, Optional<Instant> signingTime) {}

  /**
   * The signatures of the document in the order of its signature fields; an unreadable PDF is 4024.
   */
  List<Embedded> signatures(byte[] document);
}

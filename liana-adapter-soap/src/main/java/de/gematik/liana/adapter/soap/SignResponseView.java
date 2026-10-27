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

import de.gematik.liana.kern.signature.SignResult;
import de.gematik.liana.kern.signature.SignatureType;
import de.gematik.liana.kern.signature.Smime;
import java.util.Base64;
import java.util.List;

/**
 * Content of {@code SIG:SignResponse} (TAB_KON_065): status with the warnings or the error as
 * {@code GERROR:Trace}, {@code SIG:DocumentWithSignature} with the attributes of the SignRequest
 * and {@code dss:SignatureObject}. For CMS the document is empty (the signature is not in the
 * document) and the signature is in {@code dss:Base64Signature}; for PAdES it contains the signed
 * PDF, for XAdES the signed XML document ({@code CONN:Base64XML}, with {@code RefURI}), and {@code
 * dss:SignaturePtr} refers to it via {@code WhichDocument}, for XAdES with the {@code XPath} of the
 * signature ([OASIS-DSS] 2.5, KUC_1602_044). For S/MIME the document is the S/MIME message,
 * MimeType {@code application/pkcs7-mime} (TAB_KON_757). Without {@code ID} in the SignRequest
 * LIANA assigns one, because otherwise the IDREF points nowhere. Without signature only the status
 * with Result Warning and the error: ResultEnum (ConnectorCommon.xsd) knows only OK and Warning.
 *
 * @param document the signed document (Base64) for PAdES, XAdES and S/MIME, otherwise {@code null}
 * @param xPath {@code dss:SignaturePtr/@XPath} for XAdES, otherwise {@code null}
 */
public record SignResponseView(
    String requestId,
    String result,
    List<GerrorView> traces,
    String documentId,
    String refUri,
    String shortText,
    String mimeType,
    boolean xml,
    String type,
    String signature,
    String document,
    String xPath) {

  static SignResponseView of(SignResult result, int index) {
    if (result.error() != null) {
      return new SignResponseView(
          result.requestId(),
          "Warning",
          List.of(GerrorView.of(result.error(), result.error().text())),
          null,
          null,
          null,
          null,
          false,
          null,
          null,
          null,
          null);
    }
    String encoded = Base64.getEncoder().encodeToString(result.signature());
    boolean inDocument = result.type() != SignatureType.CMS;
    String id = result.document().id();
    if (inDocument && (id == null || id.isEmpty())) {
      id = "LIANA-Document-" + (index + 1);
    }
    return new SignResponseView(
        result.requestId(),
        result.warnings().isEmpty() ? "OK" : "Warning",
        result.warnings().stream().map(w -> GerrorView.of(w, w.text())).toList(),
        id,
        result.document().refUri(),
        result.document().shortText(),
        result.type() == SignatureType.SMIME ? Smime.MIME_TYPE : result.document().mimeType(),
        result.document().xml(),
        result.type().uri(),
        inDocument ? null : encoded,
        inDocument ? encoded : null,
        result.signaturePath());
  }
}

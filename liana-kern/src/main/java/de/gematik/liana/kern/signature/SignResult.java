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
import java.util.List;

/**
 * {@code SIG:SignResponse} for a SignRequest (TAB_KON_065): the signature for {@code
 * dss:SignatureObject} (for PAdES and XAdES the signed document), the document for the attributes
 * of {@code SIG:DocumentWithSignature} and the warnings for {@code CONN:Status}. Without signature,
 * {@code error} is in the status, e.g. for the SignRequests of an aborted batch (TAB_KON_192).
 *
 * @param signaturePath for XAdES the XPath of the signature in the document ({@code
 *     dss:SignaturePtr/@XPath}), otherwise {@code null}
 */
public record SignResult(
    String requestId,
    SignRequest.Document document,
    SignatureType type,
    byte[] signature,
    List<ConnectorError> warnings,
    ConnectorError error,
    String signaturePath) {

  /** A SignRequest without signature, {@code error} in the status. */
  static SignResult failed(SignRequest request, ConnectorError error) {
    return new SignResult(
        request.requestId(), request.document(), null, null, List.of(), error, null);
  }
}

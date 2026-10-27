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
package de.gematik.liana.konnektor;

/**
 * Result of a signature per document (SignResponse; LIANA-136).
 *
 * @param requestId RequestID of the document in the request
 * @param status {@code OK}, {@code Warning} or {@code Error}
 * @param signatureType {@code Base64Signature/@Type}
 * @param signature CMS signature, signed PDF or XML signature (depending on the type), empty on
 *     error
 */
public record SignResult(String requestId, String status, String signatureType, byte[] signature) {

  public SignResult {
    signature = signature == null ? new byte[0] : signature.clone();
  }

  @Override
  public byte[] signature() {
    return signature.clone();
  }
}

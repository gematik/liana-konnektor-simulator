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
 * Port for the status response for a signature certificate (TUC_KON_159 step 2, OCSP): until
 * LIANA-87 a simulator (decision-021), afterwards also the query per TUC_PKI_006.
 */
public interface RevocationSource {

  /** Certificate status of the OCSP response (RFC 6960). */
  enum Status {
    GOOD,
    REVOKED,
    UNKNOWN
  }

  /** The response: DER-encoded OCSPResponse and the status of the requested certificate. */
  record Answer(byte[] ocspResponse, Status status) {}

  /** Status response for {@code certificate} (DER). */
  Answer status(byte[] certificate);
}

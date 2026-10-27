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
package de.gematik.liana.kern.card;

/**
 * Port for the offline check of a card certificate in TUC_KON_037 „Zertifikat prüfen“, as
 * TUC_KON_018 step 6a needs it for C.CH.AUT: result valid or invalid, without revocation status
 * (OCSP).
 */
public interface CertificateCheck {

  /** {@code null} if {@code der} is valid offline, otherwise the reason for log and tests. */
  String offlineInvalid(byte[] der);
}

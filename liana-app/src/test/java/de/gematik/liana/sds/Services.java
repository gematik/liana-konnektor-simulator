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
package de.gematik.liana.sds;

import java.util.List;

/**
 * The services that {@code connector.sds} advertises, in this order; endpoint {@code /ws/<Name>}
 * each.
 */
public final class Services {

  public static final List<String> NAMES =
      List.of(
          "EventService",
          "CardTerminalService",
          "CardService",
          "CertificateService",
          "AuthSignatureService",
          "SignatureService",
          "EncryptionService",
          "VSDService",
          "KVKService");

  private Services() {}

  /** The endpoints under {@code baseUrl}. */
  public static List<String> endpoints(String baseUrl) {
    return NAMES.stream().map(name -> baseUrl + "/ws/" + name).toList();
  }
}

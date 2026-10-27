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

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Verification of the Konnektor certificate ({@code .kon} {@code trustStore}, {@code expectedHost},
 * {@code insecureSkipVerify}). A certificate from {@code certificates} counts as a pin if it is the
 * server certificate itself, otherwise as a trust anchor of the chain. Without certificates, the
 * JDK truststore applies.
 *
 * @param certificates pins and CAs
 * @param expectedHost name that must appear in the certificate instead of the host from the URL,
 *     {@code null}: host of the URL
 * @param insecureSkipVerify no verification, for tests only
 */
public record Trust(
    List<X509Certificate> certificates, String expectedHost, boolean insecureSkipVerify) {

  public Trust {
    certificates = List.copyOf(certificates);
  }

  /** JDK truststore, hostname from the URL. */
  public static Trust system() {
    return new Trust(List.of(), null, false);
  }

  /** Trusts {@code certificates} (pins or CAs). */
  public static Trust of(X509Certificate... certificates) {
    return new Trust(List.of(certificates), null, false);
  }

  /** Without any verification ({@code insecureSkipVerify}), for tests only. */
  public static Trust insecure() {
    return new Trust(List.of(), null, true);
  }

  /** The same verification with {@code expectedHost}. */
  public Trust withExpectedHost(String host) {
    return new Trust(certificates, host, insecureSkipVerify);
  }
}

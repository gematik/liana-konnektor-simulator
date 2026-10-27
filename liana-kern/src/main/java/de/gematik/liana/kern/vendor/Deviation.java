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
package de.gematik.liana.kern.vendor;

/**
 * Known deviation of a peer from the spec (LIANA-126): LIANA always talks per spec first; if it
 * detects one of these deviations, {@link PeerDeviations} decides per {@code liana.strict} whether
 * LIANA falls back. Each deviation names the peer, the spec location, the observed behavior and the
 * fallback. The fix belongs to the peer (kartos: decision-7); the entry here is removed as soon as
 * it is fixed there.
 */
public enum Deviation {

  /**
   * kartos terminal 0.8.0 ({@code crates/kartos-terminal/src/sicct/perform_verification.rs})
   * expects a PinFormat DO {@code 5F2F} for the PIN change instead of the CMD DO (control byte,
   * insertion positions) and unblocks via {@code 80 1A}; SICCT 1.2.3 §5.20 only knows {@code 80 19}
   * with CMD DO. kartos answers the spec-compliant command with {@code 6700}: it reads the control
   * byte and the 1st insertion position as PinFormat, after which the card APDU is broken. kartos
   * does not know the new-PIN-only case (null PIN procedure) at all; there it goes as {@code 80
   * 18}. Evaluated in {@code SicctTerminal.pinCommand} (LIANA-127).
   */
  KARTOS_MODIFY_VERIFICATION_DATA(
      "kartos terminal 0.8.0",
      "SICCT 1.2.3 §5.20 MODIFY VERIFICATION DATA",
      "80 19 nach Spec → 6700; erwartet PinFormat-DO 5F2F statt CMD DO, Entsperren als 80 1A, nur neue PIN "
          + "als 80 18",
      "Kommando im kartos-Format wiederholen"),

  /**
   * Konnektor-QES (KUC/HSK_1608) enables the Komfortsignatur function via the KMS without switching
   * the Clientsystem interface to TLS with client authentication; TAB_KON_596 allows
   * SAK_COMFORT_SIGNATURE = Enabled only with ANCL_TLS_MANDATORY and ANCL_CAUT_MANDATORY Enabled.
   * Evaluated in {@code ComfortSettings.enabled} (LIANA-112.06, decision of the user).
   */
  COMFORT_WITHOUT_CLIENT_TLS(
      "Administrator über das KMS",
      "TAB_KON_596 SAK_COMFORT_SIGNATURE",
      "SAK_COMFORT_SIGNATURE = Enabled bei ANCL_TLS_MANDATORY oder ANCL_CAUT_MANDATORY Disabled",
      "Komfortsignaturfunktion trotzdem einschalten"),

  /**
   * Konnektor-QES 0f274c4c (KUC_1607_003/004/012/202/203/211, KUC_1609_028–036): the vendors'
   * detached CAdES are signed over the originals with CRLF, the suite's repo holds the originals
   * with LF, and that is how the suite sends them in VerifyDocument. Per [RFC5652] 5.4,
   * messageDigest then does not match (4115); the suite expects VALID. Evaluated in {@code
   * CmsVerifier.cms} (LIANA-112.07, decision of the user).
   */
  DETACHED_CONTENT_LF(
      "Konnektor-QES 0f274c4c (Testdaten)",
      "RFC 5652 5.4 messageDigest, TUC_KON_161/151 Schritt 2",
      "detached signiertes Dokument mit LF statt der signierten CRLF-Zeilenenden",
      "CoreValidation mit CRLF-Zeilenenden wiederholen");

  private final String peer;
  private final String spec;
  private final String observed;
  private final String fallback;

  Deviation(String peer, String spec, String observed, String fallback) {
    this.peer = peer;
    this.spec = spec;
    this.observed = observed;
    this.fallback = fallback;
  }

  /** The peer with the version at which the deviation was observed. */
  public String peer() {
    return peer;
  }

  /** The spec location the peer deviates from. */
  public String spec() {
    return spec;
  }

  /** What the peer does instead of the spec. */
  public String observed() {
    return observed;
  }

  /** What LIANA does instead without {@code strict}. */
  public String fallback() {
    return fallback;
  }
}

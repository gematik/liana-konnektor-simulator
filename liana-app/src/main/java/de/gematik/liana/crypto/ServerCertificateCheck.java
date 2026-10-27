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
package de.gematik.liana.crypto;

import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

/**
 * TUC_KON_037 for the certificate of a TLS peer with {@code intendedKeyUsage} digitalSignature,
 * {@code intendedExtendedKeyUsage = id-kp-serverAuth} and a certificate type, without revocation
 * check ({@code offlineAllowNoCheck = true}): in the order of TUC_PKI_018 validity period,
 * KeyUsage, ExtendedKeyUsage, issuer in the Vertrauensraum (TSL or imported) including signature,
 * certificate type. For C.SMKT.AUT ({@link SmktCertificateCheck}) and C.FD.TLS-S ({@link CardTls}).
 */
final class ServerCertificateCheck {

  /** RFC 5280: id-kp-serverAuth. */
  static final String SERVER_AUTH = "1.3.6.1.5.5.7.3.1";

  private static final int DIGITAL_SIGNATURE = 0;

  private ServerCertificateCheck() {}

  /**
   * @param type certificate in messages, e.g. C.SMKT.AUT
   * @param policyName name of the certificate type, e.g. oid_smkt_aut
   */
  static void check(
      X509Certificate certificate,
      String type,
      String policyName,
      String policyOid,
      Function<X509Certificate, Optional<X509Certificate>> issuers,
      Clock clock)
      throws CertificateException {
    String subject = certificate.getSubjectX500Principal().getName();
    try {
      certificate.checkValidity(Date.from(clock.instant()));
    } catch (CertificateExpiredException | CertificateNotYetValidException e) {
      throw new CertificateException(
          type + " " + subject + " zeitlich ungültig: " + e.getMessage(), e);
    }
    boolean[] keyUsage = certificate.getKeyUsage();
    if (keyUsage == null || !keyUsage[DIGITAL_SIGNATURE]) {
      throw new CertificateException(type + " " + subject + ": KeyUsage digitalSignature fehlt");
    }
    if (!extendedKeyUsage(certificate).contains(SERVER_AUTH)) {
      throw new CertificateException(type + " " + subject + ": ExtendedKeyUsage serverAuth fehlt");
    }
    X509Certificate issuer =
        issuers
            .apply(certificate)
            .orElseThrow(
                () ->
                    new CertificateException(
                        type
                            + " "
                            + subject
                            + ": Aussteller "
                            + certificate.getIssuerX500Principal().getName()
                            + " weder in der TSL noch importiert"));
    try {
      certificate.verify(issuer.getPublicKey(), CryptoProviders.BC);
    } catch (GeneralSecurityException e) {
      throw new CertificateException(
          type + " " + subject + ": Signatur des Ausstellers ungültig", e);
    }
    List<String> policies = ScenarioSignerCheck.policies(certificate);
    if (!policies.contains(policyOid)) {
      throw new CertificateException(
          type
              + " "
              + subject
              + ": Policies "
              + policies
              + " ohne "
              + policyName
              + " "
              + policyOid);
    }
  }

  private static List<String> extendedKeyUsage(X509Certificate certificate)
      throws CertificateException {
    try {
      List<String> usage = certificate.getExtendedKeyUsage();
      return usage == null ? List.of() : usage;
    } catch (CertificateParsingException e) {
      throw new CertificateException("ExtendedKeyUsage nicht lesbar", e);
    }
  }
}

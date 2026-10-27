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

import de.gematik.liana.kern.card.CertificateCheck;
import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.Date;

/**
 * TUC_KON_037 „Zertifikat prüfen“ offline for C.CH.AUT of the eGK, as TUC_KON_018 step 6a needs it:
 * temporally valid (TUC_PKI_002), issuer in the TSL or imported (TUC_PKI_003), signature
 * mathematically valid (TUC_PKI_004). TUC_KON_018 specifies neither policyList nor
 * intendedKeyUsage, so LIANA checks neither.
 */
public final class EgkCertificateCheck implements CertificateCheck {

  private final TrustSpace trustSpace;
  private final Clock clock;

  public EgkCertificateCheck(TrustSpace trustSpace, Clock clock) {
    this.trustSpace = trustSpace;
    this.clock = clock;
  }

  @Override
  public String offlineInvalid(byte[] der) {
    X509Certificate certificate;
    try {
      certificate =
          (X509Certificate)
              CertificateFactory.getInstance("X.509")
                  .generateCertificate(new ByteArrayInputStream(der));
    } catch (CertificateException e) {
      return "C.CH.AUT nicht dekodierbar: " + e.getMessage();
    }
    String subject = certificate.getSubjectX500Principal().getName();
    try {
      certificate.checkValidity(Date.from(clock.instant()));
    } catch (CertificateExpiredException | CertificateNotYetValidException e) {
      return subject + " zeitlich nicht gültig: " + e.getMessage();
    }
    var issuer = trustSpace.issuerOf(certificate);
    if (issuer.isEmpty()) {
      return subject
          + ": Aussteller "
          + certificate.getIssuerX500Principal().getName()
          + " weder in TSL noch importiert";
    }
    try {
      certificate.verify(issuer.get().certificate().getPublicKey(), CryptoProviders.BC);
    } catch (GeneralSecurityException e) {
      return subject + ": Signatur ungültig: " + e.getMessage();
    }
    return null;
  }
}

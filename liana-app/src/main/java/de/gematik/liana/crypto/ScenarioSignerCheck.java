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

import de.gematik.liana.kern.error.ConnectorError;
import de.gematik.liana.kern.error.ConnectorException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.isismtt.ISISMTTObjectIdentifiers;
import org.bouncycastle.asn1.isismtt.x509.AdmissionSyntax;
import org.bouncycastle.asn1.isismtt.x509.Admissions;
import org.bouncycastle.asn1.isismtt.x509.ProfessionInfo;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;

/**
 * TUC_KON_037 „Zertifikat prüfen“ for the signer of a SignedScenario, with the parameters from
 * TAB_KON_271 step 2: {@code policyList = oid_zd_sig}, {@code intendedKeyUsage =
 * intendedKeyUsage(C.ZD.SIG)}, technical role {@code oid_popp}.
 *
 * <p>Procedure per TUC_PKI_018, with one deviation in the order: the role (4700) is checked before
 * the certificate type (1018). The Konnektor test suite (EE_KON_POPP_FF_016) signs with a C.FD.OSIG
 * certificate of the role oid_tigw_zugm and expects 4700.
 *
 * <p>Revocation status: {@code validationMode = OCSP} with {@code offlineAllowNoCheck = true}.
 * LIANA queries no OCSP responder and does not evaluate {@code stpl}; there, an OCSP check that
 * cannot be performed is only a warning.
 */
public final class ScenarioSignerCheck {

  /** GS-A_4446: technical role of the PoPP service. */
  static final String OID_POPP = "1.2.276.0.76.4.293";

  /** GS-A_4445: certificate type C.ZD.SIG. */
  static final String OID_ZD_SIG = "1.2.276.0.76.4.287";

  /** intendedKeyUsage(C.ZD.SIG), Tab_PKI_278: nonRepudiation. */
  private static final int NON_REPUDIATION = 1;

  private final TrustSpace trustSpace;
  private final Clock clock;

  public ScenarioSignerCheck(TrustSpace trustSpace, Clock clock) {
    this.trustSpace = trustSpace;
    this.clock = clock;
  }

  /**
   * Checks {@code signer} ({@code x5c[0]}).
   *
   * @throws ConnectorException with the first error in the order of TUC_PKI_018
   */
  public void check(X509Certificate signer) {
    String subject = signer.getSubjectX500Principal().getName();
    try {
      signer.checkValidity(Date.from(clock.instant()));
    } catch (CertificateExpiredException | CertificateNotYetValidException e) {
      throw ConnectorError.CERTIFICATE_NOT_VALID_TIME
          .exception(subject + ": " + e.getMessage())
          .causedBy(e);
    }
    boolean[] keyUsage = signer.getKeyUsage();
    if (keyUsage == null || !keyUsage[NON_REPUDIATION]) {
      throw ConnectorError.WRONG_KEYUSAGE.exception(subject + ": nonRepudiation fehlt");
    }
    var issuer =
        trustSpace
            .issuerOf(signer)
            .orElseThrow(
                () ->
                    ConnectorError.CA_CERT_MISSING.exception(
                        subject
                            + ": Aussteller "
                            + signer.getIssuerX500Principal().getName()
                            + " weder in TSL noch importiert"));
    try {
      signer.verify(issuer.certificate().getPublicKey(), CryptoProviders.BC);
    } catch (GeneralSecurityException e) {
      throw ConnectorError.CERTIFICATE_NOT_VALID_MATH
          .exception(subject + ": " + e.getMessage())
          .causedBy(e);
    }
    List<String> roles = roles(signer);
    if (!roles.contains(OID_POPP)) {
      throw ConnectorError.CERT_ROLE.exception(
          subject + ": Rollen " + roles + " statt oid_popp " + OID_POPP);
    }
    List<String> policies = policies(signer);
    if (!policies.contains(OID_ZD_SIG)) {
      throw ConnectorError.CERT_TYPE_MISMATCH.exception(
          subject + ": Policies " + policies + " ohne oid_zd_sig " + OID_ZD_SIG);
    }
  }

  /** TUC_PKI_009: role OIDs from the Admission extension (professionOIDs). */
  static List<String> roles(X509Certificate certificate) {
    byte[] extension =
        certificate.getExtensionValue(ISISMTTObjectIdentifiers.id_isismtt_at_admission.getId());
    List<String> roles = new ArrayList<>();
    if (extension == null) {
      return roles;
    }
    AdmissionSyntax admission = AdmissionSyntax.getInstance(parse(extension));
    for (Admissions admissions : admission.getContentsOfAdmissions()) {
      for (ProfessionInfo info : admissions.getProfessionInfos()) {
        for (ASN1ObjectIdentifier oid : info.getProfessionOIDs()) {
          roles.add(oid.getId());
        }
      }
    }
    return roles;
  }

  /** TUC_PKI_007: certificate type OIDs from CertificatePolicies. */
  static List<String> policies(X509Certificate certificate) {
    byte[] extension = certificate.getExtensionValue(Extension.certificatePolicies.getId());
    List<String> policies = new ArrayList<>();
    if (extension == null) {
      return policies;
    }
    for (PolicyInformation policy :
        CertificatePolicies.getInstance(parse(extension)).getPolicyInformation()) {
      policies.add(policy.getPolicyIdentifier().getId());
    }
    return policies;
  }

  /** Content of an extension from {@link X509Certificate#getExtensionValue}. */
  static ASN1Primitive parse(byte[] extension) {
    try {
      return JcaX509ExtensionUtils.parseExtensionValue(extension);
    } catch (IOException e) {
      throw new IllegalArgumentException("Extension nicht lesbar", e);
    }
  }
}

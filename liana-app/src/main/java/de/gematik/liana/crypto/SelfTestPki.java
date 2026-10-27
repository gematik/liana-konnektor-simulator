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

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Throwaway PKI for the crypto self-test: keys and certificates are created at runtime and do not
 * leave the process. Fixed test identities are in {@code support/pki/}.
 */
final class SelfTestPki {

  static final String BRAINPOOL_P256R1 = "brainpoolP256r1";
  static final String NIST_P256 = "secp256r1";

  private SelfTestPki() {}

  static KeyPair ecKeyPair(String curve) throws GeneralSecurityException {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", CryptoProviders.BC);
    // No static SecureRandom: the class is initialized during the native build, a seed in the image
    // heap
    // would be the same in every process (native-image therefore aborts).
    generator.initialize(new ECGenParameterSpec(curve), new SecureRandom());
    return generator.generateKeyPair();
  }

  /** CA certificate; self-signed if {@code issuer} is {@code null}. */
  static Issued ca(String commonName, String curve, Issued issuer) throws GeneralSecurityException {
    KeyPair keys = ecKeyPair(curve);
    X509Certificate cert = certificate(commonName, keys.getPublic(), issuer, keys, true);
    return new Issued(keys, cert);
  }

  static Issued endEntity(String commonName, String curve, Issued issuer)
      throws GeneralSecurityException {
    KeyPair keys = ecKeyPair(curve);
    return new Issued(keys, certificate(commonName, keys.getPublic(), issuer, keys, false));
  }

  /**
   * KT identity like C.SMKT.AUT: certificate type oid_smkt_aut, ExtendedKeyUsage serverAuth
   * (TUC_KON_050 step 3).
   */
  static Issued smktAut(String commonName, String curve, Issued issuer)
      throws GeneralSecurityException {
    KeyPair keys = ecKeyPair(curve);
    return new Issued(
        keys,
        certificate(
            commonName, keys.getPublic(), issuer, keys, false, SmktCertificateCheck.OID_SMKT_AUT));
  }

  /**
   * Fachdienst identity like C.FD.TLS-S: certificate type oid_fd_tls_s, ExtendedKeyUsage serverAuth
   * (TUC_KON_110).
   */
  static Issued fdTlsS(String commonName, String curve, Issued issuer)
      throws GeneralSecurityException {
    KeyPair keys = ecKeyPair(curve);
    return new Issued(
        keys, certificate(commonName, keys.getPublic(), issuer, keys, false, CardTls.OID_FD_TLS_S));
  }

  private static X509Certificate certificate(
      String commonName, PublicKey subjectKey, Issued issuer, KeyPair self, boolean ca)
      throws GeneralSecurityException {
    return certificate(commonName, subjectKey, issuer, self, ca, null);
  }

  private static X509Certificate certificate(
      String commonName,
      PublicKey subjectKey,
      Issued issuer,
      KeyPair self,
      boolean ca,
      String serverPolicy)
      throws GeneralSecurityException {
    X500Name subject = new X500Name("CN=" + commonName + ",O=LIANA Selbsttest,C=DE");
    X500Name issuerName =
        issuer == null
            ? subject
            : X500Name.getInstance(issuer.certificate().getSubjectX500Principal().getEncoded());
    PrivateKey signingKey = issuer == null ? self.getPrivate() : issuer.keys().getPrivate();
    Instant now = Instant.now();
    try {
      var builder =
          new JcaX509v3CertificateBuilder(
                  issuerName,
                  new BigInteger(64, new SecureRandom()),
                  Date.from(now.minus(Duration.ofMinutes(5))),
                  Date.from(now.plus(Duration.ofDays(1))),
                  subject,
                  subjectKey)
              .addExtension(Extension.basicConstraints, true, new BasicConstraints(ca))
              .addExtension(
                  Extension.keyUsage,
                  true,
                  new KeyUsage(
                      ca ? KeyUsage.keyCertSign | KeyUsage.cRLSign : KeyUsage.digitalSignature));
      if (serverPolicy != null) {
        builder
            .addExtension(
                Extension.certificatePolicies,
                false,
                new CertificatePolicies(
                    new PolicyInformation(new ASN1ObjectIdentifier(serverPolicy))))
            .addExtension(
                Extension.extendedKeyUsage,
                false,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
      }
      var signer =
          new JcaContentSignerBuilder("SHA256withECDSA")
              .setProvider(CryptoProviders.BC)
              .build(signingKey);
      return new JcaX509CertificateConverter()
          .setProvider(CryptoProviders.BC)
          .getCertificate(builder.build(signer));
    } catch (CertIOException | OperatorCreationException e) {
      throw new GeneralSecurityException("Zertifikat für " + commonName + " nicht erzeugbar", e);
    }
  }

  record Issued(KeyPair keys, X509Certificate certificate) {}
}

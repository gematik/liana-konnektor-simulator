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
import de.gematik.liana.kern.signature.RevocationSource;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Duration;
import java.util.Date;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.isismtt.ISISMTTObjectIdentifiers;
import org.bouncycastle.asn1.isismtt.ocsp.CertHash;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * {@link RevocationSource} as a simulator (decision-021): LIANA answers every request itself with
 * status good, producedAt and thisUpdate equal to the system time. CertID per RFC 6960 with SHA-1
 * over the issuer DN and the certificate's AuthorityKeyIdentifier as issuerKeyHash, plus CertHash
 * (Common PKI, SHA-256 over the certificate), which TUC_PKI_006 checks. The signer is an ECDSA key
 * generated at startup (P-256, TEST-ONLY), not a key of a test suite; the query per TUC_PKI_006
 * comes with LIANA-87.
 */
public final class SimulatedOcsp implements RevocationSource {

  private static final X500Name SIGNER_NAME =
      new X500Name("CN=LIANA OCSP-Signer TEST-ONLY,O=LIANA NOT-VALID,C=DE");

  private final Clock clock;
  private final KeyPair keys;
  private final X509CertificateHolder signer;

  public SimulatedOcsp(Clock clock) {
    this.clock = clock;
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", CryptoProviders.BC);
      generator.initialize(new ECGenParameterSpec("secp256r1"));
      keys = generator.generateKeyPair();
      signer =
          new JcaX509v3CertificateBuilder(
                  SIGNER_NAME,
                  BigInteger.ONE,
                  Date.from(clock.instant().minus(Duration.ofDays(1))),
                  Date.from(clock.instant().plus(Duration.ofDays(3650))),
                  SIGNER_NAME,
                  keys.getPublic())
              .addExtension(
                  Extension.extendedKeyUsage,
                  false,
                  new ExtendedKeyUsage(KeyPurposeId.id_kp_OCSPSigning))
              .build(contentSigner());
    } catch (GeneralSecurityException | IOException | OperatorCreationException e) {
      throw new IllegalStateException("OCSP-Signer des Simulators: " + e.getMessage(), e);
    }
  }

  /** The signer certificate with which the responses are signed. */
  public X509CertificateHolder signer() {
    return signer;
  }

  @Override
  public Answer status(byte[] certificate) {
    try {
      X509CertificateHolder ee = new X509CertificateHolder(certificate);
      AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.fromExtensions(ee.getExtensions());
      if (aki == null || aki.getKeyIdentifierOctets() == null) {
        throw ConnectorError.INTERNAL.exception(
            "OCSP-Simulator: Zertifikat ohne AuthorityKeyIdentifier " + ee.getSubject());
      }
      CertificateID id =
          new CertificateID(
              new CertID(
                  new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1),
                  new DEROctetString(digest("SHA-1", ee.getIssuer().getEncoded())),
                  new DEROctetString(aki.getKeyIdentifierOctets()),
                  new ASN1Integer(ee.getSerialNumber())));
      Date now = Date.from(clock.instant());
      Extensions certHash =
          new Extensions(
              new Extension(
                  ISISMTTObjectIdentifiers.id_isismtt_at_certHash,
                  false,
                  new CertHash(
                          new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256),
                          digest("SHA-256", certificate))
                      .getEncoded()));
      BasicOCSPResp basic =
          new BasicOCSPRespBuilder(new RespID(SIGNER_NAME))
              .addResponse(id, CertificateStatus.GOOD, now, null, certHash)
              .build(contentSigner(), new X509CertificateHolder[] {signer}, now);
      return new Answer(
          new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basic).getEncoded(), Status.GOOD);
    } catch (IOException | OCSPException | OperatorCreationException | GeneralSecurityException e) {
      throw ConnectorError.INTERNAL.exception("OCSP-Simulator: " + e.getMessage()).causedBy(e);
    }
  }

  private ContentSigner contentSigner() throws OperatorCreationException {
    return new JcaContentSignerBuilder("SHA256withECDSA")
        .setProvider(CryptoProviders.BC)
        .build(keys.getPrivate());
  }

  private static byte[] digest(String algorithm, byte[] data) throws GeneralSecurityException {
    return MessageDigest.getInstance(algorithm).digest(data);
  }
}

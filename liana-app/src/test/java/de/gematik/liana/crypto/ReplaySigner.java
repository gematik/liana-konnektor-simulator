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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.isismtt.ISISMTTObjectIdentifiers;
import org.bouncycastle.asn1.isismtt.x509.AdmissionSyntax;
import org.bouncycastle.asn1.isismtt.x509.Admissions;
import org.bouncycastle.asn1.isismtt.x509.ProfessionInfo;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Signs SignedScenarios for tests: with the replay signer from {@code support/pki/replay/} or with
 * a signer issued by the replay CA according to a {@link Profile}. LIANA imports the replay CA in
 * the test profile ({@code liana.pki.imported-cas}).
 */
public final class ReplaySigner {

  private static final Path DIR = Path.of("support/pki/replay");
  public static final String OID_POPP_TOKEN = "1.2.276.0.76.4.320";
  public static final String OID_FD_OSIG = "1.2.276.0.76.4.283";

  /**
   * Headers of the PoPP service besides {@code typ}, {@code alg} and {@code x5c}
   * (SignedScenarioHeaders). {@code stpl} is a placeholder: LIANA does not check the OCSP status of
   * the signer (LIANA-49).
   */
  public static final Map<String, String> HEADERS = Map.of("stpl", "TUlBPQ==");

  private ReplaySigner() {}

  /** A signer: key and certificate for x5c. */
  public record Signer(PrivateKey key, X509Certificate certificate) {}

  /**
   * Certificate profile of a signer. {@link #poppService()} is the profile of the PoPP service
   * (C.ZD.SIG, oid_popp); the {@code with…} methods deviate from it in exactly one attribute.
   */
  public record Profile(
      String role,
      String policy,
      int keyUsage,
      Instant notBefore,
      Instant notAfter,
      Issuer issuer) {

    public static Profile poppService() {
      Instant now = Instant.now();
      return new Profile(
          ScenarioSignerCheck.OID_POPP,
          ScenarioSignerCheck.OID_ZD_SIG,
          KeyUsage.nonRepudiation,
          now.minus(Duration.ofDays(1)),
          now.plus(Duration.ofDays(365)),
          Issuer.REPLAY_CA);
    }

    public Profile withRole(String oid) {
      return new Profile(oid, policy, keyUsage, notBefore, notAfter, issuer);
    }

    public Profile withPolicy(String oid) {
      return new Profile(role, oid, keyUsage, notBefore, notAfter, issuer);
    }

    public Profile withKeyUsage(int usage) {
      return new Profile(role, policy, usage, notBefore, notAfter, issuer);
    }

    public Profile expiredAt(Instant end) {
      return new Profile(role, policy, keyUsage, end.minus(Duration.ofDays(365)), end, issuer);
    }

    public Profile issuedBy(Issuer by) {
      return new Profile(role, policy, keyUsage, notBefore, notAfter, by);
    }
  }

  /** Who issues the signer certificate. */
  public enum Issuer {
    /** the replay CA ({@code support/pki/replay/replay-ca.*}) */
    REPLAY_CA,
    /** name of the replay CA, but a foreign key: the certificate signature does not match */
    FOREIGN_KEY,
    /** a CA that is neither in the TSL nor imported */
    UNKNOWN_CA
  }

  /** JWS Compact over {@code {"message": <message>}}, x5c = replay signer. */
  public static String sign(String messageJson) throws GeneralSecurityException, IOException {
    return sign(signer(), messageJson);
  }

  /** JWS Compact over {@code {"message": <message>}}, x5c = {@code signer}. */
  public static String sign(Signer signer, String messageJson) throws GeneralSecurityException {
    return signPayload(signer, HEADERS, "{\"message\":" + messageJson + "}");
  }

  /**
   * JWS Compact over {@code payloadJson} with exactly {@code headers} besides {@code alg} and
   * {@code x5c}.
   */
  public static String signPayload(Signer signer, Map<String, String> headers, String payloadJson)
      throws GeneralSecurityException {
    provider();
    return EcJws.sign(
        payloadJson.getBytes(StandardCharsets.UTF_8),
        signer.key(),
        List.of(signer.certificate()),
        headers);
  }

  /** The replay signer from {@code support/pki/replay/popp-signer.*}. */
  public static Signer signer() throws GeneralSecurityException, IOException {
    return new Signer(key("popp-signer.key.pem"), certificate("popp-signer.pem"));
  }

  /** A new signer according to {@code profile}. */
  public static Signer issue(Profile profile) throws GeneralSecurityException, IOException {
    provider();
    KeyPair keys = SelfTestPki.ecKeyPair(SelfTestPki.NIST_P256);
    X509Certificate ca = certificate("replay-ca.pem");
    X500Name issuerName =
        profile.issuer() == Issuer.UNKNOWN_CA
            ? new X500Name("CN=Unbekannte CA TEST-ONLY,O=LIANA NOT-VALID,C=DE")
            : X500Name.getInstance(ca.getSubjectX500Principal().getEncoded());
    PrivateKey caKey =
        profile.issuer() == Issuer.REPLAY_CA
            ? key("replay-ca.key.pem")
            : SelfTestPki.ecKeyPair(SelfTestPki.NIST_P256).getPrivate();
    X500Name subject = new X500Name("CN=LIANA Test-Signer TEST-ONLY,O=LIANA NOT-VALID,C=DE");
    try {
      var extensions = new JcaX509ExtensionUtils();
      var builder =
          new JcaX509v3CertificateBuilder(
                  issuerName,
                  new BigInteger(64, new SecureRandom()),
                  Date.from(profile.notBefore()),
                  Date.from(profile.notAfter()),
                  subject,
                  keys.getPublic())
              .addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
              .addExtension(Extension.keyUsage, true, new KeyUsage(profile.keyUsage()))
              .addExtension(
                  Extension.certificatePolicies,
                  false,
                  new CertificatePolicies(
                      new PolicyInformation(new ASN1ObjectIdentifier(profile.policy()))))
              .addExtension(
                  ISISMTTObjectIdentifiers.id_isismtt_at_admission,
                  false,
                  new AdmissionSyntax(
                      null,
                      new DERSequence(
                          new Admissions(
                              null,
                              null,
                              new ProfessionInfo[] {
                                new ProfessionInfo(
                                    null,
                                    new DirectoryString[] {new DirectoryString("Test-Rolle")},
                                    new ASN1ObjectIdentifier[] {
                                      new ASN1ObjectIdentifier(profile.role())
                                    },
                                    null,
                                    null)
                              }))));
      if (profile.issuer() == Issuer.REPLAY_CA) {
        builder.addExtension(
            Extension.authorityKeyIdentifier, false, extensions.createAuthorityKeyIdentifier(ca));
      }
      var contentSigner =
          new JcaContentSignerBuilder("SHA256withECDSA")
              .setProvider(CryptoProviders.BC)
              .build(caKey);
      return new Signer(
          keys.getPrivate(),
          new JcaX509CertificateConverter()
              .setProvider(CryptoProviders.BC)
              .getCertificate(builder.build(contentSigner)));
    } catch (CertIOException | OperatorCreationException e) {
      throw new GeneralSecurityException("Test-Signer nicht erzeugbar", e);
    }
  }

  private static void provider() {
    if (Security.getProvider(CryptoProviders.BC) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  private static PrivateKey key(String file) throws GeneralSecurityException, IOException {
    return KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(pem(file)));
  }

  static X509Certificate certificate(String file) throws GeneralSecurityException, IOException {
    return (X509Certificate)
        CertificateFactory.getInstance("X.509")
            .generateCertificate(new ByteArrayInputStream(pem(file)));
  }

  private static byte[] pem(String file) throws IOException {
    String base64 = Files.readString(DIR.resolve(file)).replaceAll("-----[A-Z ]+-----|\\s", "");
    return Base64.getDecoder().decode(base64);
  }
}

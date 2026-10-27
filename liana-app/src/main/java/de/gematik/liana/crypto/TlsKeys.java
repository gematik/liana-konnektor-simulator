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
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * TLS keys and certificates generated and imported by the Konnektor for connecting the client
 * systems (LIANA-65): Clientsystem certificates (TIP1-A_4517-04) and server certificate
 * (A_21697-01).
 *
 * <p>A_21811-05, TAB_KON_866: only RSA-3072 and ECC-256 with a NIST curve may be newly generated or
 * imported; RSA-2048 and brainpoolP256r1 MUST NOT be newly created, but remain usable where they
 * already exist (ID.AK.AUT, boot certificates from the YAML). The key in the certificate is
 * checked, not the file name or the caller's statement. LIANA allows RSA above 3072 bits
 * (gemSpec_Krypt only sets a minimum length for RSA, TAB_KON_866 footnote). Self-generated
 * certificates are valid for 5 years (A_24483).
 */
public final class TlsKeys {

  /** Algorithms that can be generated per TAB_KON_866. */
  public enum Algorithm {
    RSA_3072,
    ECC_NIST_P256
  }

  /** Violates A_21811-05 / TAB_KON_866 or is not a readable certificate. */
  public static final class RejectedKeyException extends Exception {
    public RejectedKeyException(String message) {
      super(message);
    }

    public RejectedKeyException(String message, Throwable cause) {
      super(message, cause);
    }
  }

  static final Duration VALIDITY = Duration.ofDays(1826);

  private static final String PEM_BEGIN = "-----BEGIN CERTIFICATE-----";
  private static final String PEM_END = "-----END CERTIFICATE-----";

  private TlsKeys() {}

  /**
   * A_21811-05: may a key with this public part be newly generated or imported?
   *
   * @throws RejectedKeyException RSA below 3072 bits, brainpoolP256r1 or a curve outside
   *     TAB_KON_866
   */
  public static void checkNew(PublicKey key) throws RejectedKeyException {
    if (key instanceof RSAPublicKey rsa) {
      int bits = rsa.getModulus().bitLength();
      if (bits < 3072) {
        throw new RejectedKeyException(
            "RSA-"
                + bits
                + " darf nicht erzeugt oder importiert werden "
                + "(A_21811-05, TAB_KON_866: RSA-3072 oder ECC-256 NIST)");
      }
      return;
    }
    if ("EC".equals(key.getAlgorithm()) || "ECDSA".equals(key.getAlgorithm())) {
      ASN1ObjectIdentifier curve = curve(key);
      if (SECObjectIdentifiers.secp256r1.equals(curve)) {
        return;
      }
      String name =
          TeleTrusTObjectIdentifiers.brainpoolP256r1.equals(curve)
              ? "brainpoolP256r1"
              : String.valueOf(curve);
      throw new RejectedKeyException(
          "ECC-Kurve "
              + name
              + " darf nicht erzeugt oder importiert werden "
              + "(A_21811-05, TAB_KON_866: nur ECC-256 mit NIST-Kurve P-256)");
    }
    throw new RejectedKeyException(
        "Schlüsselalgorithmus " + key.getAlgorithm() + " nicht in TAB_KON_866 (A_21811-05)");
  }

  private static ASN1ObjectIdentifier curve(PublicKey key) throws RejectedKeyException {
    try {
      var parameters =
          SubjectPublicKeyInfo.getInstance(key.getEncoded()).getAlgorithm().getParameters();
      return ASN1ObjectIdentifier.getInstance(parameters);
    } catch (IllegalArgumentException e) {
      throw new RejectedKeyException("ECC-Schlüssel ohne benannte Kurve (A_21811-05)", e);
    }
  }

  public static KeyPair generate(Algorithm algorithm) throws GeneralSecurityException {
    KeyPairGenerator generator;
    if (algorithm == Algorithm.RSA_3072) {
      generator = KeyPairGenerator.getInstance("RSA", CryptoProviders.BC);
      generator.initialize(
          new RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4), new SecureRandom());
    } else {
      generator = KeyPairGenerator.getInstance("EC", CryptoProviders.BC);
      generator.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
    }
    return generator.generateKeyPair();
  }

  /**
   * Self-signed certificate, 5 years (A_24483), KeyUsage digitalSignature (RSA additionally
   * keyEncipherment), EKU {@code purpose}, SAN from {@code dnsNames}.
   */
  public static X509Certificate selfSigned(
      KeyPair keys, String commonName, List<String> dnsNames, KeyPurposeId purpose)
      throws GeneralSecurityException {
    try {
      X500Name subject =
          new X500Name(
              "CN=" + commonName.replaceAll("[,+=\"\\\\<>;]", "_") + ",O=LIANA NOT-VALID,C=DE");
      Instant now = Instant.now();
      var builder =
          new JcaX509v3CertificateBuilder(
              subject,
              new BigInteger(64, new SecureRandom()),
              Date.from(now.minus(Duration.ofMinutes(5))),
              Date.from(now.plus(VALIDITY)),
              subject,
              keys.getPublic());
      boolean rsa = keys.getPublic() instanceof RSAPublicKey;
      builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
      builder.addExtension(
          Extension.keyUsage,
          true,
          new KeyUsage(
              rsa
                  ? KeyUsage.digitalSignature | KeyUsage.keyEncipherment
                  : KeyUsage.digitalSignature));
      builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(purpose));
      if (!dnsNames.isEmpty()) {
        builder.addExtension(
            Extension.subjectAlternativeName,
            false,
            new GeneralNames(
                dnsNames.stream()
                    .map(name -> new GeneralName(GeneralName.dNSName, name))
                    .toArray(GeneralName[]::new)));
      }
      var signer =
          new JcaContentSignerBuilder(rsa ? "SHA256withRSA" : "SHA256withECDSA")
              .setProvider(CryptoProviders.BC)
              .build(keys.getPrivate());
      return new JcaX509CertificateConverter()
          .setProvider(CryptoProviders.BC)
          .getCertificate(builder.build(signer));
    } catch (OperatorCreationException | IOException e) {
      throw new GeneralSecurityException("Zertifikat nicht erzeugbar", e);
    }
  }

  /**
   * PKCS#12 as export format (TIP1-A_4517-04), keys and certificates encrypted with PBE-SHA1-3DES:
   * readable by the JDK's KeyStore, BouncyCastle and openssl 3 without the legacy provider (BC does
   * not read the JDK's PBES2).
   */
  public static byte[] pkcs12(
      PrivateKey key, List<X509Certificate> chain, String alias, String password)
      throws GeneralSecurityException {
    try {
      KeyStore store = KeyStore.getInstance("PKCS12-3DES-3DES", CryptoProviders.BC);
      store.load(null, null);
      store.setKeyEntry(alias, key, password.toCharArray(), chain.toArray(Certificate[]::new));
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      store.store(out, password.toCharArray());
      return out.toByteArray();
    } catch (IOException e) {
      throw new GeneralSecurityException("PKCS#12 nicht schreibbar", e);
    }
  }

  /**
   * Certificate from an upload: DER or PEM, also with preamble as openssl writes it on export
   * ({@code Bag Attributes …}).
   */
  public static X509Certificate certificate(byte[] content) throws RejectedKeyException {
    byte[] der = content;
    String text = new String(content, StandardCharsets.ISO_8859_1);
    int begin = text.indexOf(PEM_BEGIN);
    if (begin >= 0) {
      int end = text.indexOf(PEM_END, begin);
      if (end < 0) {
        throw new RejectedKeyException("PEM-Zertifikat ohne Ende");
      }
      try {
        der = Base64.getMimeDecoder().decode(text.substring(begin + PEM_BEGIN.length(), end));
      } catch (IllegalArgumentException e) {
        throw new RejectedKeyException("PEM-Zertifikat nicht lesbar", e);
      }
    }
    try {
      return (X509Certificate)
          CertificateFactory.getInstance("X.509")
              .generateCertificate(new ByteArrayInputStream(der));
    } catch (GeneralSecurityException e) {
      throw new RejectedKeyException("kein X.509-Zertifikat (PEM oder DER erwartet)", e);
    }
  }

  /**
   * OID name of the curve or RSA with length, for display (TAB_KON_506-01: algorithm recognizable).
   */
  public static String describe(PublicKey key) {
    if (key instanceof RSAPublicKey rsa) {
      return "RSA-" + rsa.getModulus().bitLength();
    }
    try {
      ASN1ObjectIdentifier curve = curve(key);
      if (SECObjectIdentifiers.secp256r1.equals(curve)) {
        return "ECC-256 NIST P-256";
      }
      if (TeleTrusTObjectIdentifiers.brainpoolP256r1.equals(curve)) {
        return "ECC-256 brainpoolP256r1";
      }
      return "ECC " + curve;
    } catch (RejectedKeyException e) {
      return key.getAlgorithm();
    }
  }
}

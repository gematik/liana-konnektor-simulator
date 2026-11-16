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

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.isismtt.ISISMTTObjectIdentifiers;
import org.bouncycastle.asn1.isismtt.x509.AdmissionSyntax;
import org.bouncycastle.asn1.isismtt.x509.Admissions;
import org.bouncycastle.asn1.isismtt.x509.ProfessionInfo;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Test PKCS#12 like the gematik test SMC-B (LIANA-220): self-signed C.HCI.AUT with Admission and
 * Telematik-ID. BC writes certificates with PBEWithSHAAnd40BitRC2-CBC and keys with
 * PBEWithSHAAnd3-KeyTripleDES-CBC, the legacy PBE of {@code smcb_private.p12}.
 */
public final class TestP12 {

  /** professionOID Betriebsstätte Arzt (gemSpec_OID). */
  static final String OID_PRAXIS_ARZT = "1.2.276.0.76.4.50";

  static {
    if (Security.getProvider(CryptoProviders.BC) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  private TestP12() {}

  /** brainpoolP256r1 key with Telematik-ID {@code telematikId}, {@code null} without Admission. */
  public static Path write(Path file, String password, String telematikId) throws Exception {
    return write(file, password, telematikId, "brainpoolP256r1", null);
  }

  /**
   * {@code curve} of the key; {@code foreignKey} instead of the key that belongs to the
   * certificate.
   */
  static Path write(
      Path file, String password, String telematikId, String curve, PrivateKey foreignKey)
      throws Exception {
    return write(file, password, telematikId, curve, foreignKey, P12Cards.OID_SMC_B_AUT);
  }

  /** {@code policy} in CertificatePolicies, {@code null} without the extension. */
  static Path write(
      Path file,
      String password,
      String telematikId,
      String curve,
      PrivateKey foreignKey,
      String policy)
      throws Exception {
    KeyPair pair = keyPair(curve);
    X509Certificate certificate = certificate(pair, telematikId, policy);
    KeyStore store = KeyStore.getInstance("PKCS12", CryptoProviders.BC);
    store.load(null, null);
    store.setKeyEntry(
        "alias",
        foreignKey != null ? foreignKey : pair.getPrivate(),
        password.toCharArray(),
        new Certificate[] {certificate});
    Files.createDirectories(file.getParent());
    try (OutputStream out = Files.newOutputStream(file)) {
      store.store(out, password.toCharArray());
    }
    return file;
  }

  static KeyPair keyPair(String curve) throws GeneralSecurityException {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", CryptoProviders.BC);
    generator.initialize(new ECGenParameterSpec(curve));
    return generator.generateKeyPair();
  }

  /** The certificate of the first key entry. */
  public static X509Certificate certificate(Path p12, String password) throws Exception {
    KeyStore store = KeyStore.getInstance("PKCS12", CryptoProviders.BC);
    try (var in = Files.newInputStream(p12)) {
      store.load(in, password.toCharArray());
    }
    return (X509Certificate) store.getCertificate(store.aliases().nextElement());
  }

  private static X509Certificate certificate(KeyPair pair, String telematikId, String policy)
      throws IOException, OperatorCreationException, GeneralSecurityException {
    X500Name subject = new X500Name("CN=Praxis LIANA-220 TEST-ONLY, C=DE");
    Instant now = Instant.now();
    JcaX509v3CertificateBuilder builder =
        new JcaX509v3CertificateBuilder(
            subject,
            BigInteger.valueOf(now.toEpochMilli()),
            Date.from(now.minus(1, ChronoUnit.DAYS)),
            Date.from(now.plus(365, ChronoUnit.DAYS)),
            subject,
            pair.getPublic());
    if (policy != null) {
      builder.addExtension(
          Extension.certificatePolicies,
          false,
          new CertificatePolicies(new PolicyInformation(new ASN1ObjectIdentifier(policy))));
    }
    if (telematikId != null) {
      ProfessionInfo info =
          new ProfessionInfo(
              null,
              new DirectoryString[] {new DirectoryString("Betriebsstätte Arzt")},
              new ASN1ObjectIdentifier[] {new ASN1ObjectIdentifier(OID_PRAXIS_ARZT)},
              telematikId,
              null);
      builder.addExtension(
          ISISMTTObjectIdentifiers.id_isismtt_at_admission,
          false,
          new AdmissionSyntax(
              null, new DERSequence(new Admissions(null, null, new ProfessionInfo[] {info}))));
    }
    return new JcaX509CertificateConverter()
        .setProvider(CryptoProviders.BC)
        .getCertificate(
            builder.build(
                new JcaContentSignerBuilder("SHA256withECDSA")
                    .setProvider(CryptoProviders.BC)
                    .build(pair.getPrivate())));
  }
}

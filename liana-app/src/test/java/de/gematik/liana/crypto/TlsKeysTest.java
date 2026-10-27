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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class TlsKeysTest {

  @BeforeAll
  static void providers() {
    if (Security.getProvider(CryptoProviders.BC) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  static KeyPair rsa(int bits) throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(bits);
    return generator.generateKeyPair();
  }

  static KeyPair ec(String curve) throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", CryptoProviders.BC);
    generator.initialize(new ECGenParameterSpec(curve));
    return generator.generateKeyPair();
  }

  static X509Certificate certificate(KeyPair keys) throws Exception {
    return TlsKeys.selfSigned(keys, "test", List.of(), KeyPurposeId.id_kp_clientAuth);
  }

  @Test
  @DisplayName(
      "A_21811-05 TAB_KON_866: RSA-3072 und ECC-256 NIST dürfen erzeugt und importiert werden")
  void allowed() throws Exception {
    assertDoesNotThrow(
        () -> TlsKeys.checkNew(TlsKeys.generate(TlsKeys.Algorithm.RSA_3072).getPublic()));
    assertDoesNotThrow(
        () -> TlsKeys.checkNew(TlsKeys.generate(TlsKeys.Algorithm.ECC_NIST_P256).getPublic()));
    assertDoesNotThrow(() -> TlsKeys.checkNew(ec("secp256r1").getPublic()));
  }

  @Test
  @DisplayName("A_21811-05 TAB_KON_866: RSA-2048 darf nicht erzeugt oder importiert werden")
  void rsa2048Rejected() throws Exception {
    var e =
        assertThrows(
            TlsKeys.RejectedKeyException.class, () -> TlsKeys.checkNew(rsa(2048).getPublic()));
    assertTrue(e.getMessage().contains("RSA-2048"), e.getMessage());
  }

  @Test
  @DisplayName(
      "A_21811-05 TAB_KON_866: ECC-256 mit brainpool-Kurve darf nicht erzeugt oder importiert werden")
  void brainpoolRejected() throws Exception {
    var e =
        assertThrows(
            TlsKeys.RejectedKeyException.class,
            () -> TlsKeys.checkNew(ec("brainpoolP256r1").getPublic()));
    assertTrue(e.getMessage().contains("brainpoolP256r1"), e.getMessage());
  }

  @Test
  @DisplayName("A_21811-05: Kurven außerhalb TAB_KON_866 (P-384) werden abgelehnt")
  void otherCurveRejected() throws Exception {
    assertThrows(
        TlsKeys.RejectedKeyException.class, () -> TlsKeys.checkNew(ec("secp384r1").getPublic()));
  }

  @Test
  @DisplayName(
      "A_24483: selbst erzeugte TLS-Zertifikate laufen 5 Jahre; RSA ohne Länge ist RSA-3072")
  void validity() throws Exception {
    X509Certificate certificate = certificate(TlsKeys.generate(TlsKeys.Algorithm.RSA_3072));
    Duration validity =
        Duration.between(
            certificate.getNotBefore().toInstant(), certificate.getNotAfter().toInstant());
    assertEquals(1826, validity.toDays());
    assertEquals("RSA-3072", TlsKeys.describe(certificate.getPublicKey()));
  }

  @Test
  @DisplayName(
      "TIP1-A_4517-04: Export als PKCS#12, lesbar mit dem KeyStore des JDK und dem gewählten Passwort")
  void pkcs12() throws Exception {
    KeyPair keys = TlsKeys.generate(TlsKeys.Algorithm.ECC_NIST_P256);
    X509Certificate certificate = certificate(keys);
    byte[] p12 = TlsKeys.pkcs12(keys.getPrivate(), List.of(certificate), "C1", "geheim-123");
    KeyStore store = KeyStore.getInstance("PKCS12");
    store.load(new ByteArrayInputStream(p12), "geheim-123".toCharArray());
    assertEquals(certificate, store.getCertificate("c1"));
    assertTrue(store.isKeyEntry("c1"));
  }

  @Test
  @DisplayName("Import: DER, PEM und PEM mit Vortext („Bag Attributes“ wie openssl pkcs12 -nokeys)")
  void parse() throws Exception {
    X509Certificate certificate = certificate(ec("secp256r1"));
    String pem =
        "-----BEGIN CERTIFICATE-----\n"
            + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(certificate.getEncoded())
            + "\n-----END CERTIFICATE-----\n";
    assertEquals(certificate, TlsKeys.certificate(certificate.getEncoded()));
    assertEquals(certificate, TlsKeys.certificate(pem.getBytes(StandardCharsets.US_ASCII)));
    String bag =
        "Bag Attributes\n    localKeyID: 01 02\nsubject=CN = test\nissuer=CN = test\n" + pem;
    assertEquals(certificate, TlsKeys.certificate(bag.getBytes(StandardCharsets.US_ASCII)));
    assertThrows(
        TlsKeys.RejectedKeyException.class,
        () -> TlsKeys.certificate("kein Zertifikat".getBytes()));
  }
}

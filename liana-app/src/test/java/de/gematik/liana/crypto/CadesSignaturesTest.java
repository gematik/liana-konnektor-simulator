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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.kern.signature.CmsSignatures;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class CadesSignaturesTest {

  @BeforeAll
  static void bouncyCastle() {
    if (Security.getProvider(CryptoProviders.BC) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  @Test
  @DisplayName(
      "A_17768-01 TAB_KON_900 RSA-Zertifikat (HBA G2.0): SignerInfo mit RSASSA-PSS, SHA-256, MGF1-SHA-256, "
          + "Salt 32; den Wert über den Hash der signierten Attribute liefert die Karte (signPSS, G2_N088.600.a)")
  void rsaPss() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    KeyPair pair = generator.generateKeyPair();
    Instant now = Instant.parse("2026-10-20T08:00:00Z");
    X509CertificateHolder certificate =
        new JcaX509v3CertificateBuilder(
                new X500Name("CN=HBA G2.0 TEST-ONLY"),
                BigInteger.ONE,
                Date.from(now.minusSeconds(3600)),
                Date.from(now.plusSeconds(3600)),
                new X500Name("CN=HBA G2.0 TEST-ONLY"),
                pair.getPublic())
            .build(new JcaContentSignerBuilder("SHA256withRSA").build(pair.getPrivate()));
    byte[] content = "Hallo LIANA".getBytes(StandardCharsets.UTF_8);

    byte[] der =
        new CadesSignatures(Clock.fixed(now, java.time.ZoneOffset.UTC))
            .sign(
                new CmsSignatures.Request(
                    content, true, certificate.getEncoded(), "shortText", null),
                hash -> {
                  try {
                    // like the card: RSASSA-PSS over the given hash
                    Signature card =
                        Signature.getInstance("NONEwithRSASSA-PSS", CryptoProviders.BC);
                    card.setParameter(
                        new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
                    card.initSign(pair.getPrivate());
                    card.update(hash);
                    return card.sign();
                  } catch (Exception e) {
                    throw new IllegalStateException(e);
                  }
                });

    CMSSignedData cms = new CMSSignedData(der);
    SignerInformation signer = cms.getSignerInfos().getSigners().iterator().next();
    assertEquals(PKCSObjectIdentifiers.id_RSASSA_PSS.getId(), signer.getEncryptionAlgOID());
    assertEquals(
        32,
        RSASSAPSSparams.getInstance(signer.getEncryptionAlgParams()).getSaltLength().intValue());
    assertTrue(
        signer.verify(
            new JcaSimpleSignerInfoVerifierBuilder()
                .setProvider(CryptoProviders.BC)
                .build(certificate)));
  }
}

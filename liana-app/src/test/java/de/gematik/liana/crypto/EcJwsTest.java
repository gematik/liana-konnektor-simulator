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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import de.gematik.liana.crypto.SelfTestPki.Issued;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.Base64;
import java.util.List;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class EcJwsTest {

  private static final byte[] PAYLOAD = "{\"sub\":\"x\"}".getBytes(StandardCharsets.UTF_8);

  private static Issued root;
  private static Issued subCa;
  private static Issued signer;

  @BeforeAll
  static void pki() throws GeneralSecurityException {
    if (Security.getProvider(CryptoProviders.BC) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
    root = SelfTestPki.ca("Root", SelfTestPki.BRAINPOOL_P256R1, null);
    subCa = SelfTestPki.ca("Sub", SelfTestPki.BRAINPOOL_P256R1, root);
    signer = SelfTestPki.endEntity("Signer", SelfTestPki.NIST_P256, subCa);
  }

  private static String jws() throws GeneralSecurityException {
    return EcJws.sign(
        PAYLOAD, signer.keys().getPrivate(), List.of(signer.certificate(), subCa.certificate()));
  }

  @Test
  @DisplayName("Signiertes JWS ist gegen die Root verifizierbar")
  void roundTrip() throws GeneralSecurityException {
    assertArrayEquals(PAYLOAD, EcJws.verify(jws(), root.certificate()));
  }

  @Test
  @DisplayName("Veränderter Payload wird abgelehnt")
  void tamperedPayload() throws GeneralSecurityException {
    String[] parts = jws().split("\\.");
    String forged =
        parts[0]
            + "."
            + Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString("{\"sub\":\"y\"}".getBytes(StandardCharsets.UTF_8))
            + "."
            + parts[2];
    assertThrows(GeneralSecurityException.class, () -> EcJws.verify(forged, root.certificate()));
  }

  @Test
  @DisplayName("Kette ohne Sub-CA erreicht die Root nicht")
  void incompleteChain() throws GeneralSecurityException {
    String token = EcJws.sign(PAYLOAD, signer.keys().getPrivate(), List.of(signer.certificate()));
    assertThrows(GeneralSecurityException.class, () -> EcJws.verify(token, root.certificate()));
  }

  @Test
  @DisplayName("Brainpool-Signer ist kein ES256")
  void brainpoolSignerRejected() throws GeneralSecurityException {
    Issued bpSigner = SelfTestPki.endEntity("BP", SelfTestPki.BRAINPOOL_P256R1, subCa);
    String token =
        EcJws.sign(
            PAYLOAD,
            bpSigner.keys().getPrivate(),
            List.of(bpSigner.certificate(), subCa.certificate()));
    assertThrows(GeneralSecurityException.class, () -> EcJws.verify(token, root.certificate()));
  }
}

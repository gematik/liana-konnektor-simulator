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
package de.gematik.liana.tls;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.TestPorts;
import de.gematik.liana.TlsProbe;
import de.gematik.liana.crypto.CryptoProviders;
import io.quarkus.test.junit.QuarkusIntegrationTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import java.io.IOException;
import java.nio.file.Path;
import java.security.Security;
import java.util.Map;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Konnektor TLS from the native image (prod profile, TLS port from TestPorts) with ID.AK.AUT
 * brainpoolP256r1 and client auth: Brainpool ECDSA and ECDHE via BCJSSE in the image; runs with
 * {@code ./mvnw verify -Dnative}.
 */
@QuarkusIntegrationTest
@TestProfile(KonnektorTlsIT.Brainpool.class)
class KonnektorTlsIT {

  public static class Brainpool implements QuarkusTestProfile {
    @Override
    public Map<String, String> getConfigOverrides() {
      return TestPorts.config(
          "liana.infrastructure.konnektor.gsmc-k.ak-aut",
          "./support/pki/server/ak-aut-bp256.p12",
          "liana.tls.client-auth",
          "true");
    }
  }

  @BeforeAll
  static void bc() {
    if (Security.getProvider(CryptoProviders.BC) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  @Test
  @DisplayName(
      "GS-A_5345-04 TIP1-A_4516: connector.sds über TLS 1.2, ECDHE brainpoolP256r1, ID.AK.AUT bp256, CS1-Zertifikat")
  void brainpoolMutualTls() throws Exception {
    TlsProbe.Result result =
        TlsProbe.bc()
            .namedGroups("brainpoolP256r1")
            .clientCertificate(Path.of("support/pki/clients/cs1-bp256.p12"))
            .get(TestPorts.TLS, "/connector.sds");
    assertEquals(200, result.status());
    assertEquals("TLSv1.2", result.session().getProtocol());
    assertTrue(
        result.serverCertificate().getSubjectX500Principal().getName().contains("ID.AK.AUT bp256"));
    assertThrows(IOException.class, () -> TlsProbe.bc().get(TestPorts.TLS, "/connector.sds"));
  }
}

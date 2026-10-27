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
package de.gematik.liana.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

import de.gematik.liana.TestPorts;
import de.gematik.liana.admin.AdminServer;
import de.gematik.liana.konnektor.Credentials;
import de.gematik.liana.konnektor.KonConfig;
import de.gematik.liana.konnektor.Konnektor;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import java.io.IOException;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * LIANA-133 AC 1 and AC 4: Konnektor client against LIANA with ID.AK.AUT brainpoolP256r1 and client
 * auth (ANCL_CAUT_MANDATORY, TIP1-A_4516): {@code .kon} export with {@code pkcs12} (CS1
 * brainpoolP256r1) and {@code trustStore}, TLS 1.2 with ECDHE over brainpoolP256r1 (GS-A_5345-04).
 */
@QuarkusTest
@TestProfile(KonnektorClientTlsTest.BrainpoolMutualTls.class)
class KonnektorClientTlsTest {

  public static class BrainpoolMutualTls implements QuarkusTestProfile {
    @Override
    public Map<String, String> getConfigOverrides() {
      return TestPorts.config(
          "liana.infrastructure.konnektor.gsmc-k.ak-aut", "./support/pki/server/ak-aut-bp256.p12",
          "liana.tls.url", "https://localhost:" + TestPorts.TLS,
          "liana.tls.client-auth", "true",
          "liana.kon-export.url", "https://localhost:" + TestPorts.TLS + "/",
          "liana.kon-export.credentials.type", "pkcs12",
          "liana.kon-export.credentials.username", "",
          "liana.kon-export.credentials.keystore", "./support/pki/clients/cs1-bp256.p12",
          "liana.kon-export.credentials.password", "liana");
    }
  }

  @Inject AdminServer admin;

  @Test
  @DisplayName(
      "config.kon (pkcs12, trustStore) → connector.sds und GetCards über mTLS mit brainpoolP256r1")
  void brainpoolMutualTls() throws Exception {
    KonConfig kon = KonnektorClientTest.export(admin.port());
    assertInstanceOf(Credentials.Pkcs12.class, kon.credentials());
    try (Konnektor konnektor = Konnektor.builder().kon(kon).build()) {
      assertEquals(true, konnektor.serviceDirectory().clientAuthMandatory());
      assertEquals("OK", KonnektorClientTest.getCards(konnektor).getStatus().getResult());
    }
  }

  @Test
  @DisplayName("Ohne Client-Zertifikat lehnt LIANA die Verbindung ab")
  void ohneClientZertifikat() throws Exception {
    KonConfig kon = KonnektorClientTest.export(admin.port());
    try (Konnektor konnektor = Konnektor.builder().kon(kon).auth(Credentials.none()).build()) {
      assertThrows(IOException.class, konnektor::serviceDirectory);
    }
  }
}

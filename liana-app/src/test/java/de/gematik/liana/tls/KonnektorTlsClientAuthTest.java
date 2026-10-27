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

import de.gematik.liana.TlsProbe;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.path.xml.XmlPath;
import jakarta.inject.Inject;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * HTTPS port with ANCL_CAUT_MANDATORY Enabled (CERTIFICATE) and ID.AK.AUT brainpoolP256r1,
 * ANCL_CCERT_LIST from the YAML (CS1 P-256 and brainpoolP256r1).
 */
@QuarkusTest
@TestProfile(KonnektorTlsClientAuthTest.ClientAuth.class)
class KonnektorTlsClientAuthTest {

  public static class ClientAuth implements QuarkusTestProfile {
    @Override
    public Map<String, String> getConfigOverrides() {
      return Map.of(
          "liana.tls.client-auth",
          "true",
          "liana.infrastructure.konnektor.gsmc-k.ak-aut",
          "./support/pki/server/ak-aut-bp256.p12");
    }
  }

  static final Path CLIENTS = Path.of("support/pki/clients");

  @Inject KonnektorTlsServer tls;

  @Test
  @DisplayName(
      "TIP1-A_4516: Clientsystem mit Zertifikat aus ANCL_CCERT_LIST ruft connector.sds und SOAP über TLS auf")
  void accepted() throws Exception {
    TlsProbe probe = TlsProbe.bc().clientCertificate(CLIENTS.resolve("cs1-bp256.p12"));
    TlsProbe.Result sds = probe.get(tls.port(), "/connector.sds");
    assertEquals(200, sds.status());
    assertEquals("true", new XmlPath(sds.body()).getString("ConnectorServices.ClientAutMandatory"));
    assertEquals(
        200,
        TlsProbe.bc()
            .clientCertificate(CLIENTS.resolve("cs1-p256.p12"))
            .soap(
                tls.port(),
                "/ws/EventService",
                KonnektorTlsServerTest.GET_CARDS_ACTION,
                KonnektorTlsServerTest.GET_CARDS)
            .status());
  }

  @Test
  @DisplayName(
      "TIP1-A_4516: ohne Client-Zertifikat oder mit fremdem Zertifikat lehnt LIANA den Verbindungsaufbau ab")
  void rejected() {
    assertThrows(IOException.class, () -> TlsProbe.bc().get(tls.port(), "/connector.sds"));
    assertThrows(
        IOException.class,
        () ->
            TlsProbe.bc()
                .clientCertificate(Path.of("support/pki/server/ak-aut-p256.p12"))
                .get(tls.port(), "/connector.sds"));
  }
}

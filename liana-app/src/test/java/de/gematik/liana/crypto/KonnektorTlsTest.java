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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.TlsProbe;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServer;
import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.List;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * TLS building block of the Konnektor interface and the KMS ({@link KonnektorTls}) against a bare
 * Vert.x server, with the test PKI from {@code support/pki/} ({@code tools/pki/konnektor-tls.sh}).
 */
class KonnektorTlsTest {

  static final Path SERVER = Path.of("support/pki/server");
  static final Path CLIENTS = Path.of("support/pki/clients");

  private static Vertx vertx;
  private HttpServer server;

  @BeforeAll
  static void providers() {
    if (Security.getProvider(CryptoProviders.BC) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
    vertx = Vertx.vertx();
  }

  @AfterAll
  static void closeVertx() {
    vertx.close();
  }

  @AfterEach
  void stop() {
    if (server != null) {
      server.close();
    }
  }

  private int start(String identity, boolean clientAuth) throws Exception {
    TlsIdentity id = TlsIdentity.load(SERVER.resolve(identity), TlsProbe.PASSWORD);
    ClientCertificateList clients =
        clientAuth
            ? ClientCertificateList.load(
                List.of(CLIENTS.resolve("cs1-p256.pem"), CLIENTS.resolve("cs1-bp256.pem")))
            : null;
    server =
        vertx
            .createHttpServer(KonnektorTls.serverOptions(id, clients))
            .requestHandler(request -> request.response().end("ok"))
            .listen(0)
            .toCompletionStage()
            .toCompletableFuture()
            .get();
    return server.actualPort();
  }

  @Test
  @DisplayName(
      "TIP1-A_4514-01 GS-A_4384-03: ID.AK.AUT P-256, TLS 1.2, ECDHE-ECDSA mit AES-GCM, Kette mit Komp-CA")
  void p256() throws Exception {
    int port = start("ak-aut-p256.p12", false);
    TlsProbe.Result result = TlsProbe.bc().get(port, "/");
    assertEquals(200, result.status());
    assertEquals("TLSv1.2", result.session().getProtocol());
    assertTrue(
        KonnektorTls.CIPHER_SUITES.subList(0, 2).contains(result.session().getCipherSuite()),
        result.session().getCipherSuite());
    assertEquals(2, result.session().getPeerCertificates().length);
    assertTrue(
        result.serverCertificate().getSubjectX500Principal().getName().contains("ID.AK.AUT p256"));
  }

  @Test
  @DisplayName("GS-A_5345-04: ID.AK.AUT brainpoolP256r1, ECDHE allein über brainpoolP256r1")
  void brainpool() throws Exception {
    int port = start("ak-aut-bp256.p12", false);
    TlsProbe.Result result = TlsProbe.bc().namedGroups("brainpoolP256r1").get(port, "/");
    assertEquals(200, result.status());
    assertTrue(
        result.serverCertificate().getSubjectX500Principal().getName().contains("ID.AK.AUT bp256"));
  }

  @Test
  @DisplayName("GS-A_5345-04: ECDHE über brainpoolP384r1, P-256 und P-384")
  void namedGroups() throws Exception {
    int port = start("ak-aut-p256.p12", false);
    for (String group : List.of("brainpoolP384r1", "secp256r1", "secp384r1")) {
      assertEquals(200, TlsProbe.bc().namedGroups(group).get(port, "/").status(), group);
    }
  }

  @Test
  @DisplayName("GS-A_4384-03: andere Kurven (x25519, secp521r1) werden nicht verwendet")
  void otherGroupsRejected() throws Exception {
    int port = start("ak-aut-p256.p12", false);
    assertThrows(IOException.class, () -> TlsProbe.bc().namedGroups("x25519").get(port, "/"));
    assertThrows(IOException.class, () -> TlsProbe.bc().namedGroups("secp521r1").get(port, "/"));
  }

  @Test
  @DisplayName(
      "GS-A_4385, A_18467: nur TLS 1.2, kein TLS 1.3 (TLS 1.1 und 1.0 bieten schon die Clients nicht mehr an)")
  void protocols() throws Exception {
    int port = start("ak-aut-p256.p12", false);
    assertThrows(IOException.class, () -> TlsProbe.bc().protocols("TLSv1.3").get(port, "/"));
  }

  @Test
  @DisplayName("Java-Clientsystem ohne BouncyCastle (SunJSSE) erreicht ID.AK.AUT P-256")
  void jdkClient() throws Exception {
    int port = start("ak-aut-p256.p12", false);
    TlsProbe.Result result = TlsProbe.jdk().get(port, "/");
    assertEquals(200, result.status());
    assertEquals("TLSv1.2", result.session().getProtocol());
  }

  @Test
  @DisplayName(
      "TIP1-A_4516: Client-Zertifikat aus ANCL_CCERT_LIST (P-256 und brainpoolP256r1) wird angenommen")
  void clientAuthAccepted() throws Exception {
    int port = start("ak-aut-bp256.p12", true);
    assertEquals(
        200,
        TlsProbe.bc().clientCertificate(CLIENTS.resolve("cs1-p256.p12")).get(port, "/").status());
    assertEquals(
        200,
        TlsProbe.bc().clientCertificate(CLIENTS.resolve("cs1-bp256.p12")).get(port, "/").status());
  }

  @Test
  @DisplayName(
      "TIP1-A_4516: ohne Client-Zertifikat oder mit einem nicht in ANCL_CCERT_LIST kein Verbindungsaufbau")
  void clientAuthRejected() throws Exception {
    int port = start("ak-aut-p256.p12", true);
    assertThrows(IOException.class, () -> TlsProbe.bc().get(port, "/"));
    // ID.AK.AUT as client: valid, issued by the component CA, but not in the list
    assertThrows(
        IOException.class,
        () -> TlsProbe.bc().clientCertificate(SERVER.resolve("ak-aut-bp256.p12")).get(port, "/"));
  }

  @Test
  @DisplayName("A_24484: Fingerprint des Serverzertifikats wie openssl x509 -fingerprint -sha256")
  void fingerprint() throws GeneralSecurityException, IOException {
    assertEquals(
        "5E:2B:4B:3E:80:5E:62:13:8E:37:3B:A7:80:70:DF:8E:93:41:23:29:27:D2:C1:67:B7:BA:8C:D5:5C:2E:4D:50",
        TlsIdentity.load(SERVER.resolve("ak-aut-p256.p12"), TlsProbe.PASSWORD).fingerprint());
  }
}

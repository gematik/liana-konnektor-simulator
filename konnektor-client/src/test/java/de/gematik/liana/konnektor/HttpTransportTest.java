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
package de.gematik.liana.konnektor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * LIANA-133 AC 4: the client's TLS 1.2 via BCJSSE against a test server with the ID.AK.AUT
 * identities from {@code support/pki/server}; {@code KonnektorClientTlsTest} in liana-app checks
 * against LIANA itself.
 */
class HttpTransportTest {

  private static byte[] sds() throws IOException {
    try (InputStream in = HttpTransportTest.class.getResourceAsStream("/sds/liana.xml")) {
      return in.readAllBytes();
    }
  }

  static X509Certificate certificate(Path pem) throws Exception {
    try (InputStream in = Files.newInputStream(pem)) {
      return (X509Certificate)
          CertificateFactory.getInstance("X.509", Bc.PROVIDER).generateCertificate(in);
    }
  }

  private static Konnektor konnektor(
      TlsServer server, String host, Trust trust, Credentials credentials) throws IOException {
    return Konnektor.builder()
        .url("https://" + host + ":" + server.port())
        .context("M1", "CS1", "WP1", null)
        .trust(trust)
        .auth(credentials)
        .build();
  }

  @ParameterizedTest(name = "{0} mit ECDHE {1}")
  @CsvSource({
    "ak-aut-bp256.p12, brainpoolP256r1",
    "ak-aut-bp256.p12, brainpoolP384r1",
    "ak-aut-p256.p12, secp256r1",
    "ak-aut-p256.p12, secp384r1",
    "ak-aut-rsa.p12, secp256r1",
    "ak-aut-rsa.p12, brainpoolP256r1"
  })
  @DisplayName(
      "GS-A_5345-04, GS-A_4384-03: TLS 1.2 mit ECDHE über P-256, P-384, brainpoolP256r1, brainpoolP384r1, "
          + "Serverzertifikat ECDSA (bp256, p256) oder RSA, Kette bis zur Komp-CA")
  void kurven(String identity, String group) throws Exception {
    try (TlsServer server = new TlsServer(identity, group, false, 200, sds());
        Konnektor kon =
            konnektor(
                server,
                "localhost",
                Trust.of(certificate(TlsServer.SERVER.resolve("komp-ca.pem"))),
                Credentials.none())) {
      assertEquals("LIANA", kon.serviceDirectory().product().vendorId());
      assertEquals(group, server.negotiatedGroup);
    }
  }

  @Test
  @DisplayName(
      "TIP1-A_4516: mTLS mit dem Client-Zertifikat aus PKCS#12 (brainpoolP256r1), Server verlangt es")
  void mutualTls() throws Exception {
    byte[] p12 = Files.readAllBytes(TlsServer.CLIENTS.resolve("cs1-bp256.p12"));
    try (TlsServer server = new TlsServer("ak-aut-bp256.p12", "brainpoolP256r1", true, 200, sds());
        Konnektor kon =
            konnektor(
                server,
                "localhost",
                Trust.of(certificate(TlsServer.SERVER.resolve("komp-ca.pem"))),
                Credentials.pkcs12(p12, TlsServer.PASSWORD))) {
      kon.serviceDirectory();
      assertEquals(
          certificate(TlsServer.CLIENTS.resolve("cs1-bp256.pem")), server.clientCertificate);
    }
    try (TlsServer server = new TlsServer("ak-aut-bp256.p12", "brainpoolP256r1", true, 200, sds());
        Konnektor kon =
            konnektor(
                server,
                "localhost",
                Trust.of(certificate(TlsServer.SERVER.resolve("komp-ca.pem"))),
                Credentials.none())) {
      assertThrows(IOException.class, kon::serviceDirectory, "ohne Client-Zertifikat");
    }
  }

  @Test
  @DisplayName(
      ".kon trustStore: Pin auf das Serverzertifikat; fremde CA, falscher Host und expectedHost")
  void trust() throws Exception {
    X509Certificate leaf = certificate(TlsServer.SERVER.resolve("ak-aut-p256.pem"));
    X509Certificate otherCa = certificate(TlsServer.SERVER.resolve("ak-aut-bp256.pem"));
    try (TlsServer server = new TlsServer("ak-aut-p256.p12", "secp256r1", false, 200, sds())) {
      try (Konnektor kon = konnektor(server, "localhost", Trust.of(leaf), Credentials.none())) {
        kon.serviceDirectory();
      }
      try (Konnektor kon = konnektor(server, "localhost", Trust.of(otherCa), Credentials.none())) {
        assertThrows(IOException.class, kon::serviceDirectory, "Kette endet nicht im Truststore");
      }
      // SAN: DNS:liana, DNS:localhost, IP:127.0.0.1
      try (Konnektor kon = konnektor(server, "127.0.0.1", Trust.of(leaf), Credentials.none())) {
        kon.serviceDirectory();
      }
      try (Konnektor kon =
          konnektor(
              server,
              "127.0.0.1",
              Trust.of(leaf).withExpectedHost("konnektor.example"),
              Credentials.none())) {
        assertThrows(IOException.class, kon::serviceDirectory, "expectedHost nicht im Zertifikat");
      }
      try (Konnektor kon =
          konnektor(
              server, "127.0.0.1", Trust.of(leaf).withExpectedHost("liana"), Credentials.none())) {
        kon.serviceDirectory();
      }
      try (Konnektor kon = konnektor(server, "localhost", Trust.insecure(), Credentials.none())) {
        kon.serviceDirectory();
      }
      try (Konnektor kon = konnektor(server, "localhost", Trust.system(), Credentials.none())) {
        assertThrows(IOException.class, kon::serviceDirectory, "Komp-CA nicht im JDK-Truststore");
      }
    }
  }

  @Test
  @DisplayName("LIANA-133 AC 4: der Client registriert keinen Security-Provider")
  void keinGlobalerProvider() throws Exception {
    List<Provider> before = Arrays.asList(Security.getProviders());
    try (TlsServer server =
            new TlsServer("ak-aut-bp256.p12", "brainpoolP256r1", false, 200, sds());
        Konnektor kon =
            konnektor(
                server,
                "localhost",
                Trust.of(certificate(TlsServer.SERVER.resolve("komp-ca.pem"))),
                Credentials.none())) {
      kon.serviceDirectory();
    }
    // Other tests in the same JVM (tiger-rbel) register BC themselves; this checks that the client
    // changes nothing,
    // and ArchUnit checks that it never registers (ClientArchitectureTest)
    assertEquals(before, Arrays.asList(Security.getProviders()));
  }

  @Test
  @DisplayName("LIANA-133 AC 3: Basic-Passwort steht weder in Meldungen noch in toString")
  void keineCredentialsInMeldungen() throws Exception {
    String secret = "geheim-4711";
    try (TlsServer server = new TlsServer("ak-aut-p256.p12", "secp256r1", false, 401, new byte[0]);
        Konnektor kon =
            konnektor(server, "localhost", Trust.insecure(), Credentials.basic("user", secret))) {
      IOException e = assertThrows(IOException.class, kon::serviceDirectory);
      assertFalse(e.getMessage().contains(secret), e.getMessage());
      assertTrue(e.getMessage().contains("HTTP 401"), e.getMessage());
      assertTrue(server.requests().get(0).contains("Authorization: Basic"), "Anmeldung gesendet");
    }
    assertFalse(Credentials.basic("user", secret).toString().contains(secret));
    assertFalse(
        Credentials.pkcs12(new byte[] {1, 2}, secret.toCharArray()).toString().contains(secret));
  }

  @Test
  @DisplayName("Falsches PKCS#12-Passwort: Meldung ohne Passwort")
  void falschesPkcs12Passwort() throws Exception {
    byte[] p12 = Files.readAllBytes(TlsServer.CLIENTS.resolve("cs1-bp256.p12"));
    IOException e =
        assertThrows(
            IOException.class,
            () ->
                Konnektor.builder()
                    .url("https://localhost:1")
                    .context("M1", "CS1", "WP1", null)
                    .auth(Credentials.pkcs12(p12, "falsch-123".toCharArray()))
                    .build());
    assertFalse(e.getMessage().contains("falsch-123"));
  }
}

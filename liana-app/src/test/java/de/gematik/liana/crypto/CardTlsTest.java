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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.crypto.SelfTestPki.Issued;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.time.Clock;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.CertificateRequest;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.ClientCertificateType;
import org.bouncycastle.tls.DefaultTlsServer;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsCredentialedSigner;
import org.bouncycastle.tls.TlsServerProtocol;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaDefaultTlsCredentialedSigner;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * TUC_KON_110 against a BC TLS server that requires a client certificate; the "card" is a software
 * key on brainpoolP256r1 like PrK.HCI.AUT.E256, which only signs hashes.
 */
class CardTlsTest {

  private final ServerSocket listener;
  private final Issued ca;
  private final Issued server;
  private final Issued smb;
  private final AtomicReference<byte[]> clientCertificate = new AtomicReference<>();
  private CompletableFuture<String> served;

  @BeforeAll
  static void provider() {
    if (Security.getProvider(CryptoProviders.BC) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  CardTlsTest() throws Exception {
    provider();
    listener = new ServerSocket(0);
    ca = SelfTestPki.ca("LIANA Test-CA", SelfTestPki.BRAINPOOL_P256R1, null);
    server = SelfTestPki.fdTlsS("ufs.test", SelfTestPki.BRAINPOOL_P256R1, ca);
    smb = SelfTestPki.endEntity("Praxis LIANA", SelfTestPki.BRAINPOOL_P256R1, ca);
  }

  @AfterEach
  void close() throws IOException {
    listener.close();
  }

  /**
   * A TLS 1.2 server with {@code identity} that requires the client certificate and sends back one
   * line.
   */
  private void serve(Issued identity) {
    served =
        CompletableFuture.supplyAsync(
            () -> {
              try (Socket socket = listener.accept()) {
                TlsServerProtocol protocol =
                    new TlsServerProtocol(socket.getInputStream(), socket.getOutputStream());
                JcaTlsCrypto crypto =
                    new JcaTlsCryptoProvider()
                        .setProvider(CryptoProviders.BC)
                        .create(new SecureRandom());
                protocol.accept(
                    new DefaultTlsServer(crypto) {
                      @Override
                      protected ProtocolVersion[] getSupportedVersions() {
                        return ProtocolVersion.TLSv12.only();
                      }

                      @Override
                      protected int[] getSupportedCipherSuites() {
                        return new int[] {CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256};
                      }

                      @Override
                      protected TlsCredentialedSigner getECDSASignerCredentials()
                          throws IOException {
                        return new JcaDefaultTlsCredentialedSigner(
                            new TlsCryptoParameters(context),
                            crypto,
                            identity.keys().getPrivate(),
                            chain(crypto, identity),
                            SignatureAndHashAlgorithm.getInstance(
                                HashAlgorithm.sha256, SignatureAlgorithm.ecdsa));
                      }

                      @Override
                      public CertificateRequest getCertificateRequest() {
                        return new CertificateRequest(
                            new short[] {ClientCertificateType.ecdsa_sign},
                            new java.util.Vector<>(
                                java.util.List.of(
                                    SignatureAndHashAlgorithm.getInstance(
                                        HashAlgorithm.sha256, SignatureAlgorithm.ecdsa))),
                            null);
                      }

                      @Override
                      public void notifyClientCertificate(Certificate certificate)
                          throws IOException {
                        clientCertificate.set(certificate.getCertificateAt(0).getEncoded());
                      }
                    });
                InputStream in = protocol.getInputStream();
                byte[] line = new byte[5];
                int n = in.readNBytes(line, 0, line.length);
                OutputStream out = protocol.getOutputStream();
                out.write(
                    ("pong:" + new String(line, 0, n, StandardCharsets.US_ASCII))
                        .getBytes(StandardCharsets.US_ASCII));
                out.flush();
                protocol.close();
                return "ok";
              } catch (IOException e) {
                return "Server: " + e;
              }
            });
  }

  private static Certificate chain(JcaTlsCrypto crypto, Issued identity) throws IOException {
    try {
      return new Certificate(
          new TlsCertificate[] {crypto.createCertificate(identity.certificate().getEncoded())});
    } catch (java.security.cert.CertificateEncodingException e) {
      throw new IOException(e);
    }
  }

  /** The "card": signs the given SHA-256 hash with NONEwithECDSA, result ECDSA-Sig-Value. */
  private CardTls.CardKey card() {
    return new CardTls.CardKey() {
      @Override
      public byte[] certificate() throws IOException {
        try {
          return smb.certificate().getEncoded();
        } catch (java.security.cert.CertificateEncodingException e) {
          throw new IOException(e);
        }
      }

      @Override
      public byte[] sign(byte[] sha256) throws IOException {
        assertEquals(32, sha256.length);
        try {
          Signature signature = Signature.getInstance("NONEwithECDSA", CryptoProviders.BC);
          signature.initSign(smb.keys().getPrivate());
          signature.update(sha256);
          return signature.sign();
        } catch (GeneralSecurityException e) {
          throw new IOException(e);
        }
      }
    };
  }

  private CardTls tls(Issued trusted) {
    return new CardTls(
        certificate ->
            certificate
                    .getIssuerX500Principal()
                    .equals(trusted.certificate().getSubjectX500Principal())
                ? Optional.of(trusted.certificate())
                : Optional.empty(),
        Clock.systemUTC());
  }

  @Test
  @DisplayName(
      "TIP1-A_4720-03 Schritt 2a/2c: C.FD.TLS-S gegen den Vertrauensraum, Clientauthentisierung mit "
          + "C.HCI.AUT und der Signatur der Karte (brainpoolP256r1); Daten über TLS")
  void beidseitig() throws Exception {
    serve(server);

    try (Socket socket =
        tls(ca).connect("127.0.0.1", listener.getLocalPort(), card(), Duration.ofSeconds(5))) {
      socket.getOutputStream().write("ping!".getBytes(StandardCharsets.US_ASCII));
      socket.getOutputStream().flush();
      assertEquals(
          "pong:ping!",
          new String(socket.getInputStream().readNBytes(10), StandardCharsets.US_ASCII));
    }
    assertEquals("ok", served.get(5, TimeUnit.SECONDS));
    assertArrayEquals(smb.certificate().getEncoded(), clientCertificate.get());
  }

  @Test
  @DisplayName("TIP1-A_4720-03 Schritt 2a: Aussteller nicht im Vertrauensraum → 4156")
  void serverNichtVertraut() throws Exception {
    serve(server);
    Issued other = SelfTestPki.ca("Fremde CA", SelfTestPki.BRAINPOOL_P256R1, null);

    var e =
        assertThrows(
            CardTls.TlsException.class,
            () ->
                tls(other)
                    .connect("127.0.0.1", listener.getLocalPort(), card(), Duration.ofSeconds(5)));
    assertEquals(4156, e.code());
    assertTrue(e.getMessage().contains("C.FD.TLS-S"), e.getMessage());
  }

  @Test
  @DisplayName("TIP1-A_4720-03 Schritt 2a: Serverzertifikat ohne oid_fd_tls_s → 4156")
  void ohneZertifikatstyp() throws Exception {
    serve(SelfTestPki.endEntity("kein-fd", SelfTestPki.BRAINPOOL_P256R1, ca));

    var e =
        assertThrows(
            CardTls.TlsException.class,
            () ->
                tls(ca)
                    .connect("127.0.0.1", listener.getLocalPort(), card(), Duration.ofSeconds(5)));
    assertEquals(4156, e.code());
  }

  @Test
  @DisplayName("TIP1-A_4720-03 Schritt 2c: Karte signiert nicht (PIN.SMC nicht verifiziert) → 4157")
  void karteSigniertNicht() throws Exception {
    serve(server);
    CardTls.CardKey locked =
        new CardTls.CardKey() {
          @Override
          public byte[] certificate() throws IOException {
            return card().certificate();
          }

          @Override
          public byte[] sign(byte[] sha256) throws IOException {
            throw new IOException("4085 PIN.SMC nicht verifiziert");
          }
        };

    var e =
        assertThrows(
            CardTls.TlsException.class,
            () ->
                tls(ca)
                    .connect("127.0.0.1", listener.getLocalPort(), locked, Duration.ofSeconds(5)));
    assertEquals(4157, e.code());
    assertTrue(e.getMessage().contains("PIN.SMC"), e.getMessage());
  }
}

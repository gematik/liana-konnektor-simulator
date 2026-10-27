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

import de.gematik.liana.adapter.sicct.SicctConnection;
import de.gematik.liana.adapter.sicct.SicctEnvelope;
import de.gematik.liana.crypto.SelfTestPki.Issued;
import io.quarkus.runtime.annotations.RegisterForReflection;
import jakarta.enterprise.context.ApplicationScoped;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import org.bouncycastle.jsse.BCSSLParameters;
import org.bouncycastle.jsse.BCSSLSocket;

/**
 * Crypto self-test (LIANA-4): proves that BC and BCJSSE in the running artifact – in particular in
 * the native image – master the TI algorithms. Each check generates its own keys ({@link
 * SelfTestPki}). Triggered via the admin API {@code GET /admin/selftest/crypto/{check}} on the
 * management port (LIANA-149, before that on the Konnektor port).
 */
@ApplicationScoped
public class CryptoSelfTest {

  /** A_17124-03 no. 2: mandatory cipher suites for TLS with ECC. */
  static final String[] TLS_CIPHER_SUITES = {
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
  };

  @SuppressWarnings("java:S2068") // in-memory keystore of the self-test, never stored
  private static final char[] KEYSTORE_PASSWORD = "selftest".toCharArray();

  private static final int TLS_TIMEOUT_MILLIS = 10_000;

  /** Result of a check; registered for Jackson in the native image (admin API, LIANA-149). */
  @RegisterForReflection
  public record Result(String check, boolean ok, String detail) {}

  /** The checks that {@link #run(String)} knows. */
  public static final List<String> CHECKS =
      List.of("brainpool-ecdsa", "es256-jws", "brainpool-tls12", "sicct-tls");

  /** Runs the check {@code check} ({@link #CHECKS}); empty if it does not exist. */
  public Optional<Result> run(String check) {
    return Optional.ofNullable(
        switch (check) {
          case "brainpool-ecdsa" -> brainpoolEcdsa();
          case "es256-jws" -> es256Jws();
          case "brainpool-tls12" -> brainpoolTls12();
          case "sicct-tls" -> sicctTls();
          default -> null;
        });
  }

  /**
   * A_17207: sign and verify ECDSA on brainpoolP256r1 with SHA-256, counter-check with modified
   * text.
   */
  public Result brainpoolEcdsa() {
    return run(
        "brainpool-ecdsa",
        () -> {
          var keys = SelfTestPki.ecKeyPair(SelfTestPki.BRAINPOOL_P256R1);
          byte[] data = "LIANA brainpoolP256r1".getBytes(StandardCharsets.UTF_8);

          Signature signer = Signature.getInstance("SHA256withECDSA", CryptoProviders.BC);
          signer.initSign(keys.getPrivate());
          signer.update(data);
          byte[] sig = signer.sign();

          Signature verifier = Signature.getInstance("SHA256withECDSA", CryptoProviders.BC);
          verifier.initVerify(keys.getPublic());
          verifier.update(data);
          if (!verifier.verify(sig)) {
            throw new GeneralSecurityException("Signatur nicht verifizierbar");
          }
          verifier.initVerify(keys.getPublic());
          verifier.update("manipuliert".getBytes(StandardCharsets.UTF_8));
          if (verifier.verify(sig)) {
            throw new GeneralSecurityException("Signatur über fremde Daten akzeptiert");
          }
          return "SHA256withECDSA/brainpoolP256r1, Signatur "
              + sig.length
              + " Byte DER, Gegenprobe abgelehnt";
        });
  }

  /**
   * ES256 JWS with x5c chain as used by the PoPP service: root and sub-CA on brainpoolP256r1,
   * signer on P-256. The root is the trust anchor and is not in x5c.
   */
  public Result es256Jws() {
    return run(
        "es256-jws",
        () -> {
          Issued root = SelfTestPki.ca("LIANA Root", SelfTestPki.BRAINPOOL_P256R1, null);
          Issued subCa = SelfTestPki.ca("LIANA Sub-CA", SelfTestPki.BRAINPOOL_P256R1, root);
          Issued signer = SelfTestPki.endEntity("LIANA PoPP-Signer", SelfTestPki.NIST_P256, subCa);
          byte[] payload = "{\"sub\":\"liana-selftest\"}".getBytes(StandardCharsets.UTF_8);

          String jws =
              EcJws.sign(
                  payload,
                  signer.keys().getPrivate(),
                  List.of(signer.certificate(), subCa.certificate()));
          byte[] verified = EcJws.verify(jws, root.certificate());
          if (!Arrays.equals(payload, verified)) {
            throw new GeneralSecurityException("Payload nach Prüfung verändert");
          }

          Issued foreignRoot = SelfTestPki.ca("Fremde Root", SelfTestPki.BRAINPOOL_P256R1, null);
          try {
            EcJws.verify(jws, foreignRoot.certificate());
            throw new GeneralSecurityException("Kette gegen fremden Vertrauensanker akzeptiert");
          } catch (SignatureException expected) {
            // counter-check passed
          }
          return "ES256, x5c mit 2 Zertifikaten (P-256 <- brainpoolP256r1), Gegenprobe fremde Root abgelehnt";
        });
  }

  /**
   * A_17124-03 / A_17094-02: TLS 1.2 with mutual authentication via brainpoolP256r1 certificates
   * and exclusively brainpoolP256r1 in the ephemeral ECDH. Server and client run in the same
   * process on loopback.
   */
  public Result brainpoolTls12() {
    return run(
        "brainpool-tls12",
        () -> {
          Issued ca = SelfTestPki.ca("LIANA TLS-CA", SelfTestPki.BRAINPOOL_P256R1, null);
          Issued server = SelfTestPki.endEntity("liana-server", SelfTestPki.BRAINPOOL_P256R1, ca);
          Issued client = SelfTestPki.endEntity("liana-client", SelfTestPki.BRAINPOOL_P256R1, ca);
          SSLContext serverContext = tlsContext(server, ca);
          SSLContext clientContext = tlsContext(client, ca);

          try (var serverSocket =
              (SSLServerSocket)
                  serverContext
                      .getServerSocketFactory()
                      .createServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            serverSocket.setSoTimeout(TLS_TIMEOUT_MILLIS);
            CompletableFuture<SSLSession> serverSide =
                CompletableFuture.supplyAsync(
                    () -> {
                      try (var socket = (SSLSocket) serverSocket.accept()) {
                        configure(socket);
                        socket.setNeedClientAuth(true);
                        var in =
                            new BufferedReader(
                                new InputStreamReader(
                                    socket.getInputStream(), StandardCharsets.UTF_8));
                        var out =
                            new PrintWriter(socket.getOutputStream(), true, StandardCharsets.UTF_8);
                        out.println("echo:" + in.readLine());
                        return socket.getSession();
                      } catch (IOException e) {
                        throw new IllegalStateException("TLS-Server: " + e.getMessage(), e);
                      }
                    });

            try (var socket =
                (SSLSocket)
                    clientContext
                        .getSocketFactory()
                        .createSocket(
                            InetAddress.getLoopbackAddress(), serverSocket.getLocalPort())) {
              socket.setSoTimeout(TLS_TIMEOUT_MILLIS);
              configure(socket);
              socket.startHandshake();
              var out = new PrintWriter(socket.getOutputStream(), true, StandardCharsets.UTF_8);
              var in =
                  new BufferedReader(
                      new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
              out.println("ping");
              String reply = in.readLine();
              if (!"echo:ping".equals(reply)) {
                throw new GeneralSecurityException("unerwartete Antwort: " + reply);
              }
              SSLSession clientSession = socket.getSession();
              SSLSession serverSession = serverSide.get(TLS_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
              return clientSession.getProtocol()
                  + " "
                  + clientSession.getCipherSuite()
                  + ", ECDHE brainpoolP256r1, Server "
                  + peer(clientSession)
                  + ", Client "
                  + peer(serverSession);
            } catch (IOException e) {
              // The client only sees the alert; the cause is on the server side.
              throw new IOException(
                  "TLS-Client: " + e.getMessage() + "; " + serverFailure(serverSide), e);
            }
          }
        });
  }

  /**
   * LIANA-75: TLS client to the eHealth KT ({@link KtTls} with ID.SAK.AUT and {@link
   * SmktCertificateCheck}) and SICCT connection in the running artifact. A test KT in the same
   * process (BCJSSE server, brainpoolP256r1, certificate with oid_smkt_aut and serverAuth) answers
   * INIT CT SESSION; counter-check: a KT certificate without oid_smkt_aut aborts the handshake
   * (TUC_KON_050 step 3).
   */
  public Result sicctTls() {
    return run(
        "sicct-tls",
        () -> {
          Issued ca = SelfTestPki.ca("LIANA Komp-CA", SelfTestPki.BRAINPOOL_P256R1, null);
          Issued kt = SelfTestPki.smktAut("LIANA KT", SelfTestPki.BRAINPOOL_P256R1, ca);
          Issued foreignKt =
              SelfTestPki.endEntity("LIANA Fremd-KT", SelfTestPki.BRAINPOOL_P256R1, ca);
          Issued sak = SelfTestPki.endEntity("LIANA ID.SAK.AUT", SelfTestPki.BRAINPOOL_P256R1, ca);
          KtTls client =
              new KtTls(
                  new TlsIdentity(
                      sak.keys().getPrivate(), List.of(sak.certificate(), ca.certificate())),
                  new SmktCertificateCheck(
                      certificate -> Optional.of(ca.certificate()), Clock.systemUTC()));
          Duration timeout = Duration.ofMillis(TLS_TIMEOUT_MILLIS);

          String answer;
          try (var server = ktServer(kt, ca)) {
            try (var connection =
                new SicctConnection(
                    "KT-SELFTEST",
                    "localhost",
                    client.connect("127.0.0.1", server.getLocalPort(), timeout),
                    event -> {},
                    (ctId, host, reason) -> {})) {
              answer =
                  HexFormat.of()
                      .withUpperCase()
                      .formatHex(
                          connection.transmit(
                              SicctEnvelope.FU_TERMINAL,
                              new byte[] {(byte) 0x80, 0x28, 0x00, 0x00},
                              timeout));
            }
          }
          if (!answer.endsWith("9000")) {
            throw new GeneralSecurityException("INIT CT SESSION beantwortet mit " + answer);
          }
          try (var server = ktServer(foreignKt, ca)) {
            try (var socket = client.connect("127.0.0.1", server.getLocalPort(), timeout)) {
              throw new GeneralSecurityException("KT-Zertifikat ohne oid_smkt_aut akzeptiert");
            } catch (IOException expected) {
              // counter-check passed
            }
          }
          return "TLS 1.2 brainpoolP256r1 mit ID.SAK.AUT, C.SMKT.AUT geprüft, INIT CT SESSION → "
              + answer
              + ", Gegenprobe ohne oid_smkt_aut abgelehnt";
        });
  }

  /**
   * Test KT on loopback: accepts a TLS connection and answers every C command with its R command
   * (abCmd {@code 9000}).
   */
  @SuppressWarnings("java:S2095") // the server socket is returned to the caller, who closes it
  private static SSLServerSocket ktServer(Issued identity, Issued ca) throws Exception {
    var server =
        (SSLServerSocket)
            tlsContext(identity, ca)
                .getServerSocketFactory()
                .createServerSocket(0, 1, InetAddress.getLoopbackAddress());
    server.setSoTimeout(TLS_TIMEOUT_MILLIS);
    Thread thread =
        new Thread(
            () -> {
              try (var socket = (SSLSocket) server.accept()) {
                configure(socket);
                for (SicctEnvelope command;
                    (command = SicctEnvelope.read(socket.getInputStream())) != null; ) {
                  socket
                      .getOutputStream()
                      .write(
                          new SicctEnvelope(
                                  SicctEnvelope.Type.R_COMMAND,
                                  command.fu(),
                                  command.seq(),
                                  new byte[] {(byte) 0x90, 0x00})
                              .encode());
                  socket.getOutputStream().flush();
                }
              } catch (IOException e) {
                // handshake rejected or connection closed: end of the test KT
              }
            },
            "liana-selftest-kt");
    thread.setDaemon(true);
    thread.start();
    return server;
  }

  @SuppressWarnings(
      "java:S6437") // in-memory keystore of the self-test with a generated test key, no secret
  private static SSLContext tlsContext(Issued identity, Issued ca) throws Exception {
    KeyStore keyStore = KeyStore.getInstance("PKCS12", CryptoProviders.BC);
    keyStore.load(null, null);
    keyStore.setKeyEntry(
        "identity",
        identity.keys().getPrivate(),
        KEYSTORE_PASSWORD,
        new Certificate[] {identity.certificate(), ca.certificate()});
    KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX", CryptoProviders.tls());
    kmf.init(keyStore, KEYSTORE_PASSWORD);

    KeyStore trustStore = KeyStore.getInstance("PKCS12", CryptoProviders.BC);
    trustStore.load(null, null);
    trustStore.setCertificateEntry("ca", ca.certificate());
    TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX", CryptoProviders.tls());
    tmf.init(trustStore);

    SSLContext context = SSLContext.getInstance("TLSv1.2", CryptoProviders.tls());
    context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
    return context;
  }

  private static void configure(SSLSocket socket) {
    socket.setEnabledProtocols(new String[] {"TLSv1.2"});
    socket.setEnabledCipherSuites(TLS_CIPHER_SUITES);
    // Groups are only available via the BCJSSE API; the JDK API only offers the global
    // jdk.tls.namedGroups.
    var bcSocket = (BCSSLSocket) socket;
    BCSSLParameters parameters = bcSocket.getParameters();
    parameters.setNamedGroups(new String[] {SelfTestPki.BRAINPOOL_P256R1});
    bcSocket.setParameters(parameters);
  }

  private static String serverFailure(CompletableFuture<SSLSession> serverSide) {
    try {
      serverSide.get(TLS_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
      return "Server ohne Fehler";
    } catch (ExecutionException e) {
      Throwable cause = e.getCause().getCause() != null ? e.getCause().getCause() : e.getCause();
      return "Server: " + cause;
    } catch (InterruptedException | TimeoutException e) {
      return "Server: " + e;
    }
  }

  private static String peer(SSLSession session) throws IOException {
    Certificate[] chain = session.getPeerCertificates();
    return ((X509Certificate) chain[0]).getSubjectX500Principal().getName();
  }

  private static Result run(String check, Check body) {
    try {
      return new Result(check, true, body.run());
    } catch (Exception e) {
      Throwable cause = e.getCause() != null ? e.getCause() : e;
      return new Result(
          check,
          false,
          e.getClass().getSimpleName()
              + ": "
              + e.getMessage()
              + (cause != e ? " (" + cause + ")" : ""));
    }
  }

  @FunctionalInterface
  private interface Check {
    String run() throws Exception;
  }
}

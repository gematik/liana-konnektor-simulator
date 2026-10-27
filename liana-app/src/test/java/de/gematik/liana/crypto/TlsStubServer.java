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

import de.gematik.liana.crypto.SelfTestPki.Issued;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Vector;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.UnaryOperator;
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

/**
 * Fachdienst with HTTPS for tests of TUC_KON_110: TLS 1.2 via BC (brainpoolP256r1), identity
 * C.FD.TLS-S from a throwaway CA ({@link #writeCa}), requires a client certificate and answers one
 * HTTP request per connection with {@code handler} (request body → response body, HTTP 200).
 */
public final class TlsStubServer implements AutoCloseable {

  private final Issued ca;
  private final Issued identity;
  private final ServerSocket listener;
  private final UnaryOperator<String> handler;
  private final AtomicReference<byte[]> clientCertificate = new AtomicReference<>();
  private final List<String> requests = new java.util.concurrent.CopyOnWriteArrayList<>();

  private TlsStubServer(int port, UnaryOperator<String> handler)
      throws IOException, GeneralSecurityException {
    if (Security.getProvider(CryptoProviders.BC) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
    ca = SelfTestPki.ca("LIANA Test-CA Fachdienst", SelfTestPki.BRAINPOOL_P256R1, null);
    identity = SelfTestPki.fdTlsS("ufs.test", SelfTestPki.BRAINPOOL_P256R1, ca);
    listener = new ServerSocket(port, 50, InetAddress.getLoopbackAddress());
    this.handler = handler;
    Thread thread = new Thread(this::run, "tls-stub-" + listener.getLocalPort());
    thread.setDaemon(true);
    thread.start();
  }

  /** Listens on {@code port} (0: free) on the loopback address. */
  public static TlsStubServer start(int port, UnaryOperator<String> handler) {
    try {
      return new TlsStubServer(port, handler);
    } catch (IOException | GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  public int port() {
    return listener.getLocalPort();
  }

  /** Writes the CA certificate as PEM to {@code file}, e.g. for {@code liana.pki.imported-cas}. */
  public Path writeCa(Path file) {
    try {
      Files.writeString(
          file,
          "-----BEGIN CERTIFICATE-----\n"
              + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                  .encodeToString(ca.certificate().getEncoded())
              + "\n-----END CERTIFICATE-----\n");
      return file;
    } catch (IOException | CertificateEncodingException e) {
      throw new IllegalStateException(e);
    }
  }

  /** The client certificate of the last connection (DER). */
  public byte[] clientCertificate() {
    return clientCertificate.get();
  }

  /** Bodies of the requests so far. */
  public List<String> requests() {
    return requests;
  }

  private void run() {
    while (!listener.isClosed()) {
      try (Socket socket = listener.accept()) {
        serve(socket);
      } catch (IOException e) {
        // connection failed or server closed; continue with the next one
      }
    }
  }

  private void serve(Socket socket) throws IOException {
    socket.setSoTimeout(10_000);
    TlsServerProtocol protocol =
        new TlsServerProtocol(socket.getInputStream(), socket.getOutputStream());
    JcaTlsCrypto crypto =
        new JcaTlsCryptoProvider().setProvider(CryptoProviders.BC).create(new SecureRandom());
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
          protected TlsCredentialedSigner getECDSASignerCredentials() throws IOException {
            try {
              return new JcaDefaultTlsCredentialedSigner(
                  new TlsCryptoParameters(context),
                  crypto,
                  identity.keys().getPrivate(),
                  new Certificate(
                      new TlsCertificate[] {
                        crypto.createCertificate(identity.certificate().getEncoded())
                      }),
                  SignatureAndHashAlgorithm.getInstance(
                      HashAlgorithm.sha256, SignatureAlgorithm.ecdsa));
            } catch (CertificateEncodingException e) {
              throw new IOException(e);
            }
          }

          @Override
          public CertificateRequest getCertificateRequest() {
            return new CertificateRequest(
                new short[] {ClientCertificateType.ecdsa_sign},
                new Vector<>(
                    List.of(
                        SignatureAndHashAlgorithm.getInstance(
                            HashAlgorithm.sha256, SignatureAlgorithm.ecdsa))),
                null);
          }

          @Override
          public void notifyClientCertificate(Certificate certificate) throws IOException {
            if (certificate == null || certificate.isEmpty()) {
              throw new IOException("kein Client-Zertifikat");
            }
            clientCertificate.set(certificate.getCertificateAt(0).getEncoded());
          }
        });
    String request = readRequest(protocol.getInputStream());
    requests.add(request);
    byte[] body = handler.apply(request).getBytes(StandardCharsets.UTF_8);
    OutputStream out = protocol.getOutputStream();
    out.write(
        ("HTTP/1.1 200 OK\r\nContent-Type: text/xml; charset=utf-8\r\nContent-Length: "
                + body.length
                + "\r\nConnection: close\r\n\r\n")
            .getBytes(StandardCharsets.US_ASCII));
    out.write(body);
    out.flush();
    protocol.close();
  }

  /** Head up to the empty line, then Content-Length bytes of body. */
  private static String readRequest(InputStream in) throws IOException {
    ByteArrayOutputStream head = new ByteArrayOutputStream();
    while (!head.toString(StandardCharsets.ISO_8859_1).endsWith("\r\n\r\n")) {
      int b = in.read();
      if (b < 0) {
        throw new IOException("Anfrage unvollständig");
      }
      head.write(b);
    }
    int length = 0;
    for (String line : head.toString(StandardCharsets.ISO_8859_1).split("\r\n")) {
      if (line.toLowerCase(Locale.ROOT).startsWith("content-length:")) {
        length = Integer.parseInt(line.substring(15).trim());
      }
    }
    return new String(in.readNBytes(length), StandardCharsets.UTF_8);
  }

  @Override
  public void close() throws IOException {
    listener.close();
  }
}

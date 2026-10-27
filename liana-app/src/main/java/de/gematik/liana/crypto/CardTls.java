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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.util.Optional;
import java.util.Vector;
import java.util.function.Function;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.CertificateRequest;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.DefaultTlsClient;
import org.bouncycastle.tls.DefaultTlsCredentialedSigner;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.NameType;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.ServerName;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsAuthentication;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsCredentials;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsServerCertificate;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsSigner;
import org.bouncycastle.tls.crypto.TlsStreamSigner;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;

/**
 * TUC_KON_110 „Kartenbasierte TLS-Verbindung aufbauen“ (TIP1-A_4720-03) to a Fachdienst, here the
 * UFS ([gemSpec_FM_VSDM] Tab_FM_VSDM_15): TLS 1.2 via the BC TLS API, because the client key
 * resides on the card and the card computes the signature in the handshake.
 *
 * <ul>
 *   <li>Step 2: ECC cipher suites only (ECDHE-ECDSA with AES-GCM), because LIANA only uses the ECC
 *       identity of the SM-B; curves brainpoolP256r1/P384r1 and P-256/P-384 (GS-A_4384-03)
 *   <li>Step 2a: server certificate C.FD.TLS-S per TUC_KON_037 with {@code policyList =
 *       oid_fd_tls_s} against the Vertrauensraum (Vertrauensraum), without OCSP (LIANA has no TI
 *       connection); failed → 4156
 *   <li>Step 2c: client authentication with ID.HCI.AUT (C.HCI.AUT, ECDSA with SHA-256 on the SM-B),
 *       only towards an ECC server certificate; failed → 4157
 * </ul>
 *
 * <p>Not implemented: role check (step 2b, roleToMatch, not required for VSDM) and RSA (C.HCI.AUT
 * R2048).
 */
public final class CardTls {

  /** gemSpec_OID: certificate type C.FD.TLS-S. */
  static final String OID_FD_TLS_S = "1.2.276.0.76.4.169";

  private static final int[] CIPHER_SUITES = {
    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
  };
  private static final int[] GROUPS = {
    NamedGroup.brainpoolP256r1,
    NamedGroup.brainpoolP384r1,
    NamedGroup.secp256r1,
    NamedGroup.secp384r1,
  };

  /**
   * The card's identity: C.HCI.AUT (DER) and the signature of a SHA-256 hash (ECDSA-Sig-Value,
   * DER).
   */
  public interface CardKey {
    byte[] certificate() throws IOException;

    byte[] sign(byte[] sha256) throws IOException;
  }

  /** Server could not be authenticated (4156) or the card could not sign (4157). */
  public static final class TlsException extends IOException {

    private final int code;

    TlsException(int code, String message, Throwable cause) {
      super(code + " " + message, cause);
      this.code = code;
    }

    public int code() {
      return code;
    }
  }

  private final Function<X509Certificate, Optional<X509Certificate>> issuers;
  private final Clock clock;

  /**
   * @param issuers supplies the issuer certificate from the Vertrauensraum
   */
  public CardTls(Function<X509Certificate, Optional<X509Certificate>> issuers, Clock clock) {
    this.issuers = issuers;
    this.clock = clock;
  }

  /** Check against the Vertrauensraum made of the TSL and imported CAs. */
  public static CardTls of(TrustSpace trustSpace, Clock clock) {
    return new CardTls(
        certificate -> trustSpace.issuerOf(certificate).map(TrustSpace.Ca::certificate), clock);
  }

  /**
   * TCP and TLS to {@code host}:{@code port}, both within {@code timeout}. The returned socket
   * reads and writes via TLS; {@link Socket#setSoTimeout} applies to the TCP connection.
   */
  @SuppressWarnings("java:S2095") // the socket is returned to the caller and closed on failure
  public Socket connect(String host, int port, CardKey key, Duration timeout) throws IOException {
    Socket tcp = new Socket();
    try {
      int millis = Math.toIntExact(timeout.toMillis());
      tcp.connect(new InetSocketAddress(host, port), millis);
      tcp.setSoTimeout(millis);
      TlsClientProtocol protocol =
          new TlsClientProtocol(tcp.getInputStream(), tcp.getOutputStream());
      JcaTlsCrypto crypto =
          new JcaTlsCryptoProvider().setProvider(CryptoProviders.BC).create(new SecureRandom());
      Client client = new Client(crypto, host, key);
      try {
        protocol.connect(client);
      } catch (IOException e) {
        throw client.failure != null ? client.failure : e;
      }
      tcp.setSoTimeout(0);
      return new TlsSocket(tcp, protocol);
    } catch (IOException | RuntimeException e) {
      tcp.close();
      throw e;
    }
  }

  private final class Client extends DefaultTlsClient {

    private final String host;
    private final CardKey key;
    private TlsException failure;

    Client(JcaTlsCrypto crypto, String host, CardKey key) {
      super(crypto);
      this.host = host;
      this.key = key;
    }

    @Override
    protected ProtocolVersion[] getSupportedVersions() {
      return ProtocolVersion.TLSv12.only();
    }

    @Override
    protected int[] getSupportedCipherSuites() {
      return CIPHER_SUITES.clone();
    }

    @Override
    protected Vector<Integer> getSupportedGroups(Vector namedGroupRoles) {
      Vector<Integer> groups = new Vector<>();
      for (int group : GROUPS) {
        groups.add(group);
      }
      return groups;
    }

    @Override
    protected Vector<ServerName> getSNIServerNames() {
      if (host.chars().allMatch(c -> Character.isDigit(c) || c == '.' || c == ':')) {
        return null;
      }
      Vector<ServerName> names = new Vector<>();
      names.add(new ServerName(NameType.host_name, host.getBytes(StandardCharsets.US_ASCII)));
      return names;
    }

    @Override
    public TlsAuthentication getAuthentication() {
      return new TlsAuthentication() {
        @Override
        public void notifyServerCertificate(TlsServerCertificate serverCertificate)
            throws IOException {
          Certificate chain = serverCertificate.getCertificate();
          try {
            if (chain == null || chain.isEmpty()) {
              throw new CertificateException("Server ohne Zertifikat");
            }
            ServerCertificateCheck.check(
                x509(chain.getCertificateAt(0).getEncoded()),
                "C.FD.TLS-S",
                "oid_fd_tls_s",
                OID_FD_TLS_S,
                issuers,
                clock);
          } catch (CertificateException e) {
            failure =
                new TlsException(
                    4156,
                    "Server konnte bei TLS-Verbindungsaufbau nicht "
                        + "authentisiert werden: "
                        + e.getMessage(),
                    e);
            throw new TlsFatalAlert(AlertDescription.bad_certificate, e);
          }
        }

        @Override
        public TlsCredentials getClientCredentials(CertificateRequest request) throws IOException {
          try {
            TlsCertificate own = getCrypto().createCertificate(key.certificate());
            SignatureAndHashAlgorithm algorithm =
                SignatureAndHashAlgorithm.getInstance(
                    HashAlgorithm.sha256, SignatureAlgorithm.ecdsa);
            return new DefaultTlsCredentialedSigner(
                new TlsCryptoParameters(context),
                new CardSigner(key, this::fail),
                new Certificate(new TlsCertificate[] {own}),
                algorithm);
          } catch (IOException e) {
            throw fail(e);
          }
        }

        private TlsException fail(IOException e) {
          failure =
              new TlsException(
                  4157,
                  "Clientauthentisierung bei TLS-Verbindungsaufbau "
                      + "fehlgeschlagen: "
                      + e.getMessage(),
                  e);
          return failure;
        }
      };
    }
  }

  /** Signs the handshake hash on the card; TLS 1.2 with ECDSA passes SHA-256 over the messages. */
  private record CardSigner(CardKey key, Function<IOException, TlsException> fail)
      implements TlsSigner {

    @Override
    public byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash)
        throws IOException {
      if (algorithm != null
          && (algorithm.getHash() != HashAlgorithm.sha256
              || algorithm.getSignature() != SignatureAlgorithm.ecdsa)) {
        throw fail.apply(
            new IOException("Signaturverfahren " + algorithm + " nicht auf der Karte"));
      }
      try {
        return key.sign(hash);
      } catch (IOException e) {
        throw fail.apply(e);
      }
    }

    @Override
    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm algorithm) {
      return null;
    }
  }

  private static X509Certificate x509(byte[] der) throws CertificateException {
    try {
      return (X509Certificate)
          CertificateFactory.getInstance("X.509", CryptoProviders.BC)
              .generateCertificate(new ByteArrayInputStream(der));
    } catch (NoSuchProviderException e) {
      throw new CertificateException(e);
    }
  }

  /**
   * Socket that reads and writes via the TLS streams; timeouts and closing on the TCP connection.
   */
  private static final class TlsSocket extends Socket {

    private final Socket tcp;
    private final TlsClientProtocol protocol;

    TlsSocket(Socket tcp, TlsClientProtocol protocol) {
      this.tcp = tcp;
      this.protocol = protocol;
    }

    @Override
    public InputStream getInputStream() {
      return protocol.getInputStream();
    }

    @Override
    public OutputStream getOutputStream() {
      return protocol.getOutputStream();
    }

    @Override
    public synchronized void setSoTimeout(int timeout) throws SocketException {
      tcp.setSoTimeout(timeout);
    }

    @Override
    public synchronized void close() throws IOException {
      try {
        protocol.close();
      } finally {
        tcp.close();
      }
    }

    @Override
    public boolean isConnected() {
      return tcp.isConnected();
    }

    @Override
    public boolean isClosed() {
      return tcp.isClosed();
    }
  }
}

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

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import org.bouncycastle.jsse.BCSSLParameters;
import org.bouncycastle.jsse.BCSSLSocket;

/**
 * TLS client of the Konnektor to the Ereignissenke of a Clientsystem (TIP1-A_4595): the Konnektor
 * initiates TLS 1.2 per gemSpec_Krypt (cipher suites, groups and signature schemes as in {@link
 * KonnektorTls}) and authenticates with ID.AK.AUT (gSMC-K in the infrastructure object) if the
 * Clientsystem requests a certificate. LIANA does not check the certificate of the Ereignissenke:
 * TIP1-A_4595 requires no check, and the suites use their own test certificates (Konnektor QES:
 * {@code qes-testsuite.p12} at the Tiger proxy {@code cetpProxy}).
 */
public final class CetpTls {

  private final SSLContext context;
  private final Duration timeout;

  /**
   * @param akAut ID.AK.AUT of the Konnektor
   * @param timeout connection setup and handshake combined
   */
  public CetpTls(TlsIdentity akAut, Duration timeout) throws GeneralSecurityException {
    context = SSLContext.getInstance(KonnektorTls.PROTOCOL, CryptoProviders.tls());
    context.init(
        akAut.keyManagerFactory().getKeyManagers(),
        new TrustManager[] {new AnySink()},
        new SecureRandom());
    this.timeout = timeout;
  }

  /** TCP and TLS handshake to {@code host}:{@code port}; no read timeout afterwards. */
  @SuppressWarnings("java:S2095") // the socket is returned to the caller and closed on failure
  public Socket connect(String host, int port) throws IOException {
    int millis = Math.toIntExact(timeout.toMillis());
    Socket tcp = new Socket();
    try {
      tcp.connect(new InetSocketAddress(host, port), millis);
      SSLSocket tls = (SSLSocket) context.getSocketFactory().createSocket(tcp, host, port, true);
      tls.setUseClientMode(true);
      tls.setEnabledProtocols(new String[] {KonnektorTls.PROTOCOL});
      tls.setEnabledCipherSuites(KonnektorTls.CIPHER_SUITES.toArray(String[]::new));
      BCSSLSocket bc = (BCSSLSocket) tls;
      BCSSLParameters parameters = bc.getParameters();
      parameters.setNamedGroups(KonnektorTls.NAMED_GROUPS);
      parameters.setSignatureSchemes(KonnektorTls.SIGNATURE_SCHEMES);
      bc.setParameters(parameters);
      tls.setSoTimeout(millis);
      tls.startHandshake();
      tls.setSoTimeout(0);
      return tls;
    } catch (IOException | RuntimeException e) {
      tcp.close();
      throw e;
    }
  }

  /**
   * Accepts any server certificate of the Ereignissenke (see class comment). As
   * X509ExtendedTrustManager, otherwise BCJSSE additionally checks hostname and ExtendedKeyUsage
   * serverAuth.
   */
  @SuppressWarnings(
      "java:S4830") // intended: the Ereignissenke is not authenticated, see class comment
  private static final class AnySink extends X509ExtendedTrustManager {
    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) {}

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) {}

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {}

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType)
        throws CertificateException {
      throw new CertificateException("CetpTls ist nur TLS-Client");
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
        throws CertificateException {
      checkClientTrusted(chain, authType);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
        throws CertificateException {
      checkClientTrusted(chain, authType);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
      return new X509Certificate[0];
    }
  }
}

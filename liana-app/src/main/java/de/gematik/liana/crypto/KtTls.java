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
import java.time.Duration;
import java.util.List;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import org.bouncycastle.jsse.BCSSLParameters;
import org.bouncycastle.jsse.BCSSLSocket;

/**
 * TLS client of the Konnektor to the eHealth KT (TUC_KON_050 step 3, decision-11): BCJSSE from
 * {@link CryptoProviders#tls()}, because the JDK cannot do Brainpool TLS (decision-1).
 *
 * <ul>
 *   <li>Identity ID.SAK.AUT (ECC); the Konnektor offers „genau die Ciphersuiten aus
 *       [gemSpec_Krypt], zu denen er ID.SAK.AUT-Schlüsselmaterial hat“: ECDHE-ECDSA with AES-GCM
 *       (A_17124-03 no. 2, GS-A_4384-03)
 *   <li>TLS 1.2 only (GS-A_4385, A_18464; the KT must pass the handshake per gemSpec_Krypt,
 *       gemSpec_KT A_22890)
 *   <li>ECDHE and signatures as in {@link KonnektorTls} (GS-A_5345-04, A_21275-01)
 *   <li>KT certificate via {@link SmktCertificateCheck}; an error aborts the handshake (4028)
 * </ul>
 */
public final class KtTls {

  static final List<String> CIPHER_SUITES =
      List.of("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384");

  private final SSLContext context;

  /**
   * @param sakAut ID.SAK.AUT of the Konnektor
   * @param ktCheck check of the KT certificate C.SMKT.AUT
   */
  public KtTls(TlsIdentity sakAut, SmktCertificateCheck ktCheck) throws GeneralSecurityException {
    context = SSLContext.getInstance(KonnektorTls.PROTOCOL, CryptoProviders.tls());
    context.init(
        sakAut.keyManagerFactory().getKeyManagers(),
        new TrustManager[] {ktCheck},
        new SecureRandom());
  }

  /**
   * Establishes TCP and TLS to {@code host}:{@code port}; both within {@code timeout}
   * (CTM_TLS_HS_TIMEOUT). The returned socket has completed the handshake and has no read timeout.
   *
   * @throws IOException connection or handshake failed, also if the KT certificate is rejected
   */
  @SuppressWarnings("java:S2095") // the socket is returned to the caller and closed on failure
  public SSLSocket connect(String host, int port, Duration timeout) throws IOException {
    int millis = Math.toIntExact(timeout.toMillis());
    Socket tcp = new Socket();
    try {
      tcp.connect(new InetSocketAddress(host, port), millis);
      SSLSocket tls = (SSLSocket) context.getSocketFactory().createSocket(tcp, host, port, true);
      tls.setUseClientMode(true);
      tls.setEnabledProtocols(new String[] {KonnektorTls.PROTOCOL});
      tls.setEnabledCipherSuites(CIPHER_SUITES.toArray(String[]::new));
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
}

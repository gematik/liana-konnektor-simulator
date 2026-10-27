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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.List;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

/**
 * TLS context of the client via BCJSSE (LIANA-133): TLS 1.2 (GS-A_4385, A_18464), cipher suites as
 * on the Konnektor interface (GS-A_4384-03, GS-A_5345-04), ECDHE over P-256, P-384, brainpoolP256r1
 * and brainpoolP384r1 (GS-A_5345-04 item 3), signature schemes only with SHA-256/384/512
 * (A_21275-01), client certificate from PKCS#12 via BC, because the JDK KeyStore cannot read
 * Brainpool keys.
 *
 * <p>The BCJSSE default does not offer brainpoolP256r1 for TLS 1.2, and {@code SSLParameters}
 * cannot set groups under Java 17. The context therefore sets groups and signature schemes via the
 * BCJSSE API on every engine it creates, and again after every {@code setSSLParameters} of the
 * {@code HttpClient} ({@link GroupsEngine}).
 */
final class ClientTls {

  static final String PROTOCOL = "TLSv1.2";

  static final List<String> CIPHER_SUITES =
      List.of(
          "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
          "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
          "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
          "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
          "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
          "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384");

  static final String[] NAMED_GROUPS = {
    "secp256r1", "secp384r1", "brainpoolP256r1", "brainpoolP384r1"
  };

  static final String[] SIGNATURE_SCHEMES = {
    "ecdsa_secp256r1_sha256",
    "ecdsa_secp384r1_sha384",
    "ecdsa_secp521r1_sha512",
    "ecdsa_brainpoolP256r1tls13_sha256",
    "ecdsa_brainpoolP384r1tls13_sha384",
    "ecdsa_brainpoolP512r1tls13_sha512",
    "rsa_pss_rsae_sha256",
    "rsa_pss_rsae_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pss_pss_sha256",
    "rsa_pss_pss_sha384",
    "rsa_pss_pss_sha512",
    "rsa_pkcs1_sha256",
    "rsa_pkcs1_sha384",
    "rsa_pkcs1_sha512"
  };

  private ClientTls() {}

  static SSLContext context(Trust trust, Credentials credentials) throws IOException {
    try {
      SSLContext context = SSLContext.getInstance(PROTOCOL, Bc.JSSE);
      context.init(keyManagers(credentials), trustManagers(trust), new SecureRandom());
      return new GroupsContext(context);
    } catch (GeneralSecurityException e) {
      throw new IOException("TLS-Kontext nicht anlegbar: " + e.getMessage(), e);
    }
  }

  static SSLParameters parameters() {
    SSLParameters parameters =
        new SSLParameters(CIPHER_SUITES.toArray(String[]::new), new String[] {PROTOCOL});
    parameters.setEndpointIdentificationAlgorithm("HTTPS");
    return parameters;
  }

  private static TrustManager[] trustManagers(Trust trust) throws GeneralSecurityException {
    if (trust.insecureSkipVerify() || !trust.certificates().isEmpty()) {
      return new TrustManager[] {new ServerTrust(trust)};
    }
    TrustManagerFactory factory = TrustManagerFactory.getInstance("PKIX", Bc.JSSE);
    factory.init((KeyStore) null);
    return factory.getTrustManagers();
  }

  private static KeyManager[] keyManagers(Credentials credentials)
      throws GeneralSecurityException, IOException {
    if (!(credentials instanceof Credentials.Pkcs12 p12)) {
      return null;
    }
    char[] password = p12.password();
    KeyStore store = KeyStore.getInstance("PKCS12", Bc.PROVIDER);
    try {
      store.load(new ByteArrayInputStream(p12.data()), password);
    } catch (IOException e) {
      // The KeyStore's message reveals no secrets, but does not always state the reason either
      throw new IOException("PKCS#12 der Credentials nicht lesbar (Passwort oder Format)", e);
    }
    KeyManagerFactory factory = KeyManagerFactory.getInstance("PKIX", Bc.JSSE);
    factory.init(store, password);
    return factory.getKeyManagers();
  }
}

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

import io.netty.handler.ssl.ApplicationProtocolConfig;
import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.DelegatingSslContext;
import io.netty.handler.ssl.IdentityCipherSuiteFilter;
import io.netty.handler.ssl.JdkSslContext;
import io.netty.handler.ssl.SslContext;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.net.JdkSSLEngineOptions;
import io.vertx.core.net.KeyCertOptions;
import io.vertx.core.spi.tls.SslContextFactory;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.List;
import java.util.Set;
import java.util.function.BooleanSupplier;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import org.bouncycastle.jsse.BCSSLEngine;
import org.bouncycastle.jsse.BCSSLParameters;

/**
 * TLS server of the Konnektor per gemSpec_Krypt for Vert.x: Konnektor interface to the client
 * systems and KMS (TIP1-A_4806-01). The context always comes from {@link CryptoProviders#tls()},
 * never from the globally registered BCJSSE (no Brainpool) or from SunJSSE; LIANA sets groups and
 * signature schemes per connection via the BCJSSE API.
 *
 * <ul>
 *   <li>GS-A_4385, A_18464, GS-A_4387: TLS 1.2 only (TLS 1.3 is only optional (KANN) per A_18467,
 *       the Konnektors in the field do not offer it)
 *   <li>GS-A_4384-03, GS-A_5345-04: ECDHE-RSA with AES-GCM and AES-CBC, for ECC identities
 *       ECDHE-ECDSA with AES-GCM
 *   <li>GS-A_4384-03, GS-A_5345-04 item 3: ECDHE only over P-256, P-384, brainpoolP256r1,
 *       brainpoolP384r1
 *   <li>A_21275-01: signatures in the handshake only with SHA-256, SHA-384, SHA-512
 *   <li>TIP1-A_4516: optional client authentication against ANCL_CCERT_LIST ({@link
 *       ClientCertificateList}, at runtime {@link ClientCertificates}), decided anew for each
 *       handshake
 * </ul>
 */
public final class KonnektorTls {

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

  private KonnektorTls() {}

  /** TLS version of the Konnektor interface, for the admin API (LIANA-149). */
  public static String protocol() {
    return PROTOCOL;
  }

  /** Offered cipher suites in order of preference, for the admin API (LIANA-149). */
  public static List<String> cipherSuites() {
    return CIPHER_SUITES;
  }

  /** Offered curves (named groups), for the admin API (LIANA-149). */
  public static List<String> namedGroups() {
    return List.of(NAMED_GROUPS);
  }

  /**
   * Options for an HTTPS server with {@code identity}; with {@code clients} it requires a client
   * certificate from this list (ANCL_CAUT_MANDATORY Enabled, ANCL_CAUT_MODE CERTIFICATE), without
   * it performs no client authentication.
   */
  public static HttpServerOptions serverOptions(TlsIdentity identity, ClientCertificateList clients)
      throws GeneralSecurityException {
    return serverOptions(
        (X509KeyManager) identity.keyManagerFactory().getKeyManagers()[0],
        clients == null ? null : new ClientAuthentication(() -> true, clients));
  }

  /**
   * Client authentication that applies per handshake (LIANA-65): {@code required} says whether a
   * certificate is required (ANCL_CAUT_MANDATORY with ANCL_CAUT_MODE CERTIFICATE), {@code trust}
   * checks it (ANCL_CCERT_LIST).
   */
  public record ClientAuthentication(BooleanSupplier required, X509TrustManager trust) {}

  /**
   * Options for an HTTPS server that queries identity ({@code keyManager}) and client
   * authentication ({@code clients}, {@code null}: never) anew on each handshake: changes via the
   * KMS take effect without restarting the server.
   */
  public static HttpServerOptions serverOptions(
      X509KeyManager keyManager, ClientAuthentication clients) {
    HttpServerOptions options =
        new HttpServerOptions()
            .setSsl(true)
            .setEnabledSecureTransportProtocols(Set.of(PROTOCOL))
            .setKeyCertOptions(KeyCertOptions.wrap(keyManager))
            .setSslEngineOptions(new EngineOptions(clients));
    CIPHER_SUITES.forEach(options::addEnabledCipherSuite);
    return options;
  }

  /** Vert.x engine whose SSLContext comes from {@link CryptoProviders#tls()}. */
  private static final class EngineOptions extends JdkSSLEngineOptions {

    private final ClientAuthentication clients;

    EngineOptions(ClientAuthentication clients) {
      this.clients = clients;
    }

    @Override
    public JdkSSLEngineOptions copy() {
      return new EngineOptions(clients);
    }

    @Override
    public SslContextFactory sslContextFactory() {
      return new Factory(clients);
    }
  }

  private static final class Factory implements SslContextFactory {

    private final ClientAuthentication clients;
    private KeyManagerFactory keyManagers;

    Factory(ClientAuthentication clients) {
      this.clients = clients;
    }

    @Override
    public SslContextFactory keyMananagerFactory(KeyManagerFactory factory) {
      this.keyManagers = factory;
      return this;
    }

    @Override
    public SslContext create() throws SSLException {
      try {
        SSLContext context = SSLContext.getInstance(PROTOCOL, CryptoProviders.tls());
        context.init(
            keyManagers.getKeyManagers(),
            clients == null ? null : new TrustManager[] {clients.trust()},
            new SecureRandom());
        SslContext netty =
            new JdkSslContext(
                context,
                false,
                CIPHER_SUITES,
                IdentityCipherSuiteFilter.INSTANCE,
                ApplicationProtocolConfig.DISABLED,
                ClientAuth.NONE,
                new String[] {PROTOCOL},
                false);
        return new DelegatingSslContext(netty) {
          @Override
          protected void initEngine(SSLEngine engine) {
            BCSSLEngine bc = (BCSSLEngine) engine;
            BCSSLParameters parameters = bc.getParameters();
            parameters.setNamedGroups(NAMED_GROUPS);
            parameters.setSignatureSchemes(SIGNATURE_SCHEMES);
            parameters.setNeedClientAuth(clients != null && clients.required().getAsBoolean());
            bc.setParameters(parameters);
          }
        };
      } catch (GeneralSecurityException e) {
        throw new SSLException("TLS-Kontext nicht anlegbar", e);
      }
    }
  }
}

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
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import javax.net.ssl.KeyManagerFactory;

/**
 * TLS server identity of the Konnektor towards Clientsysteme (TIP1-A_4514-01: ID.AK.AUT or imported
 * per A_21697-01): private key and certificate chain from a PKCS#12 container. Loaded via BC,
 * because the JDK's PKCS12 KeyStore cannot read brainpoolP256r1 keys.
 */
public record TlsIdentity(PrivateKey key, List<X509Certificate> chain) {

  /** Loads the first key entry from {@code p12}. */
  public static TlsIdentity load(Path p12, String password)
      throws GeneralSecurityException, IOException {
    try (InputStream in = Files.newInputStream(p12)) {
      return load(in, password, p12.toString());
    }
  }

  /** Loads the first key entry from an in-memory PKCS#12 (import via the KMS, A_21697-01). */
  public static TlsIdentity load(byte[] p12, String password)
      throws GeneralSecurityException, IOException {
    return load(new java.io.ByteArrayInputStream(p12), password, "PKCS#12");
  }

  private static TlsIdentity load(InputStream in, String password, String source)
      throws GeneralSecurityException, IOException {
    char[] secret = password.toCharArray();
    KeyStore store = KeyStore.getInstance("PKCS12", CryptoProviders.BC);
    store.load(in, secret);
    for (String alias : java.util.Collections.list(store.aliases())) {
      if (store.isKeyEntry(alias)) {
        Certificate[] chain = store.getCertificateChain(alias);
        return new TlsIdentity(
            (PrivateKey) store.getKey(alias, secret),
            Arrays.stream(chain).map(X509Certificate.class::cast).toList());
      }
    }
    throw new GeneralSecurityException("kein Schlüssel in " + source);
  }

  /** End-entity certificate (C.AK.AUT). */
  public X509Certificate certificate() {
    return chain.getFirst();
  }

  /**
   * KeyManagerFactory (PKIX) of BCJSSE. The SunX509 KeyManager that Vert.x builds from key material
   * finds no credentials under BCJSSE (handshake_failure).
   */
  public KeyManagerFactory keyManagerFactory() throws GeneralSecurityException {
    try {
      KeyStore store = KeyStore.getInstance("PKCS12", CryptoProviders.BC);
      store.load(null, null);
      store.setKeyEntry("tls", key, new char[0], chain.toArray(Certificate[]::new));
      KeyManagerFactory factory = KeyManagerFactory.getInstance("PKIX", CryptoProviders.tls());
      factory.init(store, new char[0]);
      return factory;
    } catch (IOException e) {
      throw new GeneralSecurityException("Schlüsselspeicher nicht anlegbar", e);
    }
  }

  /**
   * A_24484: SHA-256 fingerprint of the server certificate, hex with colons like {@code openssl
   * x509 -fingerprint}.
   */
  public String fingerprint() {
    try {
      byte[] digest = MessageDigest.getInstance("SHA-256").digest(certificate().getEncoded());
      return HexFormat.ofDelimiter(":").withUpperCase().formatHex(digest);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }
}

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

import de.gematik.liana.kern.management.ClientSystemBinding;
import java.io.IOException;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;
import org.bouncycastle.asn1.x509.KeyPurposeId;

/**
 * The TLS server identity of the Konnektor interface at runtime (TIP1-A_4514-01, LIANA-65):
 * ID.AK.AUT as ECC ({@code gsmc-k.ak-aut}) or RSA variant ({@code gsmc-k.ak-aut-rsa}, chosen via
 * TLS_USE_ECC_FOR_CS) or a server certificate generated or imported via the KMS (A_21697-01,
 * A_21811-05), if {@link ClientSystemBinding.State#serverSoftwareKey()} is set. {@link
 * #keyManager()} queries the choice anew on every handshake; {@link #reset()} discards the software
 * certificate.
 */
public final class ServerIdentities {

  private final TlsIdentity ecc;
  private final TlsIdentity rsa;
  private final ClientSystemBinding binding;
  private volatile TlsIdentity software;
  private final Map<TlsIdentity, X509KeyManager> keyManagers = new ConcurrentHashMap<>();

  /** {@code rsa} may be missing; then the ECC identity remains. */
  public ServerIdentities(TlsIdentity ecc, Optional<TlsIdentity> rsa, ClientSystemBinding binding) {
    this.ecc = ecc;
    this.rsa = rsa.orElse(null);
    this.binding = binding;
  }

  /** The identity LIANA uses for the next handshake. */
  public TlsIdentity current() {
    ClientSystemBinding.State state = binding.state();
    TlsIdentity own = software;
    if (state.serverSoftwareKey() && own != null) {
      return own;
    }
    return state.eccForClientSystems() || rsa == null ? ecc : rsa;
  }

  public boolean hasRsa() {
    return rsa != null;
  }

  public Optional<TlsIdentity> software() {
    return Optional.ofNullable(software);
  }

  /**
   * Generates a server certificate (self-signed, EKU serverAuth, SAN {@code hostnames}, 5 years per
   * A_24483) and replaces an existing one.
   */
  public TlsIdentity generate(TlsKeys.Algorithm algorithm, List<String> hostnames)
      throws GeneralSecurityException {
    KeyPair keys = TlsKeys.generate(algorithm);
    String name = hostnames.isEmpty() ? "LIANA Konnektor" : hostnames.getFirst();
    X509Certificate certificate =
        TlsKeys.selfSigned(keys, name, hostnames, KeyPurposeId.id_kp_serverAuth);
    software = new TlsIdentity(keys.getPrivate(), List.of(certificate));
    return software;
  }

  /** A_21697-01: imports key and certificate from PKCS#12, checked per A_21811-05. */
  public TlsIdentity importPkcs12(byte[] p12, String password) throws TlsKeys.RejectedKeyException {
    TlsIdentity identity;
    try {
      identity = TlsIdentity.load(p12, password);
    } catch (GeneralSecurityException | IOException | RuntimeException e) {
      throw new TlsKeys.RejectedKeyException(
          "PKCS#12 nicht lesbar (Passwort?): " + e.getMessage(), e);
    }
    TlsKeys.checkNew(identity.certificate().getPublicKey());
    software = identity;
    return identity;
  }

  public void remove() {
    software = null;
  }

  public void reset() {
    software = null;
  }

  /** KeyManager that delegates to the current identity per handshake. */
  public X509ExtendedKeyManager keyManager() {
    return new Delegating();
  }

  private X509KeyManager managerOf(TlsIdentity identity) {
    return keyManagers.computeIfAbsent(
        identity,
        id -> {
          try {
            return (X509KeyManager) id.keyManagerFactory().getKeyManagers()[0];
          } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Schlüsselspeicher der Serveridentität", e);
          }
        });
  }

  /**
   * The alias carries the identity ({@code <hash>/<alias>}), so that key and chain come from the
   * same identity, even if the choice changes between alias and key.
   */
  private final class Delegating extends X509ExtendedKeyManager {

    private final Map<String, TlsIdentity> byPrefix = new ConcurrentHashMap<>();

    private String wrap(TlsIdentity identity, String alias) {
      if (alias == null) {
        return null;
      }
      String prefix = Integer.toHexString(System.identityHashCode(identity));
      byPrefix.put(prefix, identity);
      return prefix + "/" + alias;
    }

    private X509KeyManager owner(String alias) {
      int slash = alias == null ? -1 : alias.indexOf('/');
      TlsIdentity identity = slash < 0 ? null : byPrefix.get(alias.substring(0, slash));
      return identity == null ? null : managerOf(identity);
    }

    private static String inner(String alias) {
      return alias.substring(alias.indexOf('/') + 1);
    }

    @Override
    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
      TlsIdentity identity = current();
      X509KeyManager manager = managerOf(identity);
      String alias =
          manager instanceof X509ExtendedKeyManager extended
              ? extended.chooseEngineServerAlias(keyType, issuers, engine)
              : manager.chooseServerAlias(keyType, issuers, null);
      return wrap(identity, alias);
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
      TlsIdentity identity = current();
      return wrap(identity, managerOf(identity).chooseServerAlias(keyType, issuers, socket));
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
      TlsIdentity identity = current();
      String[] aliases = managerOf(identity).getServerAliases(keyType, issuers);
      return aliases == null
          ? null
          : java.util.Arrays.stream(aliases).map(a -> wrap(identity, a)).toArray(String[]::new);
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
      X509KeyManager manager = owner(alias);
      return manager == null ? null : manager.getCertificateChain(inner(alias));
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
      X509KeyManager manager = owner(alias);
      return manager == null ? null : manager.getPrivateKey(inner(alias));
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
      return null;
    }

    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
      return null;
    }
  }
}

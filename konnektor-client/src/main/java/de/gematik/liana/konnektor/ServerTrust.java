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

import java.net.IDN;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.security.auth.x500.X500Principal;

/**
 * Verifies the Konnektor's TLS certificate against {@link Trust} (LIANA-133): a certificate from
 * the truststore that equals the server certificate counts as a pin; otherwise the chain must end
 * at a certificate from the truststore (signature, validity, CA property). Then the hostname from
 * {@code expectedHost} or the URL is checked against SAN or CN. Signatures via the client's own BC
 * instance, so that Brainpool chains can be verified too. No revocation check: TI PKI validation
 * (TSL, OCSP) is not part of the client.
 */
final class ServerTrust extends X509ExtendedTrustManager {

  private final Trust trust;

  ServerTrust(Trust trust) {
    this.trust = trust;
  }

  @Override
  public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
      throws CertificateException {
    check(chain, engine == null ? null : engine.getPeerHost());
  }

  @Override
  public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
      throws CertificateException {
    String host =
        socket instanceof SSLSocket ssl && ssl.getHandshakeSession() != null
            ? ssl.getHandshakeSession().getPeerHost()
            : null;
    check(chain, host);
  }

  @Override
  public void checkServerTrusted(X509Certificate[] chain, String authType)
      throws CertificateException {
    check(chain, null);
  }

  void check(X509Certificate[] chain, String peerHost) throws CertificateException {
    if (trust.insecureSkipVerify()) {
      return;
    }
    if (chain == null || chain.length == 0) {
      throw new CertificateException("Konnektor sendet kein Zertifikat");
    }
    X509Certificate leaf = chain[0];
    leaf.checkValidity();
    if (!trust.certificates().contains(leaf)) {
      verifyChain(chain);
    }
    String host = trust.expectedHost() != null ? trust.expectedHost() : peerHost;
    if (host == null) {
      throw new CertificateException(
          "Hostname für die Prüfung des Konnektor-Zertifikats unbekannt");
    }
    if (!matches(leaf, host)) {
      throw new CertificateException(
          "Konnektor-Zertifikat "
              + leaf.getSubjectX500Principal().getName()
              + " passt nicht zu "
              + host);
    }
  }

  private void verifyChain(X509Certificate[] chain) throws CertificateException {
    for (int i = 0; i < chain.length; i++) {
      X509Certificate cert = chain[i];
      cert.checkValidity();
      for (X509Certificate anchor : trust.certificates()) {
        if (anchor.getSubjectX500Principal().equals(cert.getIssuerX500Principal())
            && signedBy(cert, anchor)) {
          anchor.checkValidity();
          return;
        }
      }
      if (i + 1 < chain.length) {
        X509Certificate issuer = chain[i + 1];
        if (issuer.getBasicConstraints() < 0 || !signedBy(cert, issuer)) {
          break;
        }
      }
    }
    throw new CertificateException(
        "Konnektor-Zertifikat "
            + chain[0].getSubjectX500Principal().getName()
            + " endet bei keinem Zertifikat aus dem Truststore");
  }

  private static boolean signedBy(X509Certificate cert, X509Certificate issuer) {
    try {
      cert.verify(issuer.getPublicKey(), Bc.PROVIDER);
      return true;
    } catch (GeneralSecurityException e) {
      return false;
    }
  }

  static boolean matches(X509Certificate cert, String host) throws CertificateParsingException {
    String name = IDN.toASCII(host).toLowerCase(Locale.ROOT);
    boolean ip = name.matches("[0-9.]+") || name.contains(":");
    Collection<List<?>> sans = cert.getSubjectAlternativeNames();
    if (sans != null && !sans.isEmpty()) {
      for (List<?> san : sans) {
        int type = (Integer) san.get(0);
        String value = String.valueOf(san.get(1)).toLowerCase(Locale.ROOT);
        if ((type == 2 && !ip && dnsMatches(value, name))
            || (type == 7 && ip && value.equals(name))) {
          return true;
        }
      }
      return false;
    }
    String cn = commonName(cert.getSubjectX500Principal());
    return cn != null && !ip && dnsMatches(cn.toLowerCase(Locale.ROOT), name);
  }

  private static boolean dnsMatches(String pattern, String host) {
    if (pattern.startsWith("*.")) {
      int dot = host.indexOf('.');
      return dot > 0 && host.substring(dot).equals(pattern.substring(1));
    }
    return pattern.equals(host);
  }

  private static String commonName(X500Principal principal) {
    for (String part : principal.getName(X500Principal.RFC2253).split(",")) {
      if (part.startsWith("CN=")) {
        return part.substring(3);
      }
    }
    return null;
  }

  @Override
  public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
      throws CertificateException {
    throw new CertificateException("Client prüft keine Client-Zertifikate");
  }

  @Override
  public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
      throws CertificateException {
    throw new CertificateException("Client prüft keine Client-Zertifikate");
  }

  @Override
  public void checkClientTrusted(X509Certificate[] chain, String authType)
      throws CertificateException {
    throw new CertificateException("Client prüft keine Client-Zertifikate");
  }

  @Override
  public X509Certificate[] getAcceptedIssuers() {
    return trust.certificates().toArray(X509Certificate[]::new);
  }
}

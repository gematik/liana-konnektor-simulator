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
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.X509TrustManager;

/**
 * ANCL_CCERT_LIST (TAB_KON_506-01): the certificates with which Clientsysteme may authenticate via
 * TLS (TIP1-A_4516). A client is authenticated if its certificate is in the list and has not
 * expired; there is no chain check or online check (gemSpec_Kon 3.5.1: locally limited
 * authentication).
 */
public final class ClientCertificateList implements X509TrustManager {

  private final List<X509Certificate> certificates;

  public ClientCertificateList(List<X509Certificate> certificates) {
    this.certificates = List.copyOf(certificates);
  }

  /** Reads all PEM certificates of each file. */
  public static ClientCertificateList load(List<Path> files)
      throws GeneralSecurityException, IOException {
    CertificateFactory factory = CertificateFactory.getInstance("X.509");
    List<X509Certificate> certificates = new ArrayList<>();
    for (Path file : files) {
      try (InputStream in = Files.newInputStream(file)) {
        factory.generateCertificates(in).forEach(c -> certificates.add((X509Certificate) c));
      }
    }
    return new ClientCertificateList(certificates);
  }

  public List<X509Certificate> certificates() {
    return certificates;
  }

  @Override
  public void checkClientTrusted(X509Certificate[] chain, String authType)
      throws CertificateException {
    if (chain == null || chain.length == 0) {
      throw new CertificateException("kein Client-Zertifikat");
    }
    X509Certificate client = chain[0];
    if (!certificates.contains(client)) {
      throw new CertificateException(
          "Client-Zertifikat nicht in ANCL_CCERT_LIST: "
              + client.getSubjectX500Principal().getName());
    }
    client.checkValidity();
  }

  @Override
  public void checkServerTrusted(X509Certificate[] chain, String authType)
      throws CertificateException {
    throw new CertificateException("ANCL_CCERT_LIST prüft nur Clientsysteme");
  }

  @Override
  public X509Certificate[] getAcceptedIssuers() {
    return certificates.toArray(X509Certificate[]::new);
  }
}

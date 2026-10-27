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

import de.gematik.liana.konnektor.ws.conn.certificateservice.v6_0.CryptType;
import de.gematik.liana.konnektor.ws.conn.certificateservice.v6_0.ReadCardCertificate;
import de.gematik.liana.konnektor.ws.conn.certificateservice.v6_0.ReadCardCertificateResponse;
import de.gematik.liana.konnektor.ws.conn.certificateservicecommon.v2_0.CertRefEnum;
import de.gematik.liana.konnektor.ws.conn.certificateservicecommon.v2_0.X509DataInfoListType;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * ReadCardCertificate (TIP1-A_4698, CertificateService 6.0; LIANA-135) for a certificate reference.
 * Verifying the certificate (VerifyCertificate) belongs to LIANA-136.
 */
public final class CertificateScope {

  private final Konnektor kon;
  private final String handle;
  private final String certRef;
  private final String crypt;

  CertificateScope(Konnektor kon, String handle, String certRef, String crypt) {
    this.kon = kon;
    this.handle = handle;
    this.certRef = certRef;
    this.crypt = crypt;
  }

  /** ECC certificate (Crypt ECC, default). */
  public CertificateScope ecc() {
    return new CertificateScope(kon, handle, certRef, "ECC");
  }

  /** RSA certificate (Crypt RSA, G2.0 cards). */
  public CertificateScope rsa() {
    return new CertificateScope(kon, handle, certRef, "RSA");
  }

  /** The certificate; the first one if the Konnektor returns several. */
  public X509Certificate read() {
    List<X509Certificate> all = readAll();
    if (all.isEmpty()) {
      throw new KonnektorException(
          "ReadCardCertificate " + certRef + " " + crypt + ": kein Zertifikat");
    }
    return all.get(0);
  }

  /** All certificates of the response for this reference. */
  public List<X509Certificate> readAll() {
    ReadCardCertificate request = new ReadCardCertificate();
    request.setContext(Jaxb.context(kon.context()));
    request.setCardHandle(handle);
    request.setCertRefList(new ReadCardCertificate.CertRefList());
    request.getCertRefList().getCertRef().add(CertRefEnum.fromValue(certRef));
    request.setCrypt(CryptType.fromValue(crypt));
    ReadCardCertificateResponse response =
        kon.invoke(Operation.READ_CARD_CERTIFICATE, request, ReadCardCertificateResponse.class);
    List<X509Certificate> certificates = new ArrayList<>();
    if (response.getX509DataInfoList() == null) {
      return certificates;
    }
    for (X509DataInfoListType.X509DataInfo info :
        response.getX509DataInfoList().getX509DataInfo()) {
      if (info.getX509Data() != null && info.getX509Data().getX509Certificate() != null) {
        certificates.add(parse(info.getX509Data().getX509Certificate()));
      }
    }
    return certificates;
  }

  /** {@link #read()} as PEM. */
  public String asPem() {
    try {
      return "-----BEGIN CERTIFICATE-----\n"
          + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(read().getEncoded())
          + "\n-----END CERTIFICATE-----\n";
    } catch (java.security.cert.CertificateEncodingException e) {
      throw new KonnektorException("Zertifikat nicht kodierbar", e);
    }
  }

  /** Expiry ({@code notAfter}) of {@link #read()}. */
  public Instant expiration() {
    return read().getNotAfter().toInstant();
  }

  private static X509Certificate parse(byte[] der) {
    try {
      return (X509Certificate)
          CertificateFactory.getInstance("X.509", Bc.PROVIDER)
              .generateCertificate(new ByteArrayInputStream(der));
    } catch (CertificateException e) {
      throw new KonnektorException("ReadCardCertificate: kein X.509-Zertifikat", e);
    }
  }
}

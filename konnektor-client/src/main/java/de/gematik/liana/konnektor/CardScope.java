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

import java.util.Objects;

/**
 * Operations on a card (LIANA-135): PIN, certificates, authentication. Bound to the CardHandle;
 * after the card is pulled, the Konnektor responds with an error.
 */
public final class CardScope {

  private final Konnektor kon;
  private final String handle;

  CardScope(Konnektor kon, String handle) {
    this.kon = kon;
    this.handle = Objects.requireNonNull(handle, "handle");
  }

  /** CardHandle of the card. */
  public String handle() {
    return handle;
  }

  /** A PIN of the card, such as {@code PIN.SMC}, {@code PIN.CH}, {@code PIN.QES}. */
  public PinScope pin(String pinType) {
    return new PinScope(kon, handle, pinType);
  }

  /**
   * A certificate of the card: {@code C.AUT}, {@code C.ENC}, {@code C.SIG}, {@code C.QES}; ECC by
   * default.
   */
  public CertificateScope certificate(String certRef) {
    return new CertificateScope(kon, handle, certRef, "ECC");
  }

  /** ExternalAuthenticate over a hash (TIP1-A_5439-02), e.g. for ZETA or IDP logins. */
  public Authentication authenticate(byte[] hash) {
    return new Authentication(kon, this, hash.clone());
  }

  /** SignDocument for one document (LIANA-136): {@code sign(doc).cades().detached().sign()}. */
  public Signing sign(Document document) {
    return new Signing(kon, this, java.util.List.of(document));
  }

  /** SignDocument for several documents in one job (one JobNumber, one PIN dialog). */
  public Signing signAll(java.util.List<Document> documents) {
    return new Signing(kon, this, documents);
  }

  /** Komfortsignatur of the HBA (LIANA-136). */
  public Comfort comfort() {
    return new Comfort(kon, this);
  }

  /**
   * DecryptDocument (TIP1-A_4627, TUC_KON_071; LIANA-136) with the card's ENC key.
   *
   * @param encrypted CMS EnvelopedData ({@code application/pkcs7-mime})
   */
  public byte[] decrypt(byte[] encrypted) {
    var request = new de.gematik.liana.konnektor.ws.conn.encryptionservice.v6_1.DecryptDocument();
    request.setContext(Jaxb.context(kon.context()));
    var key = new de.gematik.liana.konnektor.ws.conn.encryptionservice.v6_1.KeyOnCardType();
    key.setCardHandle(handle);
    request.setPrivateKeyOnCard(key);
    request.setDocument(Encryption.document(Document.of(encrypted, "application/pkcs7-mime")));
    var response =
        kon.invoke(
            Operation.DECRYPT_DOCUMENT,
            request,
            de.gematik.liana.konnektor.ws.conn.encryptionservice.v6_1.DecryptDocumentResponse
                .class);
    return Encryption.content(response.getDocument());
  }

  /**
   * ReadVSD without Onlineprüfung (VSDService 5.2, VSDM-A_2567; LIANA-105): reads PD, VD and GVD of
   * this eGK. The Konnektor requires an unlocked SMC-B or an HBA ({@code hpcHandle}), e.g. after
   * VerifyPin PIN.SMC.
   */
  public Vsd readVsd(String hpcHandle) {
    var request = new de.gematik.liana.konnektor.ws.conn.vsds.vsdservice.v5_2.ReadVSD();
    request.setContext(Jaxb.context(kon.context()));
    request.setEhcHandle(handle);
    request.setHpcHandle(Objects.requireNonNull(hpcHandle, "hpcHandle"));
    request.setPerformOnlineCheck(false);
    request.setReadOnlineReceipt(false);
    var response =
        kon.invoke(
            Operation.READ_VSD,
            request,
            de.gematik.liana.konnektor.ws.conn.vsds.vsdservice.v5_2.ReadVSDResponse.class);
    var status = response.getVSDStatus();
    return new Vsd(
        Vsd.gunzip("PersoenlicheVersichertendaten", response.getPersoenlicheVersichertendaten()),
        Vsd.gunzip("AllgemeineVersicherungsdaten", response.getAllgemeineVersicherungsdaten()),
        java.util.Optional.ofNullable(response.getGeschuetzteVersichertendaten())
            .map(gvd -> Vsd.gunzip("GeschuetzteVersichertendaten", gvd)),
        new Vsd.Status(
            "1".equals(status.getStatus()),
            status.getTimestamp().toGregorianCalendar().toZonedDateTime().toLocalDateTime(),
            status.getVersion()));
  }

  /** A JWS, signed via ExternalAuthenticate, with the card's C.AUT in the {@code x5c} header. */
  public Jws jws(java.util.Map<String, Object> claims) {
    return new Jws(kon, this, claims);
  }
}

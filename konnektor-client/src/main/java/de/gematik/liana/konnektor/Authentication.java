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

import de.gematik.liana.konnektor.ws.conn.signatureservice.v7_4.BinaryDocumentType;
import de.gematik.liana.konnektor.ws.conn.signatureservice.v7_4.ExternalAuthenticate;
import de.gematik.liana.konnektor.ws.conn.signatureservice.v7_4.ExternalAuthenticateResponse;
import de.gematik.liana.konnektor.ws.ext.dss.core.Base64Data;

/**
 * ExternalAuthenticate (TIP1-A_5439-02, AuthSignatureService 7.4; LIANA-135): the Konnektor signs a
 * hash with the card's AUT key (TUC_KON_218).
 */
public final class Authentication {

  /** {@code SignatureType} ECDSA_URI per BSI TR-03111. */
  public static final String ECDSA_URI = "urn:bsi:tr:03111:ecdsa";

  /** {@code SignatureType} RSA per RFC 3447, with {@code SignatureSchemes} RSASSA-PSS. */
  public static final String RSA = "urn:ietf:rfc:3447";

  private final Konnektor kon;
  private final CardScope card;
  private final byte[] hash;

  Authentication(Konnektor kon, CardScope card, byte[] hash) {
    this.kon = kon;
    this.card = card;
    this.hash = hash;
  }

  /**
   * ECDSA_URI; the result is the ECDSA_URI-Sig-Value (TR-03111 5.2.2, DER) as the Konnektor returns
   * it.
   */
  public byte[] ecdsa() {
    return sign(ECDSA_URI, null);
  }

  /** RSASSA-PSS (G2.0 cards, R2048 keys). */
  public byte[] rsaPss() {
    return sign(RSA, "RSASSA-PSS");
  }

  private byte[] sign(String type, String scheme) {
    ExternalAuthenticate request = new ExternalAuthenticate();
    request.setContext(Jaxb.context(kon.context()));
    request.setCardHandle(card.handle());
    ExternalAuthenticate.OptionalInputs inputs = new ExternalAuthenticate.OptionalInputs();
    inputs.setSignatureType(type);
    inputs.setSignatureSchemes(scheme);
    request.setOptionalInputs(inputs);
    BinaryDocumentType binary = new BinaryDocumentType();
    Base64Data data = new Base64Data();
    data.setValue(hash.clone());
    // TAB_KON_781: BinaryString/Base64Data with MimeType application/octet-stream
    data.setMimeType("application/octet-stream");
    binary.setBase64Data(data);
    request.setBinaryString(binary);
    ExternalAuthenticateResponse response =
        kon.invoke(Operation.EXTERNAL_AUTHENTICATE, request, ExternalAuthenticateResponse.class);
    if (response.getSignatureObject() == null
        || response.getSignatureObject().getBase64Signature() == null) {
      throw new KonnektorException("ExternalAuthenticate: Antwort ohne Signatur");
    }
    return response.getSignatureObject().getBase64Signature().getValue();
  }
}

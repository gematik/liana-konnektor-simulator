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

import de.gematik.liana.konnektor.ws.conn.connectorcommon.v5_0.DocumentType;
import de.gematik.liana.konnektor.ws.conn.encryptionservice.v6_1.EncryptDocument;
import de.gematik.liana.konnektor.ws.conn.encryptionservice.v6_1.EncryptDocumentResponse;
import de.gematik.liana.konnektor.ws.conn.encryptionservice.v6_1.KeyOnCardType;
import de.gematik.liana.konnektor.ws.ext.dss.core.Base64Data;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

/**
 * EncryptDocument (TIP1-A_4626, EncryptionService 6.1, TUC_KON_070; LIANA-136): hybrid, for
 * recipient certificates or the C.ENC of a card, CMS by default ({@code urn:ietf:rfc:5652}).
 */
public final class Encryption {

  public static final String CMS = "urn:ietf:rfc:5652";
  public static final String SMIME = "urn:ietf:rfc:5751";
  public static final String XMLENC = "http://www.w3.org/TR/xmlenc-core/";

  private final Konnektor kon;
  private final Document document;
  private String type = CMS;

  Encryption(Konnektor kon, Document document) {
    this.kon = kon;
    this.document = document;
  }

  /** {@code EncryptionType}: {@link #CMS}, {@link #SMIME} or {@link #XMLENC}. */
  public Encryption type(String encryptionType) {
    this.type = encryptionType;
    return this;
  }

  /** For these recipient certificates (C.ENC, C.HCI.ENC). */
  public byte[] to(X509Certificate... recipients) {
    EncryptDocument request = request();
    for (X509Certificate recipient : recipients) {
      try {
        request.getRecipientKeys().getCertificate().add(recipient.getEncoded());
      } catch (CertificateEncodingException e) {
        throw new KonnektorException("Empfängerzertifikat nicht kodierbar", e);
      }
    }
    return send(request);
  }

  /** For the C.ENC of the card with this CardHandle. */
  public byte[] toCard(String cardHandle) {
    EncryptDocument request = request();
    KeyOnCardType key = new KeyOnCardType();
    key.setCardHandle(cardHandle);
    request.getRecipientKeys().setCertificateOnCard(key);
    return send(request);
  }

  private EncryptDocument request() {
    EncryptDocument request = new EncryptDocument();
    request.setContext(Jaxb.context(kon.context()));
    request.setRecipientKeys(new EncryptDocument.RecipientKeys());
    request.setDocument(document(document));
    EncryptDocument.OptionalInputs inputs = new EncryptDocument.OptionalInputs();
    inputs.setEncryptionType(type);
    request.setOptionalInputs(inputs);
    return request;
  }

  private byte[] send(EncryptDocument request) {
    EncryptDocumentResponse response =
        kon.invoke(Operation.ENCRYPT_DOCUMENT, request, EncryptDocumentResponse.class);
    return content(response.getDocument());
  }

  static DocumentType document(Document document) {
    DocumentType value = new DocumentType();
    if (document.xml()) {
      value.setBase64XML(document.content());
    } else {
      Base64Data data = new Base64Data();
      data.setValue(document.content());
      data.setMimeType(document.mimeType());
      value.setBase64Data(data);
    }
    return value;
  }

  static byte[] content(DocumentType document) {
    if (document == null) {
      throw new KonnektorException("Antwort ohne Dokument");
    }
    return document.getBase64XML() != null
        ? document.getBase64XML()
        : document.getBase64Data().getValue();
  }
}

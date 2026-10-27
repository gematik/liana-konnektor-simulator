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

import de.gematik.liana.konnektor.ws.ext.dss.core.Base64Data;
import java.util.ArrayList;
import java.util.List;

/**
 * SignDocument (TIP1-A_4655, SignatureService 7.4/7.5, TUC_KON_150; LIANA-136): first a JobNumber
 * (GetJobNumber), then one SignRequest per document with signature type and variant. Signature
 * types per gemSpec_Kon: CMS/CAdES {@code urn:ietf:rfc:5652} (detached: {@code IncludeEContent}
 * false), XML/XAdES {@code urn:ietf:rfc:3275}, PDF/PAdES {@code http://uri.etsi.org/02778/3} (only
 * {@code application/pdf-a}). Without a type, the Konnektor derives it from the document
 * (TAB_KON_583).
 */
public final class Signing {

  public static final String CADES_URI = "urn:ietf:rfc:5652";
  public static final String XADES_URI = "urn:ietf:rfc:3275";
  public static final String PADES_URI = "http://uri.etsi.org/02778/3";

  private final Konnektor kon;
  private final CardScope card;
  private final List<Document> documents;
  private String signatureType;
  private Boolean includeEContent;
  private boolean includeRevocationInfo;
  private String crypt;

  Signing(Konnektor kon, CardScope card, List<Document> documents) {
    this.kon = kon;
    this.card = card;
    this.documents = List.copyOf(documents);
  }

  /** CAdES (CMS); variant with {@link #detached()} or {@link #enveloping()}. */
  public Signing cades() {
    signatureType = CADES_URI;
    return this;
  }

  /** PAdES; the document must be {@code application/pdf-a}. */
  public Signing pades() {
    signatureType = PADES_URI;
    return this;
  }

  /** XAdES. */
  public Signing xades() {
    signatureType = XADES_URI;
    return this;
  }

  /** CMS without embedded content ({@code IncludeEContent} false). */
  public Signing detached() {
    includeEContent = false;
    return this;
  }

  /** CMS with embedded content ({@code IncludeEContent} true). */
  public Signing enveloping() {
    includeEContent = true;
    return this;
  }

  /** Embed OCSP responses ({@code IncludeRevocationInfo}, not for PAdES). */
  public Signing includeRevocationInfo(boolean include) {
    includeRevocationInfo = include;
    return this;
  }

  /** {@code Crypt} RSA, ECC or RSA_ECC (the Konnektor's default if not set). */
  public Signing crypt(String value) {
    crypt = value;
    return this;
  }

  /** Signs all documents in one call, with a new JobNumber. */
  public List<SignResult> sign() {
    return sign(kon.signatures().jobNumber());
  }

  /** Signs with a previously obtained JobNumber (for {@link Signatures#stop(String)}). */
  public List<SignResult> sign(String jobNumber) {
    ServiceDirectory.Selection selection = kon.select(Operation.SIGN_DOCUMENT);
    Object request = Jaxb.request(selection.binding(), "SignDocument");
    Jaxb.set(request, "Context", Jaxb.context(kon.context()));
    Jaxb.set(request, "CardHandle", card.handle());
    if (crypt != null) {
      Jaxb.set(request, "Crypt", crypt);
    }
    Jaxb.set(request, "TvMode", "NONE");
    Jaxb.set(request, "JobNumber", jobNumber);
    @SuppressWarnings("unchecked")
    List<Object> requests = (List<Object>) Jaxb.get(request, "SignRequest");
    for (int i = 0; i < documents.size(); i++) {
      requests.add(signRequest(selection.binding(), documents.get(i), "Doc" + (i + 1)));
    }
    Object response =
        kon.invoke(selection, request, Jaxb.type(selection.binding(), "SignDocumentResponse"));
    List<SignResult> results = new ArrayList<>();
    @SuppressWarnings("unchecked")
    List<Object> responses = (List<Object>) Jaxb.get(response, "SignResponse");
    for (Object signResponse : responses) {
      Object status = Jaxb.get(signResponse, "Status");
      Object object = Jaxb.get(signResponse, "SignatureObject");
      String type = null;
      byte[] value = null;
      if (object instanceof de.gematik.liana.konnektor.ws.ext.dss.core.SignatureObject signature
          && signature.getBase64Signature() != null) {
        type = signature.getBase64Signature().getType();
        value = signature.getBase64Signature().getValue();
      }
      Object document = Jaxb.get(signResponse, "DocumentWithSignature");
      if (value == null && document != null) {
        value = content(document);
      }
      results.add(
          new SignResult(
              (String) Jaxb.get(signResponse, "RequestID"),
              status == null ? null : (String) Jaxb.get(status, "Result"),
              type,
              value));
    }
    return results;
  }

  private Object signRequest(Binding binding, Document document, String requestId) {
    Object signRequest = Jaxb.request(binding, "SignRequest");
    Jaxb.set(signRequest, "RequestID", requestId);
    Object inputs = Jaxb.request(binding, "SignRequest$OptionalInputs");
    if (signatureType != null) {
      Jaxb.set(inputs, "SignatureType", signatureType);
    }
    if (includeEContent != null) {
      Jaxb.set(inputs, "IncludeEContent", includeEContent);
    }
    Jaxb.set(signRequest, "OptionalInputs", inputs);
    Jaxb.set(signRequest, "Document", document(binding, document));
    Jaxb.set(signRequest, "IncludeRevocationInfo", includeRevocationInfo);
    return signRequest;
  }

  static Object document(Binding binding, Document document) {
    Object value = Jaxb.request(binding, "DocumentType");
    if (document.xml()) {
      Jaxb.set(value, "Base64XML", document.content());
    } else {
      Base64Data data = new Base64Data();
      data.setValue(document.content());
      data.setMimeType(document.mimeType());
      Jaxb.set(value, "Base64Data", data);
    }
    if (document.shortText() != null) {
      Jaxb.set(value, "ShortText", document.shortText());
    }
    return value;
  }

  static byte[] content(Object document) {
    byte[] xml = (byte[]) Jaxb.get(document, "Base64XML");
    if (xml != null) {
      return xml;
    }
    Object data = Jaxb.get(document, "Base64Data");
    return data instanceof Base64Data b ? b.getValue() : null;
  }
}

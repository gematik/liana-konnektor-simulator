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

import de.gematik.liana.konnektor.ws.conn.certificateservice.v6_0.VerifyCertificate;
import de.gematik.liana.konnektor.ws.conn.certificateservice.v6_0.VerifyCertificateResponse;
import de.gematik.liana.konnektor.ws.ext.dss.core.Base64Signature;
import de.gematik.liana.konnektor.ws.ext.dss.core.SignatureObject;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Verifications without a card (LIANA-136): VerifyDocument (TIP1-A_4656, TUC_KON_161) and
 * VerifyCertificate (TIP1-A_5483, TUC_KON_037/042).
 */
public final class Verification {

  /**
   * Result of VerifyDocument.
   *
   * @param highLevelResult {@code VALID}, {@code INCONCLUSIVE}, {@code INVALID}
   */
  public record SignatureCheck(String status, String highLevelResult) {}

  /**
   * Result of VerifyCertificate.
   *
   * @param result {@code VALID}, {@code INCONCLUSIVE}, {@code INVALID}
   * @param roles roles from the certificate (OIDs)
   */
  public record CertificateCheck(String status, String result, List<String> roles) {}

  private final Konnektor kon;

  Verification(Konnektor kon) {
    this.kon = kon;
  }

  /**
   * VerifyDocument for a document with an embedded signature (PAdES, XAdES enveloped, CAdES
   * enveloping).
   */
  public SignatureCheck signature(Document signed) {
    return signature(signed, null, null);
  }

  /** VerifyDocument for a detached signature ({@code signatureType} e.g. {@link Signing#CADES}). */
  public SignatureCheck signature(
      Document document, byte[] detachedSignature, String signatureType) {
    ServiceDirectory.Selection selection = kon.select(Operation.VERIFY_DOCUMENT);
    Object request = Jaxb.request(selection.binding(), "VerifyDocument");
    Jaxb.set(request, "Context", Jaxb.context(kon.context()));
    Jaxb.set(request, "TvMode", "NONE");
    Jaxb.set(request, "Document", Signing.document(selection.binding(), document));
    if (detachedSignature != null) {
      SignatureObject object = new SignatureObject();
      Base64Signature signature = new Base64Signature();
      signature.setValue(detachedSignature);
      signature.setType(signatureType);
      object.setBase64Signature(signature);
      Jaxb.set(request, "SignatureObject", object);
    }
    Jaxb.set(request, "IncludeRevocationInfo", false);
    Object response =
        kon.invoke(selection, request, Jaxb.type(selection.binding(), "VerifyDocumentResponse"));
    Object status = Jaxb.get(response, "Status");
    Object result = Jaxb.get(response, "VerificationResult");
    return new SignatureCheck(
        status == null ? null : (String) Jaxb.get(status, "Result"),
        result == null ? null : (String) Jaxb.get(result, "HighLevelResult"));
  }

  /** VerifyCertificate at the current point in time. */
  public CertificateCheck certificate(X509Certificate certificate) {
    VerifyCertificate request = new VerifyCertificate();
    request.setContext(Jaxb.context(kon.context()));
    try {
      request.setX509Certificate(certificate.getEncoded());
    } catch (CertificateEncodingException e) {
      throw new KonnektorException("Zertifikat nicht kodierbar", e);
    }
    VerifyCertificateResponse response =
        kon.invoke(Operation.VERIFY_CERTIFICATE, request, VerifyCertificateResponse.class);
    return new CertificateCheck(
        response.getStatus() == null ? null : response.getStatus().getResult(),
        response.getVerificationStatus() == null
                || response.getVerificationStatus().getVerificationResult() == null
            ? null
            : response.getVerificationStatus().getVerificationResult().value(),
        response.getRoleList() == null ? List.of() : List.copyOf(response.getRoleList().getRole()));
  }
}

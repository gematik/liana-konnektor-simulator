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
package de.gematik.liana.adapter.soap;

import de.gematik.liana.kern.card.CardCertificates;
import de.gematik.liana.kern.card.CertificateExpiration;
import de.gematik.liana.kern.error.ConnectorError;
import de.gematik.liana.kern.error.ConnectorException;
import io.quarkus.qute.Location;
import io.quarkus.qute.Template;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Response;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

/**
 * Certificate service CertificateService v6.0 under {@code /ws/CertificateService}:
 * ReadCardCertificate (TIP1-A_4700-03) and CheckCertificateExpiration (TIP1-A_4699-07, LIANA-188).
 * Issuer and subject name in RFC 2253 format as in the TU trace popp-kon-tu.
 */
@Path("/ws/CertificateService")
public class CertificateServiceResource {

  static final String NAMESPACE = "http://ws.gematik.de/conn/CertificateService/v6.0";

  private final CardCertificates certificates;
  private final CertificateExpiration expiration;
  private final Template readResponse;
  private final Template expirationResponse;
  private final SoapFaults faults;
  private final RequestCheck requestCheck;

  CertificateServiceResource(
      CardCertificates certificates,
      CertificateExpiration expiration,
      @Location("soap/ReadCardCertificateResponse.xml") Template readResponse,
      @Location("soap/CheckCertificateExpirationResponse.xml") Template expirationResponse,
      SoapFaults faults,
      RequestCheck requestCheck) {
    this.certificates = certificates;
    this.expiration = expiration;
    this.readResponse = readResponse;
    this.expirationResponse = expirationResponse;
    this.faults = faults;
    this.requestCheck = requestCheck;
  }

  @POST
  public Response post(@HeaderParam("SOAPAction") String soapAction, byte[] body) {
    XmlNode operation;
    try {
      operation = SoapEnvelope.operation(body);
    } catch (SoapEnvelope.InvalidSoapException e) {
      return faults.client(e);
    }
    Optional<Response> rejected = requestCheck.check(soapAction, body, operation);
    if (rejected.isPresent()) {
      return rejected.get();
    }
    String name = EventServiceResource.operationName(NAMESPACE, soapAction, operation);
    if (name == null) {
      return faults.client(
          "SOAPAction '"
              + soapAction
              + "' passt nicht zu "
              + operation.namespace()
              + "#"
              + operation.name());
    }
    try {
      return switch (name) {
        case "ReadCardCertificate" -> readCardCertificate(operation);
        case "CheckCertificateExpiration" -> checkCertificateExpiration(operation);
        default -> faults.unsupported("CertificateService", name);
      };
    } catch (ConnectorException e) {
      return faults.connector(e, operation);
    }
  }

  /** TAB_KON_678: CardHandle, Context, CertRefList, Crypt (optional). */
  private Response readCardCertificate(XmlNode operation) {
    List<String> certRefs =
        operation
            .child("CertRefList")
            .map(
                list ->
                    list.children().stream()
                        .filter(c -> c.name().equals("CertRef"))
                        .map(c -> c.text().strip())
                        .toList())
            .orElse(List.of());
    var read =
        certificates.read(
            EventServiceResource.context(operation),
            operation.childText("CardHandle").orElse(null),
            certRefs,
            operation.childText("Crypt").orElse(null));
    List<CertificateView> views = read.stream().map(CertificateServiceResource::view).toList();
    return EventServiceResource.ok(readResponse.data("certificates", views).render());
  }

  /**
   * TAB_KON_676: CardHandle (optional), Context, Crypt (optional, from schema 6.0.2 on); warnings
   * 4257 in one GERROR:Error with one trace each (TAB_KON_677, like secunet).
   */
  private Response checkCertificateExpiration(XmlNode operation) {
    CertificateExpiration.Result result =
        expiration.execute(
            new CertificateExpiration.Request(
                EventServiceResource.context(operation),
                text(operation, "CardHandle"),
                text(operation, "Crypt")));
    return EventServiceResource.ok(
        expirationResponse
            .data("expirations", result.entries().stream().map(ExpirationView::of).toList())
            .data(
                "warnings",
                result.warnings().stream()
                    .map(text -> GerrorView.of(ConnectorError.CERT_MISSING, text))
                    .toList())
            .render());
  }

  private static String text(XmlNode operation, String name) {
    return operation.childText(name).map(String::strip).filter(t -> !t.isEmpty()).orElse(null);
  }

  private static CertificateView view(CardCertificates.Certificate certificate) {
    try {
      X509Certificate x509 =
          (X509Certificate)
              CertificateFactory.getInstance("X.509")
                  .generateCertificate(new ByteArrayInputStream(certificate.der()));
      return new CertificateView(
          certificate.certRef(),
          x509.getIssuerX500Principal().getName(),
          x509.getSerialNumber().toString(),
          x509.getSubjectX500Principal().getName(),
          Base64.getEncoder().encodeToString(certificate.der()));
    } catch (CertificateException e) {
      throw ConnectorError.CERT_NOT_ON_CARD
          .exception(
              ConnectorError.CERT_NOT_ON_CARD.text(),
              certificate.certRef() + " nicht lesbar: " + e.getMessage())
          .causedBy(e);
    }
  }
}

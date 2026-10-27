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

import de.gematik.liana.kern.card.ExternalAuthentication;
import de.gematik.liana.kern.error.ConnectorError;
import de.gematik.liana.kern.error.ConnectorException;
import io.quarkus.qute.Location;
import io.quarkus.qute.Template;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Response;
import java.util.Base64;
import java.util.Optional;

/**
 * Authentication service AuthSignatureService (SignatureService v7.4) under {@code
 * /ws/AuthSignatureService}: ExternalAuthenticate (TIP1-A_5439-02, TIP1-A_5665-03).
 */
@Path("/ws/AuthSignatureService")
public class AuthSignatureServiceResource {

  static final String NAMESPACE = "http://ws.gematik.de/conn/SignatureService/v7.4";
  private static final String OCTET_STREAM = "application/octet-stream";

  private final ExternalAuthentication external;
  private final Template response;
  private final SoapFaults faults;
  private final RequestCheck requestCheck;

  AuthSignatureServiceResource(
      ExternalAuthentication external,
      @Location("soap/ExternalAuthenticateResponse.xml") Template response,
      SoapFaults faults,
      RequestCheck requestCheck) {
    this.external = external;
    this.response = response;
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
    if (!name.equals("ExternalAuthenticate")) {
      return faults.unsupported("AuthSignatureService", name);
    }
    try {
      return externalAuthenticate(operation);
    } catch (ConnectorException e) {
      return faults.connector(e, operation);
    }
  }

  /**
   * TAB_KON_781: CardHandle, Context, OptionalInputs (not evaluated for G2.1),
   * BinaryString/Base64Data.
   */
  private Response externalAuthenticate(XmlNode operation) {
    XmlNode data =
        operation
            .child("BinaryString")
            .flatMap(b -> b.child("Base64Data"))
            .orElseThrow(() -> ConnectorError.SYNTAX.exception("BinaryString/Base64Data fehlt"));
    if (!OCTET_STREAM.equals(data.attributes().get("MimeType"))) {
      throw ConnectorError.SYNTAX.exception(
          "MimeType '" + data.attributes().get("MimeType") + "' statt " + OCTET_STREAM);
    }
    byte[] binaryString;
    try {
      binaryString = Base64.getMimeDecoder().decode(data.text().strip());
    } catch (IllegalArgumentException e) {
      throw ConnectorError.SYNTAX.exception("Base64Data ist kein Base64").causedBy(e);
    }
    byte[] signature =
        external.sign(
            EventServiceResource.context(operation),
            operation.childText("CardHandle").orElse(null),
            binaryString);
    return EventServiceResource.ok(
        response
            .data("type", ExternalAuthentication.ECDSA)
            .data("signature", Base64.getEncoder().encodeToString(signature))
            .render());
  }
}

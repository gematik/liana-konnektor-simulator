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

import de.gematik.liana.kern.error.ConnectorError;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.ws.rs.core.Response;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import org.jboss.logging.Logger;

/**
 * {@link RequestValidation} for the service resources (LIANA-48): in mode {@code log} violations as
 * a warning, in mode {@code reject} a wrong SOAPAction as {@code SOAP-ENV:Client} (SOAP 1.1, like
 * an unknown operation) and a schema violation as gematik SOAP fault 4000 „Syntaxfehler“
 * (TIP1-A_5058-01, A_14159).
 */
@ApplicationScoped
public class RequestCheck {

  private static final Logger LOG = Logger.getLogger(RequestCheck.class);

  private final RequestValidation validation;
  private final SoapFaults faults;

  RequestCheck(RequestValidation validation, SoapFaults faults) {
    this.validation = validation;
    this.faults = faults;
  }

  /**
   * Empty if the request may proceed; otherwise the fault. {@code message} is the root part (MTOM).
   */
  Optional<Response> check(String soapAction, byte[] message, XmlNode operation) {
    List<RequestValidation.Violation> violations =
        validation.violations(soapAction, message, operation);
    if (violations.isEmpty()) {
      return Optional.empty();
    }
    String service = SoapFaults.service(operation);
    if (validation.mode() == RequestValidation.Mode.LOG) {
      LOG.warnf(
          "Anfrage %s verletzt den Vertrag (liana.soap.request-validation=log): %s",
          service,
          violations.stream()
              .map(RequestValidation.Violation::text)
              .collect(Collectors.joining("; ")));
      return Optional.empty();
    }
    Optional<RequestValidation.Violation> action =
        violations.stream().filter(RequestValidation.Violation::soapAction).findFirst();
    if (action.isPresent()) {
      return Optional.of(faults.client(service + ": " + action.get().text()));
    }
    return Optional.of(
        faults.connector(
            ConnectorError.SYNTAX.exception(
                violations.stream()
                    .map(RequestValidation.Violation::text)
                    .collect(Collectors.joining("; "))),
            operation));
  }
}

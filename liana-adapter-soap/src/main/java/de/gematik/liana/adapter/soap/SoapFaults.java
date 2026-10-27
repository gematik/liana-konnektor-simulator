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
import de.gematik.liana.kern.error.ConnectorException;
import de.gematik.liana.kern.vendor.VendorProfile;
import io.quarkus.qute.Location;
import io.quarkus.qute.Template;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.ws.rs.core.Response;
import java.util.stream.Collectors;
import org.jboss.logging.Logger;

/**
 * SOAP 1.1 faults: Konnektor errors with GERROR detail (TelematikError v2.0) as in the trace
 * popp-kon-tu, HTTP 500.
 */
@ApplicationScoped
public class SoapFaults {

  static final String CONTENT_TYPE = "text/xml; charset=utf-8";

  private static final Logger LOG = Logger.getLogger(SoapFaults.class);

  private final Template template;
  private final VendorProfile vendor;

  SoapFaults(@Location("soap/Fault.xml") Template template, VendorProfile vendor) {
    this.template = template;
    this.vendor = vendor;
  }

  /**
   * {@code SOAP-ENV:Server} with GERROR, error text as faultstring. If the error has its own
   * protocol code (TAB_KON_514-01 note 3) and the vendor profile reports it at the external
   * interface, it is in the GERROR. All details (detail text, shortened request including context,
   * stack trace with cause) go only to the log, never into the response (LIANA-164); MessageID and
   * EventID connect the two. {@code GERROR:Trace/Detail} contains only what the core explicitly
   * sets for the client ({@link ConnectorException#clientDetail(String)}).
   */
  Response connector(ConnectorException e, XmlNode operation) {
    ConnectorError error = e.error();
    String text = e.text();
    if (e.protocolError() != error && vendor.reportsProtocolError(e.protocolError())) {
      error = e.protocolError();
      text = error.text();
    }
    GerrorView gerror = GerrorView.of(error, text, e.clientDetail());
    LOG.warnf(
        e,
        "SOAP-Fault %d an %s: %s; MessageID %s, EventID %s; Anfrage %s",
        error.code(),
        service(operation),
        e.getMessage(),
        gerror.messageId(),
        gerror.eventId(),
        describe(operation));
    return response(
        template
            .data("faultcode", "SOAP-ENV:Server")
            .data("faultstring", text)
            .data("error", gerror)
            .render());
  }

  /**
   * {@code SOAP-ENV:Client} without detail, for requests that are not an operation of the service.
   */
  Response client(String reason) {
    LOG.warnf("SOAP-Fault Client: %s", reason);
    return clientFault(reason);
  }

  /** Like {@link #client(String)} for a request that is not SOAP; with stack trace in the log. */
  Response client(SoapEnvelope.InvalidSoapException e) {
    LOG.warnf(e, "SOAP-Fault Client: %s", e.getMessage());
    return clientFault(e.getMessage());
  }

  private Response clientFault(String reason) {
    return response(
        template
            .data("faultcode", "SOAP-ENV:Client")
            .data("faultstring", reason)
            .data("error", null)
            .render());
  }

  /**
   * {@code Service#Operation}, the service from the namespace ({@code …/SignatureService/v7.4}).
   */
  static String service(XmlNode operation) {
    String[] parts = operation.namespace().split("/");
    String service =
        parts.length >= 2
            ? parts[parts.length - 2] + "/" + parts[parts.length - 1]
            : operation.namespace();
    return service + "#" + operation.name();
  }

  /** Long texts (Base64, certificates) shortened in the log to beginning and length. */
  private static final int TEXT_LIMIT = 64;

  /**
   * The request in compact form: {@code Name[attribute=value]=text} or {@code Name{children}};
   * texts over {@value #TEXT_LIMIT} characters shortened, with their length.
   */
  static String describe(XmlNode node) {
    StringBuilder out = new StringBuilder(node.name());
    if (!node.attributes().isEmpty()) {
      out.append(
          node.attributes().entrySet().stream()
              .map(a -> a.getKey() + "=" + a.getValue())
              .collect(Collectors.joining(", ", "[", "]")));
    }
    if (!node.children().isEmpty()) {
      out.append('{');
      for (int i = 0; i < node.children().size(); i++) {
        out.append(i == 0 ? "" : ", ").append(describe(node.children().get(i)));
      }
      out.append('}');
    } else if (node.text() != null && !node.text().isBlank()) {
      String text = node.text().strip();
      out.append('=')
          .append(
              text.length() <= TEXT_LIMIT
                  ? text
                  : text.substring(0, TEXT_LIMIT) + "… (" + text.length() + " Zeichen)");
    }
    return out.toString();
  }

  /**
   * decision-12: service or operation LIANA does not implement. {@code SOAP-ENV:Client} with
   * service and operation in the faultstring, plus a warning in the log.
   */
  Response unsupported(String service, String operation) {
    String reason = service + ": Operation " + operation + " wird von LIANA nicht unterstützt";
    LOG.warn(reason);
    return clientFault(reason);
  }

  /**
   * decision-12 for a variant of an operation LIANA does not implement, e.g. ReadVSD with online
   * check: {@code SOAP-ENV:Client} with service, operation and reason in the faultstring, plus a
   * warning in the log.
   */
  Response unsupported(String service, String operation, String reason) {
    String text = service + ": Operation " + operation + ": " + reason;
    LOG.warn(text);
    return clientFault(text);
  }

  /**
   * decision-12 for operations LIANA implements only up to the access check: the Aufrufkontext is
   * valid (TUC_KON_000), the business logic behind it is missing. {@code SOAP-ENV:Client} like
   * {@link #unsupported(String, String)}, plus a warning in the log.
   */
  Response afterAccessCheck(String service, String operation) {
    String reason =
        service
            + ": Operation "
            + operation
            + " wird von LIANA nur bis zur Zugriffsprüfung "
            + "(TUC_KON_000) unterstützt, die Fachlogik ist nicht umgesetzt";
    LOG.warn(reason);
    return clientFault(reason);
  }

  private static Response response(String body) {
    return Response.serverError().type(CONTENT_TYPE).entity(body).build();
  }
}

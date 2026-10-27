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
import de.gematik.liana.kern.vsdm.ReadVsd;
import io.quarkus.qute.Location;
import io.quarkus.qute.Template;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Response;
import java.util.Base64;
import java.util.Optional;

/**
 * Fachmodul VSDM, interface I_VSDService (VSDService v5.2) under {@code /ws/VSDService}: ReadVSD
 * ([gemSpec_FM_VSDM] 3.2.1, LIANA-119), with Onlineprüfung and Prüfungsnachweis (LIANA-141). The
 * WSDL gives {@code …/VSDService/v6.0#ReadVSD} as SOAPAction; as with the other services, only the
 * operation after the {@code #} is decisive.
 */
@Path("/ws/VSDService")
public class VsdServiceResource {

  static final String NAMESPACE = "http://ws.gematik.de/conn/vsds/VSDService/v5.2";

  private final ReadVsd readVsd;
  private final Template readResponse;
  private final SoapFaults faults;
  private final RequestCheck requestCheck;

  VsdServiceResource(
      ReadVsd readVsd,
      @Location("soap/ReadVSDResponse.xml") Template readResponse,
      SoapFaults faults,
      RequestCheck requestCheck) {
    this.readVsd = readVsd;
    this.readResponse = readResponse;
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
    if (!name.equals("ReadVSD")) {
      return faults.unsupported("VSDService", name);
    }
    try {
      return readVsd(operation);
    } catch (ReadVsd.Unsupported e) {
      return faults.unsupported("VSDService", "ReadVSD", e.getMessage());
    } catch (ConnectorException e) {
      return faults.connector(e, operation);
    }
  }

  /**
   * ReadVSD: EhcHandle, HpcHandle, PerformOnlineCheck, ReadOnlineReceipt, Context; data and proof
   * of check (gzip) Base64 (VSDM-A_2652).
   */
  private Response readVsd(XmlNode operation) {
    var result =
        readVsd.read(
            EventServiceResource.context(operation),
            required(operation, "EhcHandle"),
            required(operation, "HpcHandle"),
            bool(operation, "PerformOnlineCheck"),
            bool(operation, "ReadOnlineReceipt"));
    Base64.Encoder base64 = Base64.getEncoder();
    return EventServiceResource.ok(
        readResponse
            .data("pd", base64.encodeToString(result.persoenlicheVersichertendaten()))
            .data("vd", base64.encodeToString(result.allgemeineVersicherungsdaten()))
            .data("status", result.status().status())
            .data("timestamp", result.status().timestamp())
            .data("version", result.status().version())
            .data(
                "pruefungsnachweis",
                result.pruefungsnachweis() == null
                    ? null
                    : base64.encodeToString(result.pruefungsnachweis().gzip()))
            .render());
  }

  private static String required(XmlNode operation, String element) {
    return operation
        .childText(element)
        .filter(s -> !s.isEmpty())
        .orElseThrow(() -> ConnectorError.SYNTAX.exception("ReadVSD ohne " + element));
  }

  /** xsd:boolean: true, false, 1, 0. */
  private static boolean bool(XmlNode operation, String element) {
    return switch (required(operation, element)) {
      case "true", "1" -> true;
      case "false", "0" -> false;
      default -> throw ConnectorError.SYNTAX.exception(element + " ist kein xsd:boolean");
    };
  }
}

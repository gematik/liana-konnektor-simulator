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
import de.gematik.liana.kern.vsdm.ReadKvk;
import io.quarkus.qute.Location;
import io.quarkus.qute.Template;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Response;
import java.util.Base64;
import java.util.Optional;

/**
 * Fachmodul VSDM, interface I_KVKService (KvkService v4.0) under {@code /ws/KVKService}: ReadKVK
 * ([gemSpec_FM_VSDM] 3.2.2, LIANA-113). The WSDL gives {@code …/KvkService/v4.0#ReadVDT} as
 * SOAPAction, not {@code #ReadKVK}; the konnektor-service-client of the suites sends exactly that.
 * LIANA accepts both.
 */
@Path("/ws/KVKService")
public class KvkServiceResource {

  static final String NAMESPACE = "http://ws.gematik.de/conn/vsds/KvkService/v4.0";

  /** SOAPAction of the operation ReadKVK according to {@code conn/vsds/KvkService.wsdl}. */
  private static final String WSDL_ACTION = "ReadVDT";

  private final ReadKvk readKvk;
  private final Template readResponse;
  private final SoapFaults faults;
  private final RequestCheck requestCheck;

  KvkServiceResource(
      ReadKvk readKvk,
      @Location("soap/ReadKVKResponse.xml") Template readResponse,
      SoapFaults faults,
      RequestCheck requestCheck) {
    this.readKvk = readKvk;
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
    String action = soapAction == null ? "" : soapAction.strip().replaceAll("^\"|\"$", "");
    boolean readVdt =
        NAMESPACE.equals(operation.namespace())
            && operation.name().equals("ReadKVK")
            && action.substring(action.lastIndexOf('#') + 1).equals(WSDL_ACTION);
    String name =
        readVdt
            ? operation.name()
            : EventServiceResource.operationName(NAMESPACE, soapAction, operation);
    if (name == null) {
      return faults.client(
          "SOAPAction '"
              + soapAction
              + "' passt nicht zu "
              + operation.namespace()
              + "#"
              + operation.name());
    }
    if (!name.equals("ReadKVK")) {
      return faults.unsupported("KVKService", name);
    }
    try {
      // TAB_FM_VSDM ReadKVK: KVKHandle, Context; response KVK as base64Binary (VSDM-A_2609)
      String handle =
          operation
              .childText("KVKHandle")
              .map(String::strip)
              .filter(s -> !s.isEmpty())
              .orElseThrow(() -> ConnectorError.SYNTAX.exception("ReadKVK ohne KVKHandle"));
      byte[] kvk = readKvk.read(EventServiceResource.context(operation), handle);
      return EventServiceResource.ok(
          readResponse.data("kvk", Base64.getEncoder().encodeToString(kvk)).render());
    } catch (ConnectorException e) {
      return faults.connector(e, operation);
    }
  }
}

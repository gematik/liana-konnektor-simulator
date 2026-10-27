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

import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.core.Response;

/**
 * All services under {@code /ws/} for which LIANA has no resource of its own (decision-12): SOAP
 * fault with service and operation from the body instead of the Quarkus 404. The resources of the
 * implemented services have fixed paths and take precedence.
 */
@Path("/ws/{service}")
public class UnsupportedServiceResource {

  private final SoapFaults faults;

  UnsupportedServiceResource(SoapFaults faults) {
    this.faults = faults;
  }

  @POST
  public Response post(@PathParam("service") String service, byte[] body) {
    XmlNode operation;
    try {
      operation = SoapEnvelope.operation(body);
    } catch (SoapEnvelope.InvalidSoapException e) {
      return faults.client(e);
    }
    return faults.unsupported(service, operation.name());
  }
}

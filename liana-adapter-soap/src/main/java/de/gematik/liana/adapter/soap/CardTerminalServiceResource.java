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

import de.gematik.liana.kern.cardterminal.CardTerminalService;
import de.gematik.liana.kern.error.ConnectorError;
import de.gematik.liana.kern.error.ConnectorException;
import io.quarkus.qute.Location;
import io.quarkus.qute.Template;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Response;
import java.util.Optional;

/**
 * Card terminal service CardTerminalService v1.1 under {@code /ws/CardTerminalService}
 * (TIP1-A_5411-02, endpoint from {@code connector.sds}): RequestCard (TIP1-A_5412) and EjectCard
 * (TIP1-A_5413, LIANA-110). The response comes only once the card is inserted or removed, or the
 * waiting time expires. As with the EventService, the operation comes from SOAPAction and body.
 */
@Path("/ws/CardTerminalService")
public class CardTerminalServiceResource {

  static final String NAMESPACE = "http://ws.gematik.de/conn/CardTerminalService/v1.1";

  private final CardTerminalService service;
  private final Template requestResponse;
  private final Template ejectResponse;
  private final SoapFaults faults;
  private final RequestCheck requestCheck;

  CardTerminalServiceResource(
      CardTerminalService service,
      @Location("soap/RequestCardResponse.xml") Template requestResponse,
      @Location("soap/EjectCardResponse.xml") Template ejectResponse,
      SoapFaults faults,
      RequestCheck requestCheck) {
    this.service = service;
    this.requestResponse = requestResponse;
    this.ejectResponse = ejectResponse;
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
        case "RequestCard" -> {
          CardTerminalService.Requested requested =
              service.requestCard(
                  new CardTerminalService.Request(
                      EventServiceResource.context(operation),
                      slot(operation),
                      operation.childText("CardType").orElse(null),
                      displayMsg(operation),
                      number(operation, "TimeOut")));
          yield EventServiceResource.ok(
              requestResponse
                  .data("card", CardView.of(requested.card()))
                  .data("alreadyInserted", requested.alreadyInserted())
                  .render());
        }
        case "EjectCard" -> {
          service.ejectCard(
              new CardTerminalService.Eject(
                  EventServiceResource.context(operation),
                  operation.childText("CardHandle").orElse(null),
                  slot(operation),
                  displayMsg(operation),
                  number(operation, "TimeOut")));
          yield EventServiceResource.ok(ejectResponse.render());
        }
        default -> faults.unsupported("CardTerminalService", name);
      };
    } catch (ConnectorException e) {
      return faults.connector(e, operation);
    }
  }

  /**
   * {@code CT:Slot} with {@code CARDCMN:CtId} and {@code CARDCMN:SlotId}; {@code null} without
   * slot.
   */
  private static CardTerminalService.Slot slot(XmlNode operation) {
    return operation
        .child("Slot")
        .map(
            slot ->
                new CardTerminalService.Slot(
                    slot.childText("CtId").orElse(null),
                    number(slot, "SlotId") == null
                        ? null
                        : Math.toIntExact(number(slot, "SlotId"))))
        .orElse(null);
  }

  /** {@code CT:DisplayMsg} unchanged, also with leading/trailing whitespace. */
  private static String displayMsg(XmlNode operation) {
    return operation.child("DisplayMsg").map(XmlNode::text).orElse(null);
  }

  /** Non-negative integer (xs:nonNegativeInteger); otherwise 4000. */
  private static Long number(XmlNode node, String child) {
    String text = node.childText(child).map(String::strip).orElse(null);
    if (text == null) {
      return null;
    }
    try {
      long value = Long.parseLong(text);
      if (value < 0 || value > Integer.MAX_VALUE) {
        throw new NumberFormatException(text);
      }
      return value;
    } catch (NumberFormatException e) {
      throw ConnectorError.SYNTAX.exception(child + " " + text).causedBy(e);
    }
  }
}

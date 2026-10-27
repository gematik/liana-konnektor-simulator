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

import de.gematik.liana.kern.card.CardSessions;
import de.gematik.liana.kern.card.PinVerification;
import de.gematik.liana.kern.error.ConnectorError;
import de.gematik.liana.kern.error.ConnectorException;
import io.quarkus.qute.Location;
import io.quarkus.qute.Template;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Response;
import java.util.HexFormat;
import java.util.Optional;
import java.util.Set;

/**
 * Card service CardService v8.2 under {@code /ws/CardService} (endpoint from {@code
 * connector.sds}): the PoPP tunnel with StartCardSession, SecureSendAPDU and StopCardSession, plus
 * the PIN operations VerifyPin (SMC-B of the ZETA registration), GetPinStatus, ChangePin,
 * UnblockPin, EnablePin and DisablePin (LIANA-109). As with the EventService, the operation comes
 * from SOAPAction and body.
 *
 * <p>Clients with CardService v8.1 (konnektor-service-client of the eHealth KT suite, LIANA-106)
 * get the same operations except the PoPP tunnel: according to the XSD change history
 * (api-telematik), v8.2.0 only added SecureSendAPDU, StartCardSession and StopCardSession; the PIN
 * operations are the same in v8.1.3. The response is in the namespace of the request; {@code
 * connector.sds} still lists only v8.2.
 */
@Path("/ws/CardService")
public class CardServiceResource {

  static final String NAMESPACE = "http://ws.gematik.de/conn/CardService/v8.2";
  static final String NAMESPACE_V81 = "http://ws.gematik.de/conn/CardService/v8.1";

  /** Added with v8.2.0 (PoPP tunnel), unknown in v8.1. */
  private static final Set<String> ONLY_V82 =
      Set.of("StartCardSession", "SecureSendAPDU", "StopCardSession");

  private static final HexFormat HEX = HexFormat.of().withUpperCase();

  private final CardSessions sessions;
  private final PinVerification pins;
  private final Template startResponse;
  private final Template secureSendResponse;
  private final Template stopResponse;
  private final Template pinResponse;
  private final Template pinStatusResponse;
  private final SoapFaults faults;
  private final RequestCheck requestCheck;

  CardServiceResource(
      CardSessions sessions,
      PinVerification pins,
      @Location("soap/StartCardSessionResponse.xml") Template startResponse,
      @Location("soap/SecureSendAPDUResponse.xml") Template secureSendResponse,
      @Location("soap/StopCardSessionResponse.xml") Template stopResponse,
      @Location("soap/PinResponse.xml") Template pinResponse,
      @Location("soap/GetPinStatusResponse.xml") Template pinStatusResponse,
      SoapFaults faults,
      RequestCheck requestCheck) {
    this.sessions = sessions;
    this.pins = pins;
    this.pinResponse = pinResponse;
    this.pinStatusResponse = pinStatusResponse;
    this.startResponse = startResponse;
    this.secureSendResponse = secureSendResponse;
    this.stopResponse = stopResponse;
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
      name = EventServiceResource.operationName(NAMESPACE_V81, soapAction, operation);
    }
    if (name == null || NAMESPACE_V81.equals(operation.namespace()) && ONLY_V82.contains(name)) {
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
        case "StartCardSession" -> startCardSession(operation);
        case "SecureSendAPDU" -> secureSendApdu(operation);
        case "StopCardSession" -> stopCardSession(operation);
        case "VerifyPin" ->
            pinResponse(
                operation,
                pins.verify(
                    EventServiceResource.context(operation),
                    cardHandle(operation),
                    pinTyp(operation)));
        case "GetPinStatus" -> getPinStatus(operation);
        case "ChangePin" ->
            pinResponse(
                operation,
                pins.change(
                    EventServiceResource.context(operation),
                    cardHandle(operation),
                    pinTyp(operation)));
        case "UnblockPin" ->
            pinResponse(
                operation,
                pins.unblock(
                    EventServiceResource.context(operation),
                    cardHandle(operation),
                    pinTyp(operation),
                    setNewPin(operation)));
        case "EnablePin", "DisablePin" ->
            pinResponse(
                operation,
                pins.protect(
                    EventServiceResource.context(operation),
                    cardHandle(operation),
                    pinTyp(operation),
                    name.equals("EnablePin")));
        default -> faults.unsupported("CardService", name);
      };
    } catch (ConnectorException e) {
      return faults.connector(e, operation);
    }
  }

  /** A_25970-01, TAB_KON_273: Context, CardHandle. */
  private Response startCardSession(XmlNode operation) {
    String sessionId =
        sessions.start(
            EventServiceResource.context(operation),
            operation.childText("CardHandle").orElse(null));
    return EventServiceResource.ok(startResponse.data("sessionId", sessionId).render());
  }

  /**
   * A_25822-02, TAB_KON_270: SignedScenario; an unexpected status word reports 4284 as WARNING in
   * the status.
   */
  private Response secureSendApdu(XmlNode operation) {
    var result = sessions.secureSend(operation.childText("SignedScenario").orElse(null));
    var warning =
        result.apduNotProcessed()
            ? GerrorView.of(
                ConnectorError.APDU_NOT_PROCESSED, ConnectorError.APDU_NOT_PROCESSED.text())
            : null;
    return EventServiceResource.ok(
        secureSendResponse
            .data("responseApdus", result.responseApdus().stream().map(HEX::formatHex).toList())
            .data("timeSpan", result.timeSpan())
            .data("warning", warning)
            .render());
  }

  /**
   * VerifyPin (TIP1-A_4587), ChangePin (TIP1-A_4588), UnblockPin (TIP1-A_4590), EnablePin and
   * DisablePin (TIP1-A_5487): CARDCMN:PinResponseType with Status, PinResult and LeftTries; the
   * result of the PIN entry is not an error.
   */
  private Response pinResponse(XmlNode operation, PinVerification.Result result) {
    return EventServiceResource.ok(
        pinResponse
            .data("namespace", operation.namespace())
            .data("operation", operation.name())
            .data("pinResult", result.pinResult().name())
            .data("leftTries", result.leftTries())
            .render());
  }

  private static String cardHandle(XmlNode operation) {
    return operation.childText("CardHandle").orElse(null);
  }

  private static String pinTyp(XmlNode operation) {
    return operation.childText("PinTyp").orElse(null);
  }

  /** TAB_KON_053 SetNewPin (xs:boolean): false if absent; otherwise 4000. */
  private static boolean setNewPin(XmlNode operation) {
    String value = operation.childText("SetNewPin").map(String::strip).orElse("false");
    return switch (value) {
      case "true", "1" -> true;
      case "false", "0" -> false;
      default -> throw ConnectorError.SYNTAX.exception("SetNewPin " + value);
    };
  }

  /** TIP1-A_4589, TAB_KON_051: Context, CardHandle, PinTyp → PinStatus, LeftTries. */
  private Response getPinStatus(XmlNode operation) {
    var status =
        pins.status(
            EventServiceResource.context(operation), cardHandle(operation), pinTyp(operation));
    return EventServiceResource.ok(
        pinStatusResponse
            .data("namespace", operation.namespace())
            .data("pinStatus", status.pinStatus().name())
            .data("leftTries", status.leftTries())
            .render());
  }

  /** A_26022, TAB_KON_275: SessionId. */
  private Response stopCardSession(XmlNode operation) {
    sessions.stop(operation.childText("SessionId").orElse(null));
    return EventServiceResource.ok(stopResponse.render());
  }
}

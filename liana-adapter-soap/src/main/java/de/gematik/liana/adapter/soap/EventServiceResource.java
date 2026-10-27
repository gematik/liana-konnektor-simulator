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

import de.gematik.liana.kern.access.Context;
import de.gematik.liana.kern.error.ConnectorError;
import de.gematik.liana.kern.error.ConnectorException;
import de.gematik.liana.kern.event.GetCardTerminals;
import de.gematik.liana.kern.event.GetCards;
import de.gematik.liana.kern.event.GetResourceInformation;
import de.gematik.liana.kern.event.Subscription;
import de.gematik.liana.kern.event.Subscriptions;
import io.quarkus.qute.Location;
import io.quarkus.qute.Template;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Response;
import java.util.List;
import java.util.Optional;

/**
 * Event service EventService v7.2 under {@code /ws/EventService} (endpoint from {@code
 * connector.sds}): GetCards, GetCardTerminals (LIANA-108), GetResourceInformation (LIANA-187),
 * Subscribe, Unsubscribe, RenewSubscriptions, GetSubscription (LIANA-59). The operation comes from
 * the SOAPAction ({@code <Namespace>#<Operation>}), without SOAPAction from the first body element.
 */
@Path("/ws/EventService")
public class EventServiceResource {

  static final String NAMESPACE = "http://ws.gematik.de/conn/EventService/v7.2";

  private final GetCards getCards;
  private final GetCardTerminals getCardTerminals;
  private final GetResourceInformation getResourceInformation;
  private final Template getResourceInformationResponse;
  private final Template getCardTerminalsResponse;
  private final java.time.Clock clock;
  private final Subscriptions subscriptions;
  private final Template getCardsResponse;
  private final Template subscribeResponse;
  private final Template unsubscribeResponse;
  private final Template renewResponse;
  private final Template getSubscriptionResponse;
  private final SoapFaults faults;
  private final RequestCheck requestCheck;

  EventServiceResource(
      GetCards getCards,
      GetCardTerminals getCardTerminals,
      GetResourceInformation getResourceInformation,
      Subscriptions subscriptions,
      @Location("soap/GetCardsResponse.xml") Template getCardsResponse,
      @Location("soap/GetResourceInformationResponse.xml") Template getResourceInformationResponse,
      @Location("soap/GetCardTerminalsResponse.xml") Template getCardTerminalsResponse,
      @Location("soap/SubscribeResponse.xml") Template subscribeResponse,
      @Location("soap/UnsubscribeResponse.xml") Template unsubscribeResponse,
      @Location("soap/RenewSubscriptionsResponse.xml") Template renewResponse,
      @Location("soap/GetSubscriptionResponse.xml") Template getSubscriptionResponse,
      SoapFaults faults,
      RequestCheck requestCheck) {
    this.getCards = getCards;
    this.getCardTerminals = getCardTerminals;
    this.getResourceInformation = getResourceInformation;
    this.getResourceInformationResponse = getResourceInformationResponse;
    this.getCardTerminalsResponse = getCardTerminalsResponse;
    this.clock = java.time.Clock.systemUTC();
    this.subscriptions = subscriptions;
    this.getCardsResponse = getCardsResponse;
    this.subscribeResponse = subscribeResponse;
    this.unsubscribeResponse = unsubscribeResponse;
    this.renewResponse = renewResponse;
    this.getSubscriptionResponse = getSubscriptionResponse;
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
    String name = operationName(NAMESPACE, soapAction, operation);
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
        case "GetCards" ->
            ok(
                getCardsResponse
                    .data(
                        "cards",
                        getCards.execute(getCards(operation)).stream().map(CardView::of).toList())
                    .render());
        case "GetCardTerminals" ->
            ok(
                getCardTerminalsResponse
                    .data(
                        "terminals",
                        getCardTerminals
                            .execute(context(operation), flag(operation, "mandant-wide"))
                            .stream()
                            .map(CardTerminalView::of)
                            .toList())
                    .data("informationDate", informationDate())
                    .render());
        case "GetResourceInformation" -> {
          GetResourceInformation.Result result =
              getResourceInformation.execute(getResourceInformation(operation));
          yield ok(
              getResourceInformationResponse
                  .data("card", result.card() == null ? null : CardView.of(result.card()))
                  .data(
                      "kt",
                      result.terminal() == null ? null : CardTerminalView.of(result.terminal()))
                  .data(
                      "connector",
                      result.connector() == null ? null : ConnectorView.of(result.connector()))
                  .data("informationDate", informationDate())
                  .render());
        }
        case "Subscribe" ->
            ok(
                subscribeResponse
                    .data("subscription", SubscriptionView.of(subscribe(operation)))
                    .render());
        case "Unsubscribe" -> {
          subscriptions.unsubscribe(
              context(operation),
              operation.childText("SubscriptionID").orElse(null),
              operation.childText("EventTo").orElse(null));
          yield ok(unsubscribeResponse.render());
        }
        case "RenewSubscriptions" -> renew(operation);
        case "GetSubscription" ->
            ok(
                getSubscriptionResponse
                    .data(
                        "subscriptions",
                        subscriptions
                            .get(
                                context(operation),
                                operation.childText("SubscriptionID").orElse(null),
                                flag(operation, "mandant-wide"))
                            .stream()
                            .map(SubscriptionView::of)
                            .toList())
                    .render());
        default -> faults.unsupported("EventService", name);
      };
    } catch (ConnectorException e) {
      return faults.connector(e, operation);
    }
  }

  /**
   * Operation from body and SOAPAction; {@code null} if the body is not in {@code namespace} or the
   * SOAPAction names a different operation. The body is decisive: LIANA does not evaluate the
   * namespace in the SOAPAction; popp-client 2.9.0 sends {@code CertificateService/v8.2#…} for
   * ReadCardCertificate (v6.0).
   */
  static String operationName(String namespace, String soapAction, XmlNode operation) {
    if (!namespace.equals(operation.namespace())) {
      return null;
    }
    String action = soapAction == null ? "" : soapAction.strip().replaceAll("^\"|\"$", "");
    if (action.isEmpty()) {
      return operation.name();
    }
    return action.substring(action.lastIndexOf('#') + 1).equals(operation.name())
        ? operation.name()
        : null;
  }

  /** TAB_KON_565: Context, CtId, SlotId, CardType, @mandant-wide. */
  static GetCards.Request getCards(XmlNode operation) {
    var context = context(operation);
    Integer slotId;
    try {
      slotId = operation.childText("SlotId").map(Integer::valueOf).orElse(null);
    } catch (NumberFormatException e) {
      throw ConnectorError.SYNTAX
          .exception("SlotId " + operation.childText("SlotId").orElse(""))
          .causedBy(e);
    }
    return new GetCards.Request(
        context,
        operation.childText("CtId").orElse(null),
        slotId,
        operation.childText("CardType").orElse(null),
        flag(operation, "mandant-wide"));
  }

  /** TAB_KON_568: Context, CtId, SlotId, Iccsn, CardHandle. */
  static GetResourceInformation.Request getResourceInformation(XmlNode operation) {
    Integer slotId;
    try {
      slotId = operation.childText("SlotId").map(String::strip).map(Integer::valueOf).orElse(null);
    } catch (NumberFormatException e) {
      throw ConnectorError.SYNTAX
          .exception("SlotId " + operation.childText("SlotId").orElse(""))
          .causedBy(e);
    }
    return new GetResourceInformation.Request(
        context(operation),
        text(operation, "CtId"),
        slotId,
        text(operation, "Iccsn"),
        text(operation, "CardHandle"));
  }

  private static String text(XmlNode operation, String name) {
    return operation.childText(name).map(String::strip).filter(t -> !t.isEmpty()).orElse(null);
  }

  private String informationDate() {
    return java.time.format.DateTimeFormatter.ISO_INSTANT.format(
        clock.instant().truncatedTo(java.time.temporal.ChronoUnit.SECONDS));
  }

  /**
   * TAB_KON_571: SubscriptionID and TerminationTime in the element Subscription must not be used
   * (4000).
   */
  private Subscription subscribe(XmlNode operation) {
    XmlNode subscription =
        operation
            .child("Subscription")
            .orElseThrow(() -> ConnectorError.SYNTAX.exception("Subscribe ohne Subscription"));
    if (subscription.child("SubscriptionID").isPresent()
        || subscription.child("TerminationTime").isPresent()) {
      throw ConnectorError.SYNTAX.exception("Subscribe mit SubscriptionID oder TerminationTime");
    }
    return subscriptions.subscribe(
        context(operation),
        subscription.childText("EventTo").orElse(null),
        subscription.childText("Topic").orElse(null),
        subscription.childText("Filter").orElse(null));
  }

  /**
   * TAB_KON_793: invalid SubscriptionIDs next to valid ones → warning 4102, the invalid ones in the
   * error text.
   */
  private Response renew(XmlNode operation) {
    List<String> ids =
        operation.children().stream()
            .filter(c -> c.name().equals("SubscriptionID"))
            .map(c -> c.text().strip())
            .toList();
    Subscriptions.Renewal renewal = subscriptions.renew(context(operation), ids);
    GerrorView warning =
        renewal.invalid().isEmpty()
            ? null
            : GerrorView.of(
                ConnectorError.INVALID_SUBSCRIPTION,
                ConnectorError.INVALID_SUBSCRIPTION.text()
                    + ": "
                    + String.join(", ", renewal.invalid()));
    return ok(
        renewResponse
            .data("renewed", renewal.renewed().stream().map(SubscriptionView::of).toList())
            .data("warning", warning)
            .render());
  }

  /** Boolean attribute per XSD ({@code true} or {@code 1}), default false. */
  private static boolean flag(XmlNode operation, String attribute) {
    String value = operation.attributes().getOrDefault(attribute, "false").strip();
    return value.equals("true") || value.equals("1");
  }

  /** {@code CCTX:Context} of the operation; missing values are {@code null}. */
  static Context context(XmlNode operation) {
    return operation
        .child("Context")
        .map(
            c ->
                new Context(
                    c.childText("MandantId").orElse(null),
                    c.childText("ClientSystemId").orElse(null),
                    c.childText("WorkplaceId").orElse(null),
                    c.childText("UserId").orElse(null)))
        .orElse(new Context(null, null, null, null));
  }

  static Response ok(String body) {
    return Response.ok(body, SoapFaults.CONTENT_TYPE).build();
  }
}

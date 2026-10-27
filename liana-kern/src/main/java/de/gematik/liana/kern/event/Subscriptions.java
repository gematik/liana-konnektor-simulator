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
package de.gematik.liana.kern.event;

import de.gematik.liana.kern.access.Context;
import de.gematik.liana.kern.access.Infomodel;
import de.gematik.liana.kern.error.ConnectorError;
import de.gematik.liana.kern.error.ConnectorException;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
 * Subscription management of the system information service (gemSpec_Kon 4.1.6): the operations
 * Subscribe (TIP1-A_4608), Unsubscribe (TIP1-A_4609), RenewSubscriptions (TIP1-A_5112) and
 * GetSubscription (TIP1-A_4610) and the delivery to Clientsysteme from TUC_KON_256 (TIP1-A_4598-02,
 * steps 5 and 6). In memory only: the connector starts with an empty list (TIP1-A_4613); LIANA does
 * not emit BOOTUP/BOOTUP_COMPLETE. No upper limit (TIP1-A_4612 requires at least 999).
 */
public final class Subscriptions {

  /** TAB_KON_571: TerminationTime = system time + 25 h. */
  static final Duration LIFETIME = Duration.ofHours(25);

  /**
   * XSD: TopicType and FilterType at most 1024 characters, RenewSubscriptions at most 1000
   * SubscriptionIDs.
   */
  private static final int MAX_TEXT = 1024;

  private static final int MAX_RENEWALS = 1000;

  /**
   * Result of RenewSubscriptions: renewed subscriptions and invalid SubscriptionIDs (TAB_KON_793).
   */
  public record Renewal(List<Subscription> renewed, List<String> invalid) {}

  /**
   * Last delivery attempt to a subscription (TUC_KON_256 step 6), for the Admin API (LIANA-149):
   * time, topic of the event, success and, on failure, the reason; an event discarded by the filter
   * does not count.
   */
  public record Delivery(Instant time, String topic, boolean delivered, String error) {}

  /**
   * The list of subscriptions or a delivery attempt has changed (Admin API push, LIANA-151): {@code
   * cause} subscribe, unsubscribe, renew, delivery, auto-unsubscribe, expired or reset; {@code
   * subscriptionId} {@code null} if several are affected.
   */
  public record Change(String cause, String subscriptionId) {}

  private final Infomodel infomodel;
  private final Clock clock;
  private final EventSink sink;
  private final int maxTry;
  private final Map<String, Subscription> subscriptions = new LinkedHashMap<>();

  /** Consecutive failed deliveries per Ereignissenke. */
  private final Map<String, Integer> failures = new HashMap<>();

  /** Last delivery attempt per SubscriptionID. */
  private final Map<String, Delivery> deliveries = new HashMap<>();

  private final List<Consumer<Change>> listeners = new CopyOnWriteArrayList<>();

  /**
   * @param maxTry EVT_MAX_TRY (TAB_KON_580): after that many consecutive failed deliveries LIANA
   *     removes all subscriptions of the Ereignissenke („Auto-Unsubscribe“, TAB_KON_571)
   */
  public Subscriptions(Infomodel infomodel, Clock clock, EventSink sink, int maxTry) {
    if (maxTry < 1) {
      throw new IllegalArgumentException("EVT_MAX_TRY " + maxTry + " kleiner 1");
    }
    this.infomodel = infomodel;
    this.clock = clock;
    this.sink = sink;
    this.maxTry = maxTry;
  }

  /**
   * From now on reports every {@link Change} to {@code listener}; called under the lock, so it must
   * not block.
   */
  public void addListener(Consumer<Change> listener) {
    listeners.add(listener);
  }

  /**
   * TAB_KON_572: checkArguments, TUC_KON_000 with allWorkplaces = true, saveSubscription. If the
   * subscription already exists (same context, EventTo, topic and filter), it is returned with a
   * new TerminationTime.
   */
  public synchronized Subscription subscribe(
      Context context, String eventTo, String topic, String filter) {
    checkEventTo(eventTo);
    if (topic == null || topic.isBlank() || topic.length() > MAX_TEXT) {
      throw ConnectorError.SYNTAX.exception("Topic '" + topic + "'");
    }
    if (filter != null && (filter.isBlank() || filter.length() > MAX_TEXT)) {
      throw ConnectorError.SYNTAX.exception("Filter '" + filter + "'");
    }
    infomodel.checkAccess(context, true);
    removeExpired();
    Instant termination = terminationTime();
    for (Subscription existing : subscriptions.values()) {
      if (sameContext(existing.context(), context, false)
          && existing.eventTo().equals(eventTo)
          && existing.topic().equals(topic)
          && Objects.equals(existing.filter(), filter)) {
        Subscription renewed = existing.renewed(termination);
        subscriptions.put(renewed.id(), renewed);
        changed("subscribe", renewed.id());
        return renewed;
      }
    }
    Subscription subscription =
        new Subscription(
            UUID.randomUUID().toString(), termination, context, eventTo, topic, filter);
    subscriptions.put(subscription.id(), subscription);
    changed("subscribe", subscription.id());
    return subscription;
  }

  /**
   * TAB_KON_575: removes the subscription {@code subscriptionId} (unknown: 4102) or all
   * subscriptions for the Ereignissenke {@code eventTo}; exactly one of the two is set.
   */
  public synchronized void unsubscribe(Context context, String subscriptionId, String eventTo) {
    if ((subscriptionId == null) == (eventTo == null)) {
      throw ConnectorError.SYNTAX.exception("SubscriptionID oder EventTo, genau eins");
    }
    if (eventTo != null) {
      checkEventTo(eventTo);
    }
    infomodel.checkAccess(context, true);
    removeExpired();
    if (subscriptionId != null) {
      if (subscriptions.remove(subscriptionId) == null) {
        throw ConnectorError.INVALID_SUBSCRIPTION.exception(subscriptionId);
      }
      changed("unsubscribe", subscriptionId);
      return;
    }
    if (subscriptions.values().removeIf(s -> s.eventTo().equals(eventTo))) {
      changed("unsubscribe", null);
    }
  }

  /**
   * TAB_KON_793: removes expired subscriptions and extends every valid one by 25 h; if no
   * SubscriptionID is valid, 4102, otherwise the invalid ones in the result (the adapter reports
   * them as a warning).
   */
  public synchronized Renewal renew(Context context, List<String> subscriptionIds) {
    if (subscriptionIds.isEmpty() || subscriptionIds.size() > MAX_RENEWALS) {
      throw ConnectorError.SYNTAX.exception(subscriptionIds.size() + " SubscriptionIDs");
    }
    infomodel.checkAccess(context, true);
    removeExpired();
    Instant termination = terminationTime();
    List<Subscription> renewed = new ArrayList<>();
    List<String> invalid = new ArrayList<>();
    for (String id : subscriptionIds) {
      Subscription subscription = subscriptions.get(id);
      if (subscription == null) {
        invalid.add(id);
      } else {
        subscription = subscription.renewed(termination);
        subscriptions.put(id, subscription);
        renewed.add(subscription);
      }
    }
    if (renewed.isEmpty()) {
      throw ConnectorError.INVALID_SUBSCRIPTION.exception(String.join(", ", invalid));
    }
    changed("renew", renewed.size() == 1 ? renewed.get(0).id() : null);
    return new Renewal(renewed, invalid);
  }

  /**
   * TAB_KON_578: TUC_KON_000 with allWorkplaces = {@code mandantWide}, then the subscription {@code
   * subscriptionId} (unknown: 4102) or all subscriptions of mandant and Clientsystem, without
   * {@code mandantWide} also of the workplace.
   */
  public synchronized List<Subscription> get(
      Context context, String subscriptionId, boolean mandantWide) {
    infomodel.checkAccess(context, mandantWide);
    removeExpired();
    if (subscriptionId != null) {
      return List.of(
          Optional.ofNullable(subscriptions.get(subscriptionId))
              .orElseThrow(() -> ConnectorError.INVALID_SUBSCRIPTION.exception(subscriptionId)));
    }
    return subscriptions.values().stream()
        .filter(s -> sameContext(s.context(), context, mandantWide))
        .toList();
  }

  /**
   * TUC_KON_256 steps 5 and 6 for {@code event}: valid subscriptions whose topic is a prefix of the
   * event topic (5a, case-insensitive) and whose context reaches the CT from the parameter CtID
   * (5b, TUC_KON_000 with allWorkplaces = false) go to the {@link EventSink}; it checks the filter
   * (5c).
   */
  public void publish(Event event) {
    List<Subscription> targets;
    synchronized (this) {
      removeExpired();
      targets = List.copyOf(subscriptions.values());
    }
    String topic = event.topic().toLowerCase(Locale.ROOT);
    Optional<String> ctId = event.parameter("ctId");
    for (Subscription subscription : targets) {
      if (topic.startsWith(subscription.topic().toLowerCase(Locale.ROOT))
          && allowed(subscription, ctId)) {
        sink.send(event, subscription, outcome(subscription, event.topic()));
      }
    }
  }

  /** All subscriptions, for the Admin API and tests. */
  public synchronized List<Subscription> all() {
    removeExpired();
    return List.copyOf(subscriptions.values());
  }

  /**
   * Last delivery attempt to the subscription {@code subscriptionId}; empty as long as none took
   * place.
   */
  public synchronized Optional<Delivery> lastDelivery(String subscriptionId) {
    return Optional.ofNullable(deliveries.get(subscriptionId));
  }

  /** Admin reset (decision-4): empty list as on bootup (TIP1-A_4613). */
  public synchronized void clear() {
    subscriptions.clear();
    failures.clear();
    deliveries.clear();
    changed("reset", null);
  }

  private boolean allowed(Subscription subscription, Optional<String> ctId) {
    try {
      Set<String> reachable = infomodel.checkAccess(subscription.context(), false);
      return ctId.map(reachable::contains).orElse(true);
    } catch (ConnectorException e) {
      return false;
    }
  }

  private EventSink.Outcome outcome(Subscription subscription, String topic) {
    String eventTo = subscription.eventTo();
    return new EventSink.Outcome() {
      @Override
      public void delivered() {
        synchronized (Subscriptions.this) {
          failures.remove(eventTo);
          record(new Delivery(clock.instant(), topic, true, null));
        }
      }

      @Override
      public void failed(String reason) {
        synchronized (Subscriptions.this) {
          record(new Delivery(clock.instant(), topic, false, reason));
          if (failures.merge(eventTo, 1, Integer::sum) >= maxTry) {
            failures.remove(eventTo);
            subscriptions.values().removeIf(s -> s.eventTo().equals(eventTo));
            deliveries.keySet().retainAll(subscriptions.keySet());
            changed("auto-unsubscribe", null);
          }
        }
      }

      private void record(Delivery delivery) {
        if (subscriptions.containsKey(subscription.id())) {
          deliveries.put(subscription.id(), delivery);
          changed("delivery", subscription.id());
        }
      }
    };
  }

  /** TAB_KON_571: {@code cetp://host:port}. */
  private static void checkEventTo(String eventTo) {
    try {
      URI uri = new URI(eventTo);
      if (!"cetp".equals(uri.getScheme())
          || uri.getHost() == null
          || uri.getPort() < 1
          || uri.getPort() > 65535
          || !(uri.getRawPath() == null || uri.getRawPath().isEmpty())) {
        throw ConnectorError.SYNTAX.exception(
            "EventTo '" + eventTo + "', erwartet cetp://host:port");
      }
    } catch (URISyntaxException | NullPointerException e) {
      throw ConnectorError.SYNTAX
          .exception("EventTo '" + eventTo + "', erwartet cetp://host:port")
          .causedBy(e);
    }
  }

  private static boolean sameContext(Context a, Context b, boolean mandantWide) {
    return Objects.equals(a.mandantId(), b.mandantId())
        && Objects.equals(a.clientSystemId(), b.clientSystemId())
        && (mandantWide || Objects.equals(a.workplaceId(), b.workplaceId()));
  }

  private Instant terminationTime() {
    return clock.instant().plus(LIFETIME).truncatedTo(ChronoUnit.SECONDS);
  }

  /** TAB_KON_571 postcondition: expired subscriptions no longer apply. */
  private void removeExpired() {
    Instant now = clock.instant();
    if (subscriptions.values().removeIf(s -> !s.terminationTime().isAfter(now))) {
      deliveries.keySet().retainAll(subscriptions.keySet());
      changed("expired", null);
    }
  }

  private void changed(String cause, String subscriptionId) {
    Change change = new Change(cause, subscriptionId);
    listeners.forEach(listener -> listener.accept(change));
  }
}

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
package de.gematik.liana.konnektor;

import de.gematik.liana.konnektor.ws.conn.eventservice.v7_2.Subscribe;
import de.gematik.liana.konnektor.ws.conn.eventservice.v7_2.SubscribeResponse;
import de.gematik.liana.konnektor.ws.conn.eventservice.v7_2.SubscriptionType;
import de.gematik.liana.konnektor.ws.conn.eventservice.v7_2.Unsubscribe;
import de.gematik.liana.konnektor.ws.conn.eventservice.v7_2.UnsubscribeResponse;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Predicate;

/**
 * Konnektor events (LIANA-137): subscription via Subscribe (TUC_KON_256) with {@code EventTo}
 * pointing to the client's own Ereignissenke ({@link EventSink}), reception via CETP, waiting for
 * events and cards. The sink starts on the first call; {@link #close()} unsubscribes all
 * subscriptions and stops it.
 */
public final class Events implements AutoCloseable {

  private final Konnektor kon;
  private final EventSink sink;
  private final List<KonnektorEvent> received = new ArrayList<>();
  private final List<Subscription> subscriptions = new CopyOnWriteArrayList<>();
  private CetpServer server;

  Events(Konnektor kon, EventSink sink) {
    this.kon = kon;
    this.sink = sink;
  }

  /** {@code cetp://host:port} of the sink; starts it if needed. */
  public synchronized String eventTo() {
    if (server == null) {
      try {
        server = new CetpServer(sink, this::deliver);
      } catch (IOException e) {
        throw new UncheckedIOException("Ereignissenke nicht startbar", e);
      }
    }
    return "cetp://" + sink.host() + ":" + server.port();
  }

  /** Subscribe for a topic, such as {@code CARD/INSERTED} or {@code CARD} (all card events). */
  public Subscription subscribe(String topic) {
    return subscribe(topic, null);
  }

  /** Subscribe with an XPath filter on the event XML (TUC_KON_256 step 6). */
  public Subscription subscribe(String topic, String filter) {
    Subscribe request = new Subscribe();
    request.setContext(Jaxb.context(kon.context()));
    SubscriptionType subscription = new SubscriptionType();
    subscription.setEventTo(eventTo());
    subscription.setTopic(topic);
    subscription.setFilter(filter);
    request.setSubscription(subscription);
    SubscribeResponse response = kon.invoke(Operation.SUBSCRIBE, request, SubscribeResponse.class);
    Subscription result =
        new Subscription(
            response.getSubscriptionID(),
            topic,
            response.getTerminationTime() == null
                ? null
                : response.getTerminationTime().toGregorianCalendar().toInstant());
    subscriptions.add(result);
    return result;
  }

  /** Unsubscribe. */
  public void unsubscribe(Subscription subscription) {
    Unsubscribe request = new Unsubscribe();
    request.setContext(Jaxb.context(kon.context()));
    request.setSubscriptionID(subscription.id());
    kon.invoke(Operation.UNSUBSCRIBE, request, UnsubscribeResponse.class);
    subscriptions.remove(subscription);
  }

  /** All events received so far. */
  public synchronized List<KonnektorEvent> received() {
    return List.copyOf(received);
  }

  /**
   * Waits for the first event from now on that satisfies {@code match}; empty after {@code
   * timeout}.
   */
  public Optional<KonnektorEvent> await(Predicate<KonnektorEvent> match, Duration timeout) {
    int from;
    synchronized (this) {
      from = received.size();
    }
    return awaitFrom(from, match, timeout);
  }

  /**
   * Waits until a card of the type is inserted: subscribes to {@code CARD/INSERTED}, then checks
   * via GetCards (the card may already be inserted) and otherwise waits for the event.
   *
   * @param cardType such as {@code EGK} or {@code SM-B}
   * @throws KonnektorException if no card arrives within {@code timeout}
   */
  public Card awaitCard(String cardType, Duration timeout) {
    int from;
    synchronized (this) {
      from = received.size();
    }
    if (subscriptions.stream()
        .noneMatch(s -> s.topic().equals("CARD/INSERTED") || s.topic().equals("CARD"))) {
      subscribe("CARD/INSERTED");
    }
    List<Card> present = kon.cards().ofType(cardType);
    if (!present.isEmpty()) {
      return present.get(0);
    }
    KonnektorEvent event =
        awaitFrom(
                from,
                e ->
                    "CARD/INSERTED".equals(e.topic())
                        && cardType.equals(e.parameters().get("CardType")),
                timeout)
            .orElseThrow(
                () ->
                    new KonnektorException(
                        "awaitCard "
                            + cardType
                            + ": keine Karte nach "
                            + timeout.toSeconds()
                            + " s"));
    String handle = event.parameters().get("CardHandle");
    return kon.cards()
        .byHandle(handle)
        .orElseGet(
            () ->
                new Card(
                    handle,
                    cardType,
                    event.parameters().get("ICCSN"),
                    event.parameters().get("CtID"),
                    Integer.parseInt(event.parameters().getOrDefault("SlotID", "0")),
                    Instant.now(),
                    event.parameters().get("CardHolderName"),
                    event.parameters().get("KVNR"),
                    null));
  }

  private synchronized Optional<KonnektorEvent> awaitFrom(
      int from, Predicate<KonnektorEvent> match, Duration timeout) {
    long end = System.nanoTime() + timeout.toNanos();
    int index = from;
    while (true) {
      for (; index < received.size(); index++) {
        if (match.test(received.get(index))) {
          return Optional.of(received.get(index));
        }
      }
      long left = end - System.nanoTime();
      if (left <= 0) {
        return Optional.empty();
      }
      try {
        wait(Math.max(1, left / 1_000_000));
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        return Optional.empty();
      }
    }
  }

  private synchronized void deliver(KonnektorEvent event) {
    received.add(event);
    notifyAll();
  }

  @Override
  public void close() {
    for (Subscription subscription : subscriptions) {
      try {
        unsubscribe(subscription);
      } catch (RuntimeException e) {
        // Unsubscribing is best effort; the Konnektor unsubscribes dead sinks itself (EVT_MAX_TRY)
      }
    }
    synchronized (this) {
      if (server != null) {
        server.close();
        server = null;
      }
    }
  }
}

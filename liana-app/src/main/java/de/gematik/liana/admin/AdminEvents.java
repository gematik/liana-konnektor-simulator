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
package de.gematik.liana.admin;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.liana.adapter.fake.FakeTerminals;
import de.gematik.liana.config.LianaConfig;
import de.gematik.liana.kern.card.CardList;
import de.gematik.liana.kern.card.CardSessions;
import de.gematik.liana.kern.card.PinVerification;
import de.gematik.liana.kern.event.Event;
import de.gematik.liana.kern.event.Subscriptions;
import de.gematik.liana.kern.event.SystemLog;
import de.gematik.liana.kms.KmsChanged;
import io.quarkus.runtime.ShutdownEvent;
import io.quarkus.runtime.Startup;
import io.quarkus.runtime.annotations.RegisterForReflection;
import io.vertx.core.Context;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.json.Json;
import io.vertx.ext.web.RoutingContext;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Singleton;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import org.jboss.logging.Logger;

/**
 * Push of the admin API as server-sent events under {@code GET /admin/events} (LIANA-150), so that
 * the Control Center updates without polling. Event kinds:
 *
 * <ul>
 *   <li>{@code log}: every new entry in the Systemprotokoll (TUC_KON_271), fields as in {@code GET
 *       /admin/log},
 *   <li>{@code card}: CARD/INSERTED, CARD/REMOVED, CARD/PIN/* (TUC_KON_256, also without an entry
 *       in the Systemprotokoll) and CARD/SESSION/TIMEOUT with topic and parameters as for client
 *       systems,
 *   <li>{@code terminal}: a CT has changed (CT/* entry, display, card, fault, PIN script, pairing),
 *       with cause and the CT as in {@code GET /admin/terminals/{id}},
 *   <li>{@code state}: vendor profile or strict, management settings, reset, a writing call to the
 *       KMS (settings, TLS, certificates); with profile and settings afterwards,
 *   <li>{@code subscription}: subscriptions of the Clientsysteme (Subscribe, Unsubscribe, Renew,
 *       expiry, auto-unsubscribe) or a delivery attempt via CETP, with cause and SubscriptionID
 *       (LIANA-151),
 *   <li>{@code session}: a card session has started or ended (A_25970-01, TUC_KON_224), LIANA-151.
 * </ul>
 *
 * Every event has an ID {@code <start>-<n>}; a ring buffer holds the last {@code
 * liana.admin.events.buffer}. A stream with {@code Last-Event-ID} (header that the browser sets on
 * reconnect, or query {@code lastEventId}) first receives all later events; if the ID is no longer
 * in the buffer or comes from an earlier start, a {@code resync}, after which the client reloads.
 * Events are created and sent out in a single thread, so ordering and resumption have no gaps. A
 * heartbeat comment keeps proxies open; at most {@code liana.admin.events.max-streams} streams,
 * beyond that 503. A stream whose write buffer is full is closed; the client resumes with
 * Last-Event-ID.
 */
@Startup
@Singleton
public class AdminEvents {

  private static final Logger LOG = Logger.getLogger(AdminEvents.class);

  static final String PATH = "/admin/events";

  /** Kinds of events as they appear in the field {@code event}. */
  static final String LOG_EVENT = "log";

  static final String CARD = "card";
  static final String TERMINAL = "terminal";
  static final String STATE = "state";
  static final String SUBSCRIPTION = "subscription";
  static final String SESSION = "session";
  static final String RESYNC = "resync";

  /** {@code card}: topic and parameters of the event according to TUC_KON_256. */
  @RegisterForReflection
  public record CardChange(String topic, Map<String, String> parameters) {}

  /**
   * {@code terminal}: cause (e.g. CT/CONNECTED, display, fault) and the CT afterwards; {@code null}
   * if unknown.
   */
  @RegisterForReflection
  public record TerminalChange(String id, String cause, AdminApi.Terminal terminal) {}

  /** {@code state}: cause (vendor, settings, reset) and the state afterwards. */
  @RegisterForReflection
  public record StateChange(
      String cause, AdminApi.VendorState vendor, AdminApi.Settings settings) {}

  /**
   * {@code subscription}: cause (subscribe, delivery …) and the SubscriptionID, {@code null} for
   * several.
   */
  @RegisterForReflection
  public record SubscriptionChange(String cause, String id) {}

  /** {@code session}: SessionID and whether the session is running. */
  @RegisterForReflection
  public record SessionChange(String sessionId, boolean open) {}

  /** {@code resync}: why the client has to reload. */
  @RegisterForReflection
  public record Resync(String reason) {}

  private record Item(long sequence, String type, String data) {}

  /** An open stream; it is written to only in the context of its connection. */
  private record Stream(HttpServerResponse response, Context context, AtomicBoolean closed) {}

  private final Vertx vertx;
  private final ObjectMapper json;
  private final AdminApi api;
  private final int capacity;
  private final int maxStreams;
  private final String boot = Long.toString(System.currentTimeMillis(), Character.MAX_RADIX);
  private final Deque<Item> buffer = new ArrayDeque<>();
  private final Set<Stream> streams = ConcurrentHashMap.newKeySet();
  private final AtomicInteger open = new AtomicInteger();
  private final ExecutorService executor =
      Executors.newSingleThreadExecutor(
          Thread.ofPlatform().daemon().name("liana-admin-events").factory());
  private final long heartbeatTimer;
  private long sequence;

  AdminEvents(
      Vertx vertx,
      ObjectMapper json,
      AdminApi api,
      LianaConfig config,
      SystemLog systemLog,
      CardList cards,
      PinVerification pins,
      CardSessions sessions,
      FakeTerminals fakeTerminals,
      Subscriptions subscriptions) {
    this.vertx = vertx;
    this.json = json;
    this.api = api;
    this.capacity = config.admin().events().buffer();
    this.maxStreams = config.admin().events().maxStreams();
    systemLog.addListener(this::logged);
    cards.addListener(
        event -> {
          card(Event.of(event));
          terminalChanged(event.card().ctId(), event.topic().topic());
        });
    pins.addListener(event -> card(Event.of(event)));
    sessions.addListener(
        timeout -> {
          Map<String, String> parameters = new LinkedHashMap<>();
          parameters.put("CardType", timeout.cardType());
          parameters.put("SessionID", timeout.sessionId());
          parameters.put("Timer", timeout.timer());
          publish(CARD, () -> new CardChange(CardSessions.Timeout.TOPIC, parameters));
        });
    sessions.addChangeListener(
        change -> publish(SESSION, () -> new SessionChange(change.sessionId(), change.open())));
    subscriptions.addListener(
        change ->
            publish(
                SUBSCRIPTION,
                () -> new SubscriptionChange(change.cause(), change.subscriptionId())));
    fakeTerminals
        .terminals()
        .forEach(kt -> kt.addDisplayListener(display -> terminalChanged(kt.id(), "display")));
    heartbeatTimer =
        vertx.setPeriodic(config.admin().events().heartbeat().toMillis(), id -> heartbeat());
  }

  void stop(@Observes ShutdownEvent event) {
    vertx.cancelTimer(heartbeatTimer);
    streams.forEach(stream -> stream.context().runOnContext(v -> stream.response().end()));
    executor.shutdown();
  }

  /**
   * {@code terminal} for {@code ctId} with the cause {@code cause}; the state of the CT is read on
   * dispatch.
   */
  void terminalChanged(String ctId, String cause) {
    publish(TERMINAL, () -> new TerminalChange(ctId, cause, snapshot(ctId)));
  }

  /** The KMS has changed settings, TLS or certificates: {@code state} with cause {@code kms}. */
  void kms(@Observes KmsChanged change) {
    stateChanged("kms");
  }

  /** {@code state} with the cause {@code cause}. */
  void stateChanged(String cause) {
    publish(STATE, () -> new StateChange(cause, api.vendor(), api.settings()));
  }

  private void logged(SystemLog.Entry entry) {
    publish(
        LOG_EVENT,
        () ->
            new AdminApi.LogEntry(
                entry.time().toString(),
                entry.type().value(),
                entry.severity().value(),
                entry.topic(),
                entry.parameters()));
    // CT/CONNECTED, CT/DISCONNECTED, CT/ERROR …: the CT has changed
    String ctId = entry.parameters().get("CtID");
    if (entry.topic().startsWith("CT/") && ctId != null && !ctId.isEmpty()) {
      terminalChanged(ctId, entry.topic());
    }
  }

  private void card(Event event) {
    publish(CARD, () -> new CardChange(event.topic(), event.parameters()));
  }

  private AdminApi.Terminal snapshot(String ctId) {
    try {
      return api.terminal(ctId);
    } catch (RuntimeException e) {
      return null;
    }
  }

  /** Builds the event in the event thread, puts it into the buffer and sends it to all streams. */
  private void publish(String type, Supplier<Object> data) {
    try {
      executor.execute(
          () -> {
            Item item;
            try {
              item = new Item(++sequence, type, json.writeValueAsString(data.get()));
            } catch (JsonProcessingException | RuntimeException e) {
              LOG.warn("Admin-Ereignis " + type + " nicht serialisierbar", e);
              return;
            }
            if (buffer.size() == capacity) {
              buffer.removeFirst();
            }
            buffer.addLast(item);
            String frame = frame(item);
            streams.forEach(stream -> write(stream, frame));
          });
    } catch (RejectedExecutionException e) {
      // Shutdown
    }
  }

  /** {@code GET /admin/events}. */
  void stream(RoutingContext ctx) {
    if (open.incrementAndGet() > maxStreams) {
      open.decrementAndGet();
      ctx.response()
          .setStatusCode(503)
          .putHeader("Content-Type", "application/json")
          .end(
              Json.encode(
                  Map.of(
                      "error",
                      "mehr als "
                          + maxStreams
                          + " gleichzeitige Streams (liana.admin.events.max-streams)")));
      return;
    }
    String lastEventId = ctx.request().getHeader("Last-Event-ID");
    if (lastEventId == null) {
      lastEventId = ctx.queryParams().get("lastEventId");
    }
    HttpServerResponse response = ctx.response();
    response
        .setChunked(true)
        .putHeader("Content-Type", "text/event-stream; charset=utf-8")
        .putHeader("Cache-Control", "no-cache")
        .putHeader("X-Accel-Buffering", "no");
    Stream stream = new Stream(response, vertx.getOrCreateContext(), new AtomicBoolean());
    response.closeHandler(v -> close(stream));
    String resumeFrom = lastEventId;
    try {
      // everything in the event thread: header, resumption and registration without a gap to new
      // events
      executor.execute(
          () -> {
            write(stream, "retry: 2000\n: LIANA " + PATH + "\n\n");
            resume(stream, resumeFrom);
            if (!stream.closed().get()) {
              streams.add(stream);
            }
          });
    } catch (RejectedExecutionException e) {
      close(stream);
      response.end();
    }
  }

  /**
   * In the event thread: the events after {@code lastEventId} from the buffer, otherwise {@code
   * resync}.
   */
  private void resume(Stream stream, String lastEventId) {
    if (lastEventId == null || lastEventId.isBlank()) {
      return;
    }
    long last = -1;
    int dash = lastEventId.lastIndexOf('-');
    if (dash > 0 && lastEventId.substring(0, dash).equals(boot)) {
      try {
        last = Long.parseLong(lastEventId.substring(dash + 1));
      } catch (NumberFormatException e) {
        last = -1;
      }
    }
    long oldest = buffer.isEmpty() ? sequence + 1 : buffer.getFirst().sequence();
    if (last < 0 || last > sequence || last < oldest - 1) {
      String reason =
          last < 0
              ? "Last-Event-ID " + lastEventId + " stammt nicht aus diesem Start"
              : last > sequence
                  ? "Last-Event-ID " + lastEventId + " unbekannt"
                  : "Last-Event-ID " + lastEventId + " nicht mehr im Puffer";
      write(
          stream,
          "id: "
              + id(sequence)
              + "\nevent: "
              + RESYNC
              + "\ndata: "
              + Json.encode(new Resync(reason))
              + "\n\n");
      return;
    }
    for (Item item : buffer) {
      if (item.sequence() > last) {
        write(stream, frame(item));
      }
    }
  }

  /**
   * Heartbeat comment to all streams; the timer calls it every {@code
   * liana.admin.events.heartbeat}.
   */
  void heartbeat() {
    try {
      executor.execute(() -> streams.forEach(stream -> write(stream, ": heartbeat\n\n")));
    } catch (RejectedExecutionException e) {
      // Shutdown
    }
  }

  /** Open streams, for tests. */
  int openStreams() {
    return open.get();
  }

  private void write(Stream stream, String frame) {
    stream
        .context()
        .runOnContext(
            v -> {
              HttpServerResponse response = stream.response();
              if (stream.closed().get()) {
                return;
              }
              if (response.ended() || response.closed()) {
                close(stream);
                return;
              }
              if (response.writeQueueFull()) {
                LOG.warn(
                    "Admin-Ereignisse: Stream kommt nicht nach, geschlossen (Wiederaufnahme mit Last-Event-ID)");
                close(stream);
                response.end();
                return;
              }
              response.write(frame);
            });
  }

  private void close(Stream stream) {
    if (stream.closed().compareAndSet(false, true)) {
      streams.remove(stream);
      open.decrementAndGet();
    }
  }

  private String id(long n) {
    return boot + "-" + n;
  }

  private String frame(Item item) {
    return "id: "
        + id(item.sequence())
        + "\nevent: "
        + item.type()
        + "\ndata: "
        + item.data()
        + "\n\n";
  }
}

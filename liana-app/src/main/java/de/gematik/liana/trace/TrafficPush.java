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
package de.gematik.liana.trace;

import de.gematik.liana.kern.trace.Traffic;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Sends messages as raw data to a Tiger proxy ({@code POST /traffic}, TrafficPushController,
 * LIANA-27): sender, receiver and time in {@code tgr-sender}, {@code tgr-receiver}, {@code
 * tgr-timestamp}; LIANA-195 adds {@code tgr-uuid}, {@code tgr-response-to} for the pairing and
 * {@code tgr-supplementary: true}, so that the proxy drops what it also sees on the wire.
 *
 * <p>Sending is asynchronous and in order; a slow or missing proxy holds up nothing. If the queue
 * runs full, messages are lost. An error is reported once until the push works again; {@link
 * #stats()} counts for the Control Center (LIANA-195.03).
 */
public final class TrafficPush implements Traffic, AutoCloseable {

  static final String SENDER = "tgr-sender";
  static final String RECEIVER = "tgr-receiver";
  static final String TIMESTAMP = "tgr-timestamp";
  static final String UUID_HEADER = "tgr-uuid";
  static final String RESPONSE_TO = "tgr-response-to";
  static final String SUPPLEMENTARY = "tgr-supplementary";

  private static final int QUEUE = 10_000;
  private static final System.Logger LOG = System.getLogger(TrafficPush.class.getName());

  private final URI target;
  private final String name;
  private final Duration timeout;
  private final HttpClient http;
  private final ThreadPoolExecutor queue;
  private volatile boolean failing;
  private volatile String lastError;
  private final AtomicLong delivered = new AtomicLong();
  private final AtomicLong failed = new AtomicLong();
  private final AtomicLong dropped = new AtomicLong();

  /**
   * Counters since the start: accepted by the proxy, rejected or not reachable, lost because the
   * queue was full; {@code lastError} is the reason of the last failure, {@code null} before.
   */
  public record Stats(
      long delivered, long failed, long dropped, boolean failing, String lastError) {}

  /**
   * {@code proxy} is the base URL of the Tiger proxy (admin port), e.g. {@code http://tiger:18080}.
   */
  public TrafficPush(URI proxy, Duration timeout) {
    this(proxy, timeout, DEFAULT_NAME);
  }

  /** {@code name} is the symbolic name of this connector in the trace (LIANA-195.04). */
  public TrafficPush(URI proxy, Duration timeout, String name) {
    this.target = proxy.resolve("/traffic");
    this.name = name;
    this.timeout = timeout;
    this.http = HttpClient.newBuilder().connectTimeout(timeout).build();
    this.queue =
        new ThreadPoolExecutor(
            1,
            1,
            0,
            TimeUnit.MILLISECONDS,
            new ArrayBlockingQueue<>(QUEUE),
            runnable -> {
              Thread thread = new Thread(runnable, "liana-traffic-push");
              thread.setDaemon(true);
              return thread;
            },
            (runnable, executor) -> dropped.incrementAndGet());
  }

  public URI target() {
    return target;
  }

  @Override
  public String name() {
    return name;
  }

  public Stats stats() {
    return new Stats(delivered.get(), failed.get(), dropped.get(), failing, lastError);
  }

  @Override
  public String report(
      byte[] message, String sender, String receiver, Instant time, String responseTo) {
    String uuid = UUID.randomUUID().toString();
    HttpRequest.Builder request =
        HttpRequest.newBuilder(target)
            .timeout(timeout)
            .header("Content-Type", "application/octet-stream")
            .header(SENDER, sender)
            .header(RECEIVER, receiver)
            .header(TIMESTAMP, time.toString())
            .header(UUID_HEADER, uuid)
            .header(SUPPLEMENTARY, "true")
            .POST(HttpRequest.BodyPublishers.ofByteArray(message));
    if (responseTo != null) {
      request.header(RESPONSE_TO, responseTo);
    }
    queue.execute(() -> post(request.build()));
    return uuid;
  }

  private void post(HttpRequest request) {
    try {
      int status = http.send(request, HttpResponse.BodyHandlers.discarding()).statusCode();
      if (status / 100 != 2) {
        fail("HTTP " + status);
        return;
      }
      delivered.incrementAndGet();
      if (failing) {
        failing = false;
        LOG.log(System.Logger.Level.INFO, "Traffic-Push an " + target + " geht wieder");
      }
    } catch (IOException e) {
      fail(e.getClass().getSimpleName() + (e.getMessage() == null ? "" : ": " + e.getMessage()));
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }

  private void fail(String reason) {
    failed.incrementAndGet();
    lastError = reason;
    if (!failing) {
      failing = true;
      LOG.log(
          System.Logger.Level.WARNING,
          "Traffic-Push an "
              + target
              + " fehlgeschlagen ("
              + reason
              + "); weitere Fehler werden nicht gemeldet, bis der Push wieder geht");
    }
  }

  @Override
  public void close() {
    queue.shutdown();
    try {
      if (!queue.awaitTermination(timeout.toMillis() * 2 + 100, TimeUnit.MILLISECONDS)) {
        queue.shutdownNow();
      }
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      queue.shutdownNow();
    }
    http.close();
  }
}

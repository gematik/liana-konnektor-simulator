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

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpClientResponse;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.RequestOptions;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.function.Predicate;

/**
 * Client for {@code GET /admin/events} in tests (LIANA-150): reads the stream via Vert.x (HTTP or
 * HTTPS without certificate verification) and splits it into frames. Waits for a frame only with a
 * deadline, never by sleeping.
 */
final class SseClient implements AutoCloseable {

  /** A frame: event with {@code id}, {@code event}, {@code data}, or comment ({@code comment}). */
  record Frame(String id, String event, String data, String comment) {}

  private final HttpClient client;
  private final BlockingQueue<Frame> frames = new LinkedBlockingQueue<>();
  private final StringBuilder pending = new StringBuilder();
  private HttpClientResponse response;
  private Future<Buffer> body;

  private SseClient(HttpClient client) {
    this.client = client;
  }

  /** Opens the stream; {@code lastEventId} {@code null} without resumption. */
  static SseClient open(Vertx vertx, int port, boolean https, String lastEventId) throws Exception {
    HttpClient client =
        vertx.createHttpClient(
            new HttpClientOptions()
                .setSsl(https)
                .setTrustAll(true)
                .setVerifyHost(false)
                .setKeepAlive(false));
    RequestOptions options =
        new RequestOptions()
            .setMethod(HttpMethod.GET)
            .setHost("localhost")
            .setPort(port)
            .setURI(AdminEvents.PATH);
    if (lastEventId != null) {
      options.putHeader("Last-Event-ID", lastEventId);
    }
    SseClient sse = new SseClient(client);
    // Set the handlers and request the body in the response callback: if the head and first data
    // arrive in one packet, they are lost otherwise
    sse.response =
        client
            .request(options)
            .compose(request -> request.send())
            .map(
                response -> {
                  if (response.statusCode() == 200) {
                    response.handler(sse::received);
                  } else {
                    sse.body = response.body();
                  }
                  return response;
                })
            .toCompletionStage()
            .toCompletableFuture()
            .get(5, TimeUnit.SECONDS);
    return sse;
  }

  int status() {
    return response.statusCode();
  }

  String contentType() {
    return response.getHeader("Content-Type");
  }

  /** Body of a response that is not a stream (503). */
  String body() throws Exception {
    return body.toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS).toString();
  }

  private synchronized void received(Buffer chunk) {
    pending.append(chunk.toString());
    for (int end; (end = pending.indexOf("\n\n")) >= 0; ) {
      String block = pending.substring(0, end);
      pending.delete(0, end + 2);
      String id = null;
      String event = null;
      String comment = null;
      List<String> data = new ArrayList<>();
      for (String line : block.split("\n")) {
        if (line.startsWith(":")) {
          comment = line.substring(1).strip();
        } else if (line.startsWith("id: ")) {
          id = line.substring(4);
        } else if (line.startsWith("event: ")) {
          event = line.substring(7);
        } else if (line.startsWith("data: ")) {
          data.add(line.substring(6));
        }
      }
      if (event != null || comment != null) {
        frames.add(new Frame(id, event, data.isEmpty() ? null : String.join("\n", data), comment));
      }
    }
  }

  /**
   * The next frame that satisfies {@code match}; the skipped ones are consumed. Throws after {@code
   * wait}.
   */
  Frame next(Predicate<Frame> match, Duration wait) throws InterruptedException {
    long end = System.nanoTime() + wait.toNanos();
    for (long left = wait.toNanos(); left > 0; left = end - System.nanoTime()) {
      Frame frame = frames.poll(left, TimeUnit.NANOSECONDS);
      if (frame != null && match.test(frame)) {
        return frame;
      }
    }
    throw new AssertionError("kein passender Frame in " + wait.toMillis() + " ms");
  }

  /** The next event frame of kind {@code event}. */
  Frame next(String event) throws InterruptedException {
    return next(f -> event.equals(f.event()), Duration.ofSeconds(5));
  }

  /** All frames that are already there or arrive within {@code wait}. */
  List<Frame> drain(Duration wait) throws InterruptedException {
    List<Frame> all = new ArrayList<>();
    long end = System.nanoTime() + wait.toNanos();
    for (long left = wait.toNanos(); left > 0; left = end - System.nanoTime()) {
      Frame frame = frames.poll(left, TimeUnit.NANOSECONDS);
      if (frame != null) {
        all.add(frame);
      }
    }
    return all;
  }

  @Override
  public void close() throws Exception {
    response
        .request()
        .connection()
        .close()
        .toCompletionStage()
        .toCompletableFuture()
        .get(5, TimeUnit.SECONDS);
    client.close();
  }
}

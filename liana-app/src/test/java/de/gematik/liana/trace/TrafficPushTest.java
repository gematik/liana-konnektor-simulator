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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** LIANA-27, LIANA-195: {@code POST /traffic} to a Tiger proxy, here a local HTTP stub. */
class TrafficPushTest {

  record Pushed(Headers headers, byte[] body) {}

  private HttpServer stub;
  private final LinkedBlockingQueue<Pushed> received = new LinkedBlockingQueue<>();
  private final CountDownLatch release = new CountDownLatch(1);

  @AfterEach
  void stop() {
    release.countDown();
    if (stub != null) {
      stub.stop(0);
    }
  }

  private URI stub(boolean hang) throws IOException {
    stub = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
    stub.createContext(
        "/traffic",
        exchange -> {
          if (hang) {
            try {
              release.await();
            } catch (InterruptedException e) {
              Thread.currentThread().interrupt();
            }
          }
          received.add(
              new Pushed(exchange.getRequestHeaders(), exchange.getRequestBody().readAllBytes()));
          exchange.sendResponseHeaders(200, -1);
          exchange.close();
        });
    stub.start();
    return URI.create("http://localhost:" + stub.getAddress().getPort());
  }

  private Pushed next() throws InterruptedException {
    Pushed pushed = received.poll(5, TimeUnit.SECONDS);
    assertNotNull(pushed, "kein Push angekommen");
    return pushed;
  }

  @Test
  @DisplayName(
      "Jede Meldung ist ein POST /traffic mit tgr-sender, tgr-receiver, tgr-timestamp, eigener tgr-uuid und "
          + "tgr-supplementary: true; die Antwort trägt tgr-response-to mit der UUID der Anfrage")
  void kopfzeilen() throws Exception {
    try (var push = new TrafficPush(stub(false), Duration.ofSeconds(2))) {
      Instant time = Instant.parse("2026-11-12T10:15:30.123Z");
      String request =
          push.report(bytes("GET / HTTP/1.1\r\n\r\n"), "ps:4711", "liana:8080", time, null);
      String response =
          push.report(bytes("HTTP/1.1 200 OK\r\n\r\n"), "liana:8080", "ps:4711", time, request);

      Pushed first = next();
      assertArrayEquals(bytes("GET / HTTP/1.1\r\n\r\n"), first.body());
      assertEquals("ps:4711", first.headers().getFirst("tgr-sender"));
      assertEquals("liana:8080", first.headers().getFirst("tgr-receiver"));
      assertEquals("2026-11-12T10:15:30.123Z", first.headers().getFirst("tgr-timestamp"));
      assertEquals(request, first.headers().getFirst("tgr-uuid"));
      assertEquals("true", first.headers().getFirst("tgr-supplementary"));
      assertNull(first.headers().getFirst("tgr-response-to"));

      Pushed second = next();
      assertEquals(response, second.headers().getFirst("tgr-uuid"));
      assertEquals(request, second.headers().getFirst("tgr-response-to"));
      assertTrue(!request.equals(response));
    }
  }

  @Test
  @DisplayName(
      "Proxy nicht erreichbar: report kehrt zurück, der Fehler wird einmal geloggt, nicht je Meldung")
  void proxyNichtErreichbar() throws Exception {
    int closedPort;
    try (var socket = new ServerSocket(0)) {
      closedPort = socket.getLocalPort();
    }
    var warnings = warnings();
    try (var push =
        new TrafficPush(URI.create("http://localhost:" + closedPort), Duration.ofMillis(300))) {
      for (int i = 0; i < 5; i++) {
        push.report(bytes("x"), "a:1", "b:2", Instant.now(), null);
      }
    }
    assertEquals(1, warnings.size(), warnings.toString());
    assertTrue(warnings.getFirst().contains("fehlgeschlagen"));
  }

  @Test
  @DisplayName("Proxy hängt: report kehrt sofort zurück, der Push wartet höchstens push-timeout")
  void proxyHaengt() throws Exception {
    var warnings = warnings();
    try (var push = new TrafficPush(stub(true), Duration.ofMillis(300))) {
      assertTimeoutPreemptively(
          Duration.ofMillis(200),
          () -> {
            for (int i = 0; i < 3; i++) {
              push.report(bytes("x"), "a:1", "b:2", Instant.now(), null);
            }
          });
    }
    assertEquals(1, warnings.size(), warnings.toString());
    assertTrue(warnings.getFirst().contains("HttpTimeoutException"), warnings.toString());
  }

  private static byte[] bytes(String text) {
    return text.getBytes(StandardCharsets.US_ASCII);
  }

  /** WARNING messages from {@link TrafficPush} during the test (System.Logger → JUL). */
  private static List<String> warnings() {
    List<String> messages = Collections.synchronizedList(new ArrayList<>());
    Logger logger = Logger.getLogger(TrafficPush.class.getName());
    logger.addHandler(
        new Handler() {
          @Override
          public void publish(LogRecord record) {
            if (record.getLevel().intValue() >= Level.WARNING.intValue()) {
              messages.add(record.getMessage());
            }
          }

          @Override
          public void flush() {}

          @Override
          public void close() {}
        });
    return messages;
  }
}

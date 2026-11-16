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

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * Tiger proxy as far as the page Verkehr reads it (LIANA-195.03): the WebUI answers with responses
 * recorded from Tiger {@value #VERSION} ({@code src/test/resources/tiger-webui-4.5.0/}), {@code
 * POST /traffic} accepts everything. A filter in {@code filterRbelPath} other than the recorded one
 * gets the 500 with which Tiger rejects a JEXL expression it cannot evaluate.
 */
public final class TigerStub implements AutoCloseable {

  public static final String VERSION = "4.5.0";

  /** UUID of the first recorded message (the request). */
  public static final String UUID = "e2422797-7e71-4c9b-97db-ab8b78a403b9";

  /**
   * A filter the stub takes {@link #SLOW_MILLIS} to answer, as Tiger with thousands of messages.
   */
  public static final String SLOW_FILTER = "\"langsam\"";

  public static final long SLOW_MILLIS = 3000;

  /** The filter the filtered response was recorded with. */
  public static final String FILTER = "$.sender =~ '.*liana.*'";

  /** Decoded query strings of the requests to {@code getMessagesWithMeta}, in order. */
  public final LinkedBlockingQueue<String> queries = new LinkedBlockingQueue<>();

  private final HttpServer server;

  public TigerStub(int port) {
    try {
      server = HttpServer.create(new InetSocketAddress("localhost", port), 0);
      // a slow filter must not hold up the pushes
      server.setExecutor(java.util.concurrent.Executors.newCachedThreadPool());
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
    server.createContext(
        "/traffic",
        exchange -> {
          exchange.getRequestBody().readAllBytes();
          exchange.sendResponseHeaders(200, -1);
          exchange.close();
        });
    server.createContext("/webui/", this::webui);
    server.start();
  }

  public int port() {
    return server.getAddress().getPort();
  }

  public static String fixture(String name) {
    try (InputStream in =
        TigerStub.class.getResourceAsStream("/tiger-webui-" + VERSION + "/" + name)) {
      if (in == null) {
        throw new IllegalArgumentException("keine Fixture " + name);
      }
      return new String(in.readAllBytes(), StandardCharsets.UTF_8);
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  private void webui(HttpExchange exchange) throws IOException {
    String path = exchange.getRequestURI().getPath();
    String raw = exchange.getRequestURI().getRawQuery();
    // as Spring decodes it: + is a space
    String query = raw == null ? null : URLDecoder.decode(raw, StandardCharsets.UTF_8);
    switch (path) {
      case "/webui/getMessagesWithMeta" -> {
        queries.add(query == null ? "" : query);
        if (query == null || !query.contains("filterRbelPath=")) {
          send(exchange, 200, "application/json", fixture("getMessagesWithMeta.json"));
        } else if (query.contains("filterRbelPath=" + SLOW_FILTER)) {
          sleep();
          send(exchange, 200, "application/json", fixture("getMessagesWithMeta-filter.json"));
        } else if (query.contains("filterRbelPath=" + FILTER)) {
          send(exchange, 200, "application/json", fixture("getMessagesWithMeta-filter.json"));
        } else {
          send(exchange, 500, "application/json", "{\"status\":500}");
        }
      }
      default -> send(exchange, 404, "application/json", "{\"status\":404}");
    }
  }

  private static void sleep() {
    try {
      Thread.sleep(SLOW_MILLIS);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }

  private static void send(HttpExchange exchange, int status, String type, String body)
      throws IOException {
    byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().add("Content-Type", type);
    exchange.sendResponseHeaders(status, bytes.length);
    exchange.getResponseBody().write(bytes);
    exchange.close();
  }

  @Override
  public void close() {
    server.stop(0);
  }
}

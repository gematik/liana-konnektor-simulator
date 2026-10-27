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

import com.sun.net.httpserver.HttpServer;
import de.gematik.rbellogger.data.RbelElement;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Stub HTTP server for {@link GegenStub} (LIANA-124): answers the n-th request with the n-th HTTP
 * response from a {@code .tgr}, status line, headers and body unchanged; length and connection
 * headers are set by the server.
 */
final class StubServer implements ReplayTarget {

  private static final Set<String> SERVER_HEADERS =
      Set.of("connection", "content-length", "date", "transfer-encoding");

  private final HttpServer server;

  private StubServer(HttpServer server) {
    this.server = server;
  }

  static StubServer start(Path responses) {
    var trace = TraceFile.read(responses);
    List<byte[]> answers =
        trace.requests().stream().map(trace::responseTo).map(RbelElement::getRawContent).toList();
    var next = new AtomicInteger();
    try {
      var server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
      server.createContext(
          "/",
          exchange -> {
            exchange.getRequestBody().readAllBytes();
            int n = next.getAndIncrement();
            if (n >= answers.size()) {
              exchange.sendResponseHeaders(599, -1);
              exchange.close();
              return;
            }
            var raw = answers.get(n);
            var text = new String(raw, StandardCharsets.ISO_8859_1);
            int end = text.indexOf("\r\n\r\n");
            var head = text.substring(0, end).split("\r\n");
            var body = Arrays.copyOfRange(raw, end + 4, raw.length);
            for (int i = 1; i < head.length; i++) {
              int colon = head[i].indexOf(':');
              var name = head[i].substring(0, colon).trim();
              if (!SERVER_HEADERS.contains(name.toLowerCase())) {
                exchange.getResponseHeaders().add(name, head[i].substring(colon + 1).trim());
              }
            }
            exchange.sendResponseHeaders(
                Integer.parseInt(head[0].split(" ")[1]), body.length == 0 ? -1 : body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
          });
      server.start();
      return new StubServer(server);
    } catch (IOException e) {
      throw new UncheckedIOException("Stub für " + responses + " startet nicht", e);
    }
  }

  @Override
  public String baseUrl() {
    return "http://localhost:" + server.getAddress().getPort();
  }

  @Override
  public void close() {
    server.stop(0);
  }
}

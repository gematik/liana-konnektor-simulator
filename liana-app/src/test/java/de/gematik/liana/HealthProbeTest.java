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
package de.gematik.liana;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Health check of the images (LIANA-107) against a local HTTP server instead of LIANA. */
class HealthProbeTest {

  private final AtomicInteger status = new AtomicInteger(200);
  private HttpServer server;

  @BeforeEach
  void start() throws IOException {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext(
        "/admin/ready",
        exchange -> {
          byte[] body = ("{\"ready\":" + (status.get() == 200) + "}").getBytes();
          exchange.sendResponseHeaders(status.get(), body.length);
          exchange.getResponseBody().write(body);
          exchange.close();
        });
    server.createContext(
        "/",
        exchange -> {
          exchange.sendResponseHeaders(404, -1);
          exchange.close();
        });
    server.start();
  }

  @AfterEach
  void stop() {
    server.stop(0);
  }

  @Test
  @DisplayName("200 auf /admin/ready ist bereit, Exit-Code 0")
  void ready() {
    assertTrue(HealthProbe.ready(serverPort()));
    assertEquals(0, HealthProbe.run(new String[] {"health", String.valueOf(serverPort())}));
  }

  @Test
  @DisplayName("503 während Start oder Shutdown ist nicht bereit, Exit-Code 1")
  void notReady() {
    status.set(503);
    assertFalse(HealthProbe.ready(serverPort()));
    assertEquals(1, HealthProbe.run(new String[] {"health", String.valueOf(serverPort())}));
  }

  @Test
  @DisplayName("Kein Server auf dem Port ist nicht bereit, ohne Ausnahme")
  void noServer() throws IOException {
    int free;
    try (ServerSocket socket = new ServerSocket(0)) {
      free = socket.getLocalPort();
    }
    assertFalse(HealthProbe.ready(free));
  }

  @Test
  @DisplayName("Port: Argument vor LIANA_ADMIN_PORT vor 9090; kein Zahl-Port ist Exit-Code 2")
  void portOrder() {
    assertEquals(9191, HealthProbe.port(new String[] {"health", "9191"}, "9292"));
    assertEquals(9292, HealthProbe.port(new String[] {"health"}, "9292"));
    assertEquals(9090, HealthProbe.port(new String[] {"health"}, null));
    assertEquals(2, HealthProbe.run(new String[] {"health", "admin"}));
  }

  private int serverPort() {
    return server.getAddress().getPort();
  }
}

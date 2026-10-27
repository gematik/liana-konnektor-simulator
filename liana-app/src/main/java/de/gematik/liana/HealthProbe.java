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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * Image health check (LIANA-107): queries {@code GET /admin/ready} on the admin port without curl,
 * wget or grep, which are missing from the native base image. A socket instead of {@code
 * java.net.http}, so that the call loads only the bare minimum in the native image as well.
 */
final class HealthProbe {

  static final String DEFAULT_PORT = "9090";
  private static final int TIMEOUT_MILLIS = 3000;

  private HealthProbe() {}

  /**
   * Port from {@code args} (after {@code health}), otherwise {@code LIANA_ADMIN_PORT}, otherwise
   * 9090.
   */
  static int port(String[] args, String envPort) {
    String port =
        args.length > 1 ? args[1] : envPort != null && !envPort.isBlank() ? envPort : DEFAULT_PORT;
    return Integer.parseInt(port.strip());
  }

  /** {@code true} if LIANA reports ready with 200 on {@code 127.0.0.1:port}. */
  static boolean ready(int port) {
    try (Socket socket = new Socket()) {
      socket.connect(new InetSocketAddress("127.0.0.1", port), TIMEOUT_MILLIS);
      socket.setSoTimeout(TIMEOUT_MILLIS);
      OutputStream out = socket.getOutputStream();
      out.write(
          ("GET /admin/ready HTTP/1.1\r\nHost: 127.0.0.1:" + port + "\r\nConnection: close\r\n\r\n")
              .getBytes(StandardCharsets.US_ASCII));
      out.flush();
      return statusLine(socket.getInputStream()).matches("HTTP/1\\.[01] 200( .*)?");
    } catch (IOException e) {
      return false;
    }
  }

  private static String statusLine(InputStream in) throws IOException {
    StringBuilder line = new StringBuilder();
    for (int c = in.read(); c != -1 && c != '\n' && line.length() < 200; c = in.read()) {
      if (c != '\r') {
        line.append((char) c);
      }
    }
    return line.toString();
  }

  /** Exit code 0 when ready, otherwise 1; invalid port 2. */
  static int run(String[] args) {
    int port;
    try {
      port = port(args, System.getenv("LIANA_ADMIN_PORT"));
    } catch (NumberFormatException e) {
      System.err.println("health: Port ist keine Zahl: " + e.getMessage());
      return 2;
    }
    boolean ready = ready(port);
    System.out.println(ready ? "ready" : "not ready (127.0.0.1:" + port + "/admin/ready)");
    return ready ? 0 : 1;
  }
}

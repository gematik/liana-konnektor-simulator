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
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Reports an exchange of the JDK {@link java.net.http.HttpClient} to {@link Traffic} (LIANA-195).
 * The client hides the bytes on the wire; request and response are rebuilt as HTTP/1.1 from what it
 * hands over, with the decoded body and {@code Content-Length}. The client hides the socket too:
 * LIANA appears with its name only, the server as host and port of the URL (LIANA-195.04).
 */
public final class ClientTrace {

  private ClientTrace() {}

  /** {@code body} of the request, empty for GET. */
  public static void report(
      Traffic traffic,
      HttpRequest request,
      byte[] body,
      Instant sent,
      HttpResponse<byte[]> response) {
    if (!traffic.active()) {
      return;
    }
    URI uri = response.uri();
    String server = uri.getHost() + ":" + port(uri);
    String path = uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
    if (uri.getRawQuery() != null) {
      path += "?" + uri.getRawQuery();
    }
    String host = uri.getPort() < 0 ? uri.getHost() : uri.getHost() + ":" + uri.getPort();
    String uuid =
        traffic.report(
            message(
                request.method() + " " + path + " HTTP/1.1",
                Map.of("Host", List.of(host)),
                request.headers().map(),
                body),
            traffic.name(),
            server,
            sent,
            null);
    traffic.report(
        message(
            "HTTP/1.1 " + response.statusCode(),
            Map.of(),
            response.headers().map(),
            response.body()),
        server,
        traffic.name(),
        Instant.now(),
        uuid);
  }

  private static byte[] message(
      String startLine,
      Map<String, List<String>> first,
      Map<String, List<String>> headers,
      byte[] body) {
    StringBuilder head = new StringBuilder(startLine).append("\r\n");
    first.forEach((name, values) -> values.forEach(v -> header(head, name, v)));
    headers.forEach(
        (name, values) -> {
          if (!name.equalsIgnoreCase("content-length")
              && !name.equalsIgnoreCase("transfer-encoding")
              && !name.equalsIgnoreCase(":status")) {
            values.forEach(v -> header(head, name, v));
          }
        });
    byte[] content = body == null ? new byte[0] : body;
    if (content.length > 0 || startLine.startsWith("HTTP/")) {
      header(head, "Content-Length", String.valueOf(content.length));
    }
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.writeBytes(head.append("\r\n").toString().getBytes(StandardCharsets.ISO_8859_1));
    out.writeBytes(content);
    return out.toByteArray();
  }

  private static void header(StringBuilder head, String name, String value) {
    head.append(name).append(": ").append(value).append("\r\n");
  }

  private static int port(URI uri) {
    if (uri.getPort() >= 0) {
      return uri.getPort();
    }
    return "https".equals(uri.getScheme()) ? 443 : 80;
  }
}

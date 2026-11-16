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

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Reads the message list of the linked Tiger proxy through its WebUI (LIANA-195.03), so that the
 * Control Center shows it without Rbel in LIANA (decision-2, decision-18); a single message opens
 * in the Tiger WebUI itself ({@code /webui/message/{uuid}}, LIANA-195.05). The {@code /webui}
 * endpoints are internal API of the Tiger WebUI ({@code TigerWebUiController}); LIANA hands their
 * JSON through unchanged, the fixtures of {@code TigerWebUiTest} name the Tiger version they were
 * recorded with.
 *
 * <p>Not traced: these requests are LIANA's own view of the trace, not traffic of the connector.
 */
public final class TigerWebUi {

  private final URI webui;
  private final Duration timeout;
  private final HttpClient http;

  /** {@code proxy} is the base URL of the Tiger proxy (admin port), as {@code push-url}. */
  public TigerWebUi(URI proxy, Duration timeout) {
    this.webui = proxy.resolve("/webui/");
    this.timeout = timeout;
    this.http = HttpClient.newBuilder().connectTimeout(timeout).build();
  }

  /** The WebUI the requests go to ({@code <push-url>/webui/}). */
  public URI webui() {
    return webui;
  }

  /**
   * {@code GET /webui/getMessagesWithMeta}: all messages with UUID, sequence number, time, sender,
   * recipient and info string, filtered by {@code filter} (JEXL, or text in quotes) and the time
   * window; each argument may be {@code null}.
   */
  public String messages(String filter, Instant from, Instant to) throws IOException {
    List<String> query = new ArrayList<>();
    if (filter != null && !filter.isBlank()) {
      query.add("filterRbelPath=" + URLEncoder.encode(filter, StandardCharsets.UTF_8));
    }
    if (from != null) {
      query.add("minTimestamp=" + from);
    }
    if (to != null) {
      query.add("maxTimestamp=" + to);
    }
    String path = "getMessagesWithMeta" + (query.isEmpty() ? "" : "?" + String.join("&", query));
    HttpResponse<String> response =
        send(path, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    // Tiger answers a filter it cannot evaluate with 500
    if (response.statusCode() == 500 && filter != null && !filter.isBlank()) {
      throw new Rejected(
          "Filter "
              + filter
              + ": vom Tiger-Proxy abgelehnt (JEXL, oder Text in Anführungszeichen)");
    }
    check(response.statusCode(), "Nachrichten");
    return response.body();
  }

  /** No proxy linked, or the proxy lacks the endpoint: 404. */
  public static final class NotFound extends IOException {
    public NotFound(String message) {
      super(message);
    }
  }

  /** The proxy cannot evaluate the filter: 400. */
  public static final class Rejected extends IOException {
    public Rejected(String message) {
      super(message);
    }
  }

  /** The proxy responds with an error or not at all: 502. */
  public static final class Unavailable extends IOException {
    Unavailable(String message, Throwable cause) {
      super(message, cause);
    }
  }

  private void check(int status, String what) throws IOException {
    if (status == 404) {
      throw new NotFound(what + ": im Tiger-Proxy " + webui + " nicht vorhanden");
    }
    if (status / 100 != 2) {
      throw new Unavailable(
          what + ": Tiger-Proxy " + webui + " antwortet mit HTTP " + status, null);
    }
  }

  private <T> HttpResponse<T> send(String path, HttpResponse.BodyHandler<T> body)
      throws IOException {
    HttpRequest request =
        HttpRequest.newBuilder(webui.resolve(path)).timeout(timeout).GET().build();
    try {
      return http.send(request, body);
    } catch (IOException e) {
      throw new Unavailable("Tiger-Proxy " + webui + " nicht erreichbar: " + e, e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new Unavailable("unterbrochen", e);
    }
  }
}

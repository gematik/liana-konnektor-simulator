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
package de.gematik.liana.robot;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Client of the control interface of {@code kartos terminal} ({@code /api/v1}, OpenAPI {@code
 * kartos-terminal-control-v1}, LIANA-112.15): inserts and removes cards like the card robot, PIN
 * inputs into the PIN script. Errors of the interface report {@link UncheckedIOException} with
 * status and response.
 */
final class KartosControl {

  private static final Duration TIMEOUT = Duration.ofSeconds(10);

  private final URI base;
  private final ObjectMapper json;
  private final HttpClient http = HttpClient.newBuilder().connectTimeout(TIMEOUT).build();

  @SuppressWarnings("java:S5852") // trailing slashes of a configured URL
  KartosControl(URI control, ObjectMapper json) {
    String root = control.toString().replaceAll("/+$", "");
    this.base = URI.create(root + "/api/v1/");
    this.json = json;
  }

  URI base() {
    return base;
  }

  /**
   * Inserts the card {@code iccsn} from {@code image} into {@code slot}: if it is missing from the
   * kartos library, LIANA uploads the image; if it sits in another slot or a card is already in
   * {@code slot}, LIANA removes that one first. The CT reports removal and insertion via SICCT (85,
   * 84).
   */
  void insert(int slot, String iccsn, Path image) {
    HttpResponse<String> card = send(get("cards/" + iccsn), 200, 404);
    if (card.statusCode() == 404) {
      try {
        send(
            HttpRequest.newBuilder(base.resolve("cards"))
                .timeout(TIMEOUT)
                .header("Content-Type", "application/xml")
                .POST(HttpRequest.BodyPublishers.ofFile(image))
                .build(),
            201);
      } catch (java.io.FileNotFoundException e) {
        throw new UncheckedIOException(e);
      }
    } else {
      JsonNode found = read(card);
      if ("slot".equals(found.path("location").asText())) {
        eject(found.path("slotNo").asInt());
      }
    }
    eject(slot);
    send(
        HttpRequest.newBuilder(base.resolve("slots/" + slot + "/card"))
            .timeout(TIMEOUT)
            .header("Content-Type", "application/json")
            .PUT(HttpRequest.BodyPublishers.ofString(write(Map.of("iccsn", iccsn))))
            .build(),
        200);
  }

  /** Removes the card from {@code slot}; an empty slot stays empty. */
  void eject(int slot) {
    if (read(send(get("slots/" + slot), 200)).path("occupied").asBoolean()) {
      send(
          HttpRequest.newBuilder(base.resolve("slots/" + slot + "/card"))
              .timeout(TIMEOUT)
              .DELETE()
              .build(),
          200);
    }
  }

  /**
   * Appends an input for {@code slot} ({@code null}: any slot) to the PIN script and switches the
   * input mode to {@code script} so that it takes precedence over the auto PIN. {@code pin} only
   * with {@code digits}.
   */
  void script(Integer slot, String outcome, String pin) {
    send(
        HttpRequest.newBuilder(base.resolve("tui/input-mode"))
            .timeout(TIMEOUT)
            .header("Content-Type", "application/json")
            .PUT(HttpRequest.BodyPublishers.ofString(write(Map.of("mode", "script"))))
            .build(),
        200);
    Map<String, Object> entry = new LinkedHashMap<>();
    entry.put("outcome", outcome);
    if (pin != null) {
      entry.put("pin", pin);
    }
    if (slot != null) {
      entry.put("slotNo", slot);
    }
    send(
        HttpRequest.newBuilder(base.resolve("tui/script"))
            .timeout(TIMEOUT)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(write(List.of(entry))))
            .build(),
        200);
  }

  /** Clears the PIN script; the input mode stays. */
  void clearScript() {
    send(HttpRequest.newBuilder(base.resolve("tui/script")).timeout(TIMEOUT).DELETE().build(), 204);
  }

  private HttpRequest get(String path) {
    return HttpRequest.newBuilder(base.resolve(path)).timeout(TIMEOUT).GET().build();
  }

  private HttpResponse<String> send(HttpRequest request, int... expected) {
    HttpResponse<String> response;
    try {
      response = http.send(request, HttpResponse.BodyHandlers.ofString());
    } catch (IOException e) {
      throw new UncheckedIOException(
          "kartos " + request.method() + " " + request.uri() + ": " + e.getMessage(), e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IllegalStateException(
          "kartos " + request.method() + " " + request.uri() + " unterbrochen", e);
    }
    for (int status : expected) {
      if (response.statusCode() == status) {
        return response;
      }
    }
    throw new UncheckedIOException(
        new IOException(
            "kartos "
                + request.method()
                + " "
                + request.uri()
                + " → "
                + response.statusCode()
                + " "
                + response.body()));
  }

  private JsonNode read(HttpResponse<String> response) {
    try {
      return json.readTree(response.body());
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  private String write(Object value) {
    try {
      return json.writeValueAsString(value);
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }
}

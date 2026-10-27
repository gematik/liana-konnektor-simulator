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
package de.gematik.liana.konnektor;

import de.gematik.rbellogger.RbelLogger;
import de.gematik.rbellogger.data.RbelElement;
import de.gematik.rbellogger.facets.http.RbelHttpRequestFacet;
import de.gematik.rbellogger.facets.http.RbelHttpResponseFacet;
import de.gematik.rbellogger.file.RbelFileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Transport that returns recorded responses from a {@code .tgr} (LIANA-139, decision-9): for each
 * request, the response to the next not yet used request with the same method, the same path and,
 * for SOAP, the same {@code SOAPAction}. The response comes from the {@code .tgr}'s {@code
 * pairedMessageUuid}, because the Tiger proxy does not write messages in recording order (Rbel does
 * not pair them when reading the file); without pairing, as in older exports, the next response in
 * the trace. The host does not count, because traces were made via a Tiger proxy or under a
 * different address. Remembers the client's requests for checks via RbelPath.
 */
final class ReplayTransport implements Transport {

  private final Path trace;
  private final Mode mode;

  /** How strictly requests have to match recordings. */
  enum Mode {
    /** Method, path, SOAPAction. */
    LENIENT,
    /** additionally the same body content (recordings of this client). */
    STRICT,
    /** first like STRICT, otherwise like LENIENT (examples with other parameters). */
    PREFER_EXACT
  }

  private final List<RbelElement> messages;
  private final List<RbelElement> used = new ArrayList<>();
  private final List<Request> requests = new ArrayList<>();

  /** uuid of the request → uuid of the response. */
  private final Map<String, String> pairs = new HashMap<>();

  /** One Rbel and each trace once per JVM: parsing costs about one second per file. */
  private static final RbelLogger RBEL = RbelLogger.build();

  private static final Map<Path, List<RbelElement>> PARSED =
      new java.util.concurrent.ConcurrentHashMap<>();

  private static final Pattern UUID = Pattern.compile("\"uuid\":\"([^\"]+)\"");
  private static final Pattern PAIRED = Pattern.compile("\"pairedMessageUuid\":\"([^\"]+)\"");

  ReplayTransport(Path trace) throws IOException {
    this(trace, Mode.LENIENT);
  }

  ReplayTransport(Path trace, boolean strict) throws IOException {
    this(trace, strict ? Mode.STRICT : Mode.LENIENT);
  }

  ReplayTransport(Path trace, Mode mode) throws IOException {
    this.trace = trace;
    this.mode = mode;
    String content = Files.readString(trace);
    this.messages =
        PARSED.computeIfAbsent(
            trace.toAbsolutePath().normalize(),
            p ->
                new RbelFileReader(RBEL.getRbelConverter())
                    .convertFromRbelFile(content, Optional.empty()));
    for (String line : content.split("\n")) {
      Matcher uuid = UUID.matcher(line);
      Matcher paired = PAIRED.matcher(line);
      if (uuid.find() && paired.find()) {
        pairs.put(paired.group(1), uuid.group(1));
      }
    }
  }

  List<Request> requests() {
    return List.copyOf(requests);
  }

  @Override
  public synchronized Response send(Request request) throws IOException {
    requests.add(request);
    if (mode == Mode.PREFER_EXACT) {
      Response exact = find(request, true);
      return exact != null ? exact : orThrow(request, find(request, false));
    }
    return orThrow(request, find(request, mode == Mode.STRICT));
  }

  private Response orThrow(Request request, Response response) throws IOException {
    if (response == null) {
      String action = request.headers().get("SOAPAction");
      throw new IOException(
          trace
              + ": keine aufgezeichnete Anfrage "
              + request.method()
              + " "
              + request.uri()
              + (action == null ? "" : " " + action));
    }
    return response;
  }

  private Response find(Request request, boolean strict) throws IOException {
    String action = request.headers().get("SOAPAction");
    for (int i = 0; i < messages.size(); i++) {
      RbelElement message = messages.get(i);
      if (!message.hasFacet(RbelHttpRequestFacet.class) || used.contains(message)) {
        continue;
      }
      if (!request.method().equals(text(message, "$.method"))
          || !request.uri().getRawPath().equals(text(message, "$.path").replaceAll("\\?.*", ""))) {
        continue;
      }
      if (action != null && !action.equals(text(message, "$.header.SOAPAction"))) {
        continue;
      }
      if (strict
          && !content(request.body())
              .equals(
                  content(
                      message
                          .findElement("$.body")
                          .map(RbelElement::getRawContent)
                          .orElse(new byte[0])))) {
        continue;
      }
      used.add(message);
      int next = i + 1;
      String pairedUuid = pairs.get(message.getUuid());
      RbelElement response =
          messages.stream()
              .filter(m -> pairedUuid != null && pairedUuid.equals(m.getUuid()))
              .findFirst()
              .or(
                  () ->
                      messages.subList(next, messages.size()).stream()
                          .filter(m -> m.hasFacet(RbelHttpResponseFacet.class))
                          .findFirst())
              .orElseThrow(() -> new IOException(trace + ": keine Antwort auf " + request.uri()));
      int status = Integer.parseInt(text(response, "$.responseCode"));
      String contentType = message(response, "$.header.Content-Type");
      byte[] body =
          response.findElement("$.body").map(RbelElement::getRawContent).orElse(new byte[0]);
      return new Response(status, contentType, body);
    }
    return null;
  }

  /**
   * Content without namespace declarations and prefixes: JAXB assigns prefixes differently per
   * context.
   */
  static String content(byte[] body) {
    return new String(body, java.nio.charset.StandardCharsets.UTF_8)
        .replaceAll(" xmlns(:\\w+)?=\"[^\"]*\"", "")
        .replaceAll("<(/?)\\w+:", "<$1")
        .trim();
  }

  private static String text(RbelElement message, String path) {
    String value = message(message, path);
    return value == null ? "" : value;
  }

  private static String message(RbelElement message, String path) {
    return message
        .findElement(path)
        .map(RbelElement::getRawStringContent)
        .map(String::trim)
        .orElse(null);
  }
}

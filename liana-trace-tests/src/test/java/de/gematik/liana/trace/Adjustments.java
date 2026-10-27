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
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * Adjusts requests from the trace before they are sent to LIANA, as described by the annotations of
 * the test class: fixed environment values ({@link Replace}), values assigned by LIANA ({@link
 * Carry}), and steps of signed scenarios ({@link ReplaceSteps}). Only whole values are replaced: no
 * letter, digit, {@code -}, {@code _} or {@code .} may precede or follow them.
 *
 * <p>Signed JWS (compact, header and payload JSON) are unpacked; if their payload changes, {@link
 * JwsResigner} re-signs them. Each adjustment is recorded as a sentence in {@link
 * Applied#adjustments()} so that test messages say what LIANA received differently from the
 * Konnektor of the recording.
 */
final class Adjustments {

  /**
   * A request after the adjustments, the replacements (trace value → LIANA value) and all
   * adjustments as sentences.
   */
  record Applied(byte[] raw, Map<String, String> replaced, List<String> adjustments) {}

  private record Value(String liana, String why) {}

  /** JWS compact with JSON header and payload (base64url of {@code {"}). */
  private static final Pattern JWS =
      Pattern.compile("eyJ[A-Za-z0-9_-]*\\.eyJ[A-Za-z0-9_-]*\\.[A-Za-z0-9_-]+");

  private static final JsonMapper JSON = JsonMapper.builder().build();

  private final Map<String, Value> values = new LinkedHashMap<>();
  private final List<ReplaceSteps> steps;

  Adjustments(List<Replace> replaces, List<ReplaceSteps> steps) {
    replaces.forEach(r -> put(r.trace(), r.liana(), r.why()));
    this.steps = List.copyOf(steps);
  }

  /** Remembers a value assigned by LIANA ({@link Carry}). */
  void put(String traceValue, String lianaValue, String why) {
    if (!traceValue.equals(lianaValue)) {
      values.put(traceValue, new Value(lianaValue, why));
    }
  }

  /** Adjusts the raw HTTP request and sets {@code Content-Length} to the new body. */
  Applied apply(byte[] request) {
    // ISO-8859-1 maps every byte to one character, so the body is preserved byte for byte
    var raw = new String(request, StandardCharsets.ISO_8859_1);
    var replaced = new LinkedHashMap<String, String>();
    var adjustments = new ArrayList<String>();
    raw = replaceValues(raw, true, replaced, adjustments);

    var jws = JWS.matcher(raw);
    var out = new StringBuilder();
    while (jws.find()) {
      var payload =
          new String(
              Base64.getUrlDecoder().decode(jws.group().split("\\.")[1]), StandardCharsets.UTF_8);
      var adjusted =
          replaceSteps(replaceValues(payload, false, replaced, adjustments), adjustments);
      var token = jws.group();
      if (!adjusted.equals(payload)) {
        token = JwsResigner.sign(token.split("\\.")[0], adjusted);
        adjustments.add("JWS neu signiert mit dem Test-Signer aus support/pki/replay");
      }
      jws.appendReplacement(out, Matcher.quoteReplacement(token));
    }
    jws.appendTail(out);
    return new Applied(
        withContentLength(out.toString()).getBytes(StandardCharsets.ISO_8859_1),
        Collections.unmodifiableMap(replaced),
        List.copyOf(adjustments));
  }

  /** Replaces whole values; {@code latin1}: {@code text} is the raw request, values are UTF-8. */
  private String replaceValues(
      String text, boolean latin1, Map<String, String> replaced, List<String> adjustments) {
    for (var entry : values.entrySet()) {
      var traceValue = latin1 ? latin1(entry.getKey()) : entry.getKey();
      var lianaValue = latin1 ? latin1(entry.getValue().liana()) : entry.getValue().liana();
      var matcher =
          Pattern.compile("(?<![\\w.-])" + Pattern.quote(traceValue) + "(?![\\w.-])").matcher(text);
      if (matcher.find()) {
        text = matcher.replaceAll(Matcher.quoteReplacement(lianaValue));
        replaced.put(entry.getKey(), entry.getValue().liana());
        adjustments.add(
            entry.getValue().why()
                + ": "
                + entry.getKey()
                + " → "
                + entry.getValue().liana()
                + (latin1 ? "" : " (im JWS-Payload)"));
      }
    }
    return text;
  }

  /** {@link ReplaceSteps} for the scenario with a matching {@code sequenceCounter}. */
  private String replaceSteps(String payload, List<String> adjustments) {
    if (steps.isEmpty()) {
      return payload;
    }
    var root = JSON.readTree(payload);
    var message = root.path("message");
    for (var replacement : steps) {
      if (message.isObject()
          && message.path("sequenceCounter").asLong(-1) == replacement.sequence()) {
        ((ObjectNode) message).set("steps", blueprintSteps(replacement.with()));
        adjustments.add(
            replacement.why()
                + ": Steps von Sequenz "
                + replacement.sequence()
                + " aus "
                + replacement.with());
        return JSON.writeValueAsString(root);
      }
    }
    return payload;
  }

  private static JsonNode blueprintSteps(String blueprint) {
    try {
      return JSON.readTree(Files.readString(Path.of(blueprint))).path("steps");
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  private static String withContentLength(String raw) {
    int end = raw.indexOf("\r\n\r\n");
    if (end < 0) {
      return raw;
    }
    int length = raw.length() - end - 4;
    var head =
        Pattern.compile("(?im)^content-length:.*$")
            .matcher(raw.substring(0, end))
            .replaceAll("Content-Length: " + length);
    return head + raw.substring(end);
  }

  private static String latin1(String utf8) {
    return new String(utf8.getBytes(StandardCharsets.UTF_8), StandardCharsets.ISO_8859_1);
  }
}

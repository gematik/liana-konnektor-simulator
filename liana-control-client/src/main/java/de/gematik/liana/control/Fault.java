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
package de.gematik.liana.control;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Fault at a slot (LIANA-41, docs/handbuch.md „Admin-API“): status word, full response,
 * communication error or delay; optionally only for commands with {@code commandPrefix} and only
 * {@code count} times.
 */
public final class Fault {

  private final Map<String, Object> json = new LinkedHashMap<>();

  private Fault(String type) {
    json.put("type", type);
  }

  /** The card answers only with this status word (4 hex digits). */
  public static Fault statusWord(String statusWord) {
    Fault fault = new Fault("status-word");
    fault.json.put("statusWord", statusWord);
    return fault;
  }

  /** The card answers with this response APDU (data and status word, hex). */
  public static Fault response(String response) {
    Fault fault = new Fault("response");
    fault.json.put("response", response);
    return fault;
  }

  /** Communication error with the card terminal (4044). */
  public static Fault ioError() {
    return new Fault("io-error");
  }

  /** The card answers only after {@code delayMs}. */
  public static Fault delay(long delayMs) {
    Fault fault = new Fault("delay");
    fault.json.put("delayMs", delayMs);
    return fault;
  }

  /** Only commands with this prefix (hex). */
  public Fault commandPrefix(String prefix) {
    json.put("commandPrefix", prefix);
    return this;
  }

  /** Only the next {@code count} affected calls. */
  public Fault count(int count) {
    json.put("count", count);
    return this;
  }

  Map<String, Object> json() {
    return json;
  }
}

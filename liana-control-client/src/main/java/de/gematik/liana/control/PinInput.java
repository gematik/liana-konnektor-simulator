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
 * A PIN entry for the PIN script of a fake card terminal (LIANA-68, docs/handbuch.md „Admin-API“).
 */
public final class PinInput {

  private final Map<String, Object> json = new LinkedHashMap<>();

  private PinInput(String outcome) {
    json.put("outcome", outcome);
  }

  /** The configured PIN. */
  public static PinInput correct() {
    return new PinInput("correct");
  }

  /** The configured PIN with every digit changed. */
  public static PinInput wrong() {
    return new PinInput("wrong");
  }

  /** These digits (4–12). */
  public static PinInput digits(String pin) {
    PinInput input = new PinInput("digits");
    input.json.put("pin", pin);
    return input;
  }

  /** The configured PUK. */
  public static PinInput puk() {
    return new PinInput("puk");
  }

  /** The configured transport PIN. */
  public static PinInput transport() {
    return new PinInput("transport");
  }

  /** Cancel key (4049). */
  public static PinInput cancel() {
    return new PinInput("cancel");
  }

  /** No input (4043). */
  public static PinInput timeout() {
    return new PinInput("timeout");
  }

  /** Digits without confirmation, waits until timeout or card removal. */
  public static PinInput incomplete() {
    return new PinInput("incomplete");
  }

  /** Only for the PIN dialog of the card in this slot. */
  public PinInput slot(int slotNo) {
    json.put("slotNo", slotNo);
    return this;
  }

  Map<String, Object> json() {
    return json;
  }
}

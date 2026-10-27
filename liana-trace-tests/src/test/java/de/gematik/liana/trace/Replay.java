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

import java.util.List;

/** Result of a replay: one {@link Exchange} per HTTP request from the trace, in trace order. */
public record Replay(String trace, List<Exchange> exchanges) {

  /** The n-th exchange (from 0). */
  public Exchange exchange(int index) {
    if (index < 0 || index >= exchanges.size()) {
      throw new IllegalArgumentException(
          trace + " enthält " + exchanges.size() + " Requests, nicht #" + index);
    }
    return exchanges.get(index);
  }

  /** The only exchange of the trace. */
  public Exchange onlyExchange() {
    if (exchanges.size() != 1) {
      throw new IllegalStateException(
          trace + " enthält " + exchanges.size() + " Requests, erwartet genau einen");
    }
    return exchanges.getFirst();
  }
}

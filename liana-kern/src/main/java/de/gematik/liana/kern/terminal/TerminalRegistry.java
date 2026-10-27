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
package de.gematik.liana.kern.terminal;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** The card terminals the connector knows (CTM_CT_LIST), in configuration order. */
public final class TerminalRegistry {

  private final Map<String, CardTerminal> terminals = new LinkedHashMap<>();

  public TerminalRegistry(List<? extends CardTerminal> terminals) {
    for (CardTerminal terminal : terminals) {
      if (this.terminals.putIfAbsent(terminal.id(), terminal) != null) {
        throw new IllegalArgumentException("KT '" + terminal.id() + "' ist doppelt");
      }
    }
  }

  public List<CardTerminal> terminals() {
    return List.copyOf(terminals.values());
  }

  public Optional<CardTerminal> terminal(String id) {
    return Optional.ofNullable(terminals.get(id));
  }
}

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
package de.gematik.liana.adapter.soap;

import de.gematik.liana.kern.event.GetCardTerminals;
import de.gematik.liana.kern.terminal.CardTerminalInfo;
import java.util.List;

/** A KT for {@code CT:CardTerminal} (CardTerminalInfoType, CardTerminalInfo v8.0). */
public record CardTerminalView(
    String ctId,
    List<String> workplaceIds,
    String name,
    String macAddress,
    String ipAddress,
    int slots,
    boolean physical,
    boolean connected,
    CardTerminalInfo.Product product) {

  static CardTerminalView of(GetCardTerminals.Entry entry) {
    CardTerminalInfo info = entry.info();
    return new CardTerminalView(
        info.ctId(),
        entry.workplaceIds(),
        info.name(),
        info.macAddress(),
        info.ipAddress(),
        info.slots(),
        info.physical(),
        info.connected(),
        info.product());
  }
}

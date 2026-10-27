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

import de.gematik.liana.konnektor.ws.conn.cardterminalinfo.v8_0.CardTerminalInfoType;

/**
 * A card terminal from GetCardTerminals ({@code CARDT:CardTerminal}, CardTerminalInfo 8.0).
 *
 * @param ctId CtId
 * @param name name
 * @param slots number of slots
 * @param connected whether the Konnektor is connected
 * @param physical {@code IS_PHYSICAL}
 * @param macAddress MAC address
 */
public record CardTerminal(
    String ctId, String name, int slots, boolean connected, boolean physical, String macAddress) {

  static CardTerminal of(CardTerminalInfoType info) {
    return new CardTerminal(
        info.getCtId(),
        info.getName(),
        info.getSlots() == null ? 0 : info.getSlots().intValue(),
        info.isConnected(),
        info.isISPHYSICAL(),
        info.getMacAddress());
  }
}

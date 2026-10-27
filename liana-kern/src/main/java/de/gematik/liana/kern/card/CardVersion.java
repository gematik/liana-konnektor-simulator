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
package de.gematik.liana.kern.card;

/**
 * CARD.CARDVERSION (TAB_KON_531): product type versions and versions of the filling specifications.
 * Unreadable parts are {@code null}.
 */
public record CardVersion(
    Version cos, Version objectSystem, Version logging, Version atr, Version gdo, Version keyInfo) {

  /** Version {@code major.minor.revision}, stored on the card as three octets. */
  public record Version(int major, int minor, int revision) {

    static Version of(byte[] value) {
      if (value == null || value.length != 3) {
        return null;
      }
      return new Version(value[0] & 0xFF, value[1] & 0xFF, value[2] & 0xFF);
    }

    @Override
    public String toString() {
      return major + "." + minor + "." + revision;
    }
  }
}

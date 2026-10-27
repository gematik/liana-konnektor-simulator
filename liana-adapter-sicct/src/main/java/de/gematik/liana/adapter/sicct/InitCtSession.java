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
package de.gematik.liana.adapter.sicct;

/**
 * SICCT INIT CT SESSION and CLOSE CT SESSION (SICCT 1.2.3 §5.10, §5.11) to the terminal (FU {@code
 * 0000}).
 */
final class InitCtSession {

  /**
   * INIT CT SESSION with CTSESS DO ({@code 69}, §5.5.10.13) of empty username, password and session
   * ID, each a PrintableString {@code 13 00}: the session for correlation up to "zugewiesen"
   * (assigned) and for role = "User" (TUC_KON_050 steps 4a and 6b).
   */
  static final byte[] EMPTY = {
    (byte) 0x80, 0x28, 0x00, 0x00, 0x08, 0x69, 0x06, 0x13, 0x00, 0x13, 0x00, 0x13, 0x00
  };

  /** CLOSE CT SESSION. */
  static final byte[] CLOSE = {(byte) 0x80, 0x29, 0x00, 0x00};

  private InitCtSession() {}

  /** Whether the response ends with 9000. */
  static boolean ok(byte[] response) {
    return response.length >= 2
        && (response[response.length - 2] & 0xFF) == 0x90
        && response[response.length - 1] == 0;
  }
}

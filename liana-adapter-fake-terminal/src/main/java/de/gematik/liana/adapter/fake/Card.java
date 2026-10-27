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
package de.gematik.liana.adapter.fake;

import java.io.IOException;

/** A running card in the card engine. {@link #close()} terminates it. */
public interface Card extends AutoCloseable {

  byte[] atr();

  /**
   * Sends a command APDU and returns the response APDU including the status word. Must be
   * thread-safe: the {@link FakeTerminal} calls it without a lock of its own.
   */
  byte[] transmit(byte[] commandApdu) throws IOException;

  @Override
  void close();
}

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
package de.gematik.liana.sm;

import de.gematik.liana.kern.terminal.CardTerminal;
import de.gematik.liana.kern.terminal.SecureChannel;
import java.io.IOException;

/**
 * A trusted channel with the session keys from elcSessionkey4SM ({@link SourceCard}, LIANA-112.13):
 * commands with MAC and, if they have data, encrypted (SMCMDENC); SSC + 1 per command and response
 * (gemSpec_COS 13.2/13.3).
 */
final class SmChannel implements SecureChannel {

  private final SecureMessaging.Session session;
  private byte[] ssc = new byte[16];
  private boolean closed;

  SmChannel(SecureMessaging.Session session) {
    this.session = session;
  }

  @Override
  public synchronized byte[] transmit(CardTerminal terminal, int slot, byte[] command)
      throws IOException {
    if (closed) {
      throw new IOException(terminal.id() + "/" + slot + ": Trusted Channel beendet");
    }
    byte[] commandSsc = SecureMessaging.increment(ssc);
    byte[] wire;
    try {
      wire =
          SecureMessaging.wrapCommand(
              new SecureMessaging.Plain(command, command.length > 5), session, commandSsc);
    } catch (SecureMessaging.SecureMessagingException e) {
      throw new IOException(
          terminal.id() + "/" + slot + ": Kommando nicht einwickelbar: " + e.getMessage(), e);
    }
    byte[] response = terminal.transmit(slot, wire);
    byte[] responseSsc = SecureMessaging.increment(commandSsc);
    try {
      byte[] plain = SecureMessaging.unwrapResponse(response, session, responseSsc).apdu();
      ssc = responseSsc;
      return plain;
    } catch (SecureMessaging.SecureMessagingException e) {
      // G2_N031.700: without valid secure messaging the card has deleted the session keys
      closed = true;
      if (response.length == 2) {
        return response;
      }
      throw new IOException(
          terminal.id()
              + "/"
              + slot
              + ": Antwort ohne gültiges Secure Messaging: "
              + e.getMessage(),
          e);
    }
  }
}

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

import de.gematik.liana.kern.error.ConnectorError;
import de.gematik.liana.kern.error.ConnectorException;
import de.gematik.liana.kern.terminal.CardTimeoutException;
import de.gematik.liana.kern.terminal.PinMismatchException;

/**
 * Errors on card access via TUC_KON_200: card does not respond within CARD_TIMEOUT_CARD → 4094, any
 * other communication error with the card terminal → 4044; non-matching repetition of the new PIN
 * at the CT → 4067 (TUC_KON_019/021 7b).
 */
final class TerminalErrors {

  private TerminalErrors() {}

  static ConnectorException of(CardObject card, String what, Exception e) {
    ConnectorError error =
        e instanceof CardTimeoutException
            ? ConnectorError.CARD_TIMEOUT
            : e instanceof PinMismatchException
                ? ConnectorError.PIN_MISMATCH
                : ConnectorError.CT_ACCESS;
    return error
        .exception(card.ctId() + "/" + card.slotNo() + " " + what + ": " + e.getMessage())
        .causedBy(e);
  }
}

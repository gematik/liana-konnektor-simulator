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

import java.io.IOException;

/**
 * The CT did not recognize the repetition of the new PIN as equal and aborted the entry (SICCT
 * MODIFY VERIFICATION DATA, standard text 9 „Geheimzahl nicht gleich. Abbruch“); the card has not
 * seen a command. TUC_KON_019/021 (7b) report 4067.
 */
public class PinMismatchException extends IOException {

  public PinMismatchException(String message) {
    super(message);
  }
}

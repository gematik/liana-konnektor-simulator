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

import java.util.List;

/**
 * Payload of a SignedScenario ({@code StandardScenarioMessage} from I_PoPP_Token_Generation,
 * [api-popp]): the session, the running sequence number, the time span until the next scenario in
 * milliseconds (0 = last scenario) and the command APDUs with the expected status words.
 */
public record Scenario(
    String clientSessionId, long sequenceCounter, long timeSpan, List<Step> steps) {

  /** A step: command APDU and the accepted status words, hexadecimal like {@code 9000}. */
  public record Step(byte[] commandApdu, List<String> expectedStatusWords) {}
}

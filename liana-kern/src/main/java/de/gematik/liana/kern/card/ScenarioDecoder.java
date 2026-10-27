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
 * Port: checks a SignedScenario (JWS Compact Serialization) and returns its payload (A_25822-02,
 * TAB_KON_271 steps 1 and 2, TUC_KON_208 step 2). Adapter: {@code liana-app}, crypto with
 * BouncyCastle.
 */
@FunctionalInterface
public interface ScenarioDecoder {

  /**
   * @throws de.gematik.liana.kern.error.ConnectorException 4000 on format errors, 4701 on an
   *     invalid signature, 4286 if the payload is not a valid StandardScenario
   */
  Scenario decode(String signedScenario);
}

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

/**
 * Hook before every call with PIN entry ({@link Operation#pinInput()}, LIANA-137): e.g. a prompt
 * „Bitte PIN am Kartenterminal eingeben“ ("please enter PIN at the card terminal"), or in tests a
 * trigger for the card robot or the card terminal's PIN script. Runs in the calling thread before
 * the request; an exception aborts the call. Mandatory for {@link Deployment#KSP}.
 */
@FunctionalInterface
public interface PinPromptHandler {

  /**
   * A PIN dialog is about to start.
   *
   * @param operation the operation
   * @param cardHandle CardHandle from the request, if present
   * @param pinType PinTyp from the request, if present (empty for SignDocument)
   */
  record PinPrompt(Operation operation, String cardHandle, String pinType) {}

  void onPinPrompt(PinPrompt prompt) throws Exception;
}

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
 * Result of GetPinStatus (TUC_KON_022).
 *
 * @param status {@code VERIFIED}, {@code TRANSPORT_PIN}, {@code EMPTY_PIN}, {@code BLOCKED}, {@code
 *     VERIFIABLE}, {@code DISABLED}
 * @param leftTries remaining tries, if the Konnektor reports them
 */
public record PinStatus(String status, Integer leftTries) {}

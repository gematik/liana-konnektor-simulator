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
/**
 * Managementschnittstelle (KMS) of the vendor profile on the management port (decision-10,
 * decision-4, decision-017): the EHEX subset for Konnektor-PoPP and Konnektor-E2E (LIANA-55,
 * LIANA-65), the KOCO and the RISE subset for Konnektor-QES (LIANA-96, LIANA-97); everything else
 * responds with HTTP 501 (decision-12).
 */
package de.gematik.liana.kms;

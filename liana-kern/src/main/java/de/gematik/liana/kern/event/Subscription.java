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
package de.gematik.liana.kern.event;

import de.gematik.liana.kern.access.Context;
import java.time.Instant;

/**
 * A subscription (TAB_KON_572 saveSubscription): SubscriptionID, TerminationTime, Aufrufkontext,
 * Ereignissenke {@code cetp://host:port}, topic and optional filter ({@code null}).
 */
public record Subscription(
    String id,
    Instant terminationTime,
    Context context,
    String eventTo,
    String topic,
    String filter) {

  Subscription renewed(Instant terminationTime) {
    return new Subscription(id, terminationTime, context, eventTo, topic, filter);
  }
}

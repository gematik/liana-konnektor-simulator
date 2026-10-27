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

/**
 * Port for delivery to Clientsysteme (TUC_KON_256 step 6, TIP1-A_4594): delivers an event to the
 * Ereignissenke of a subscription, asynchronously. The adapter evaluates the subscription's XPath
 * filter (step 5c), because it builds the event XML.
 */
public interface EventSink {

  /**
   * Delivers {@code event} to {@code subscription.eventTo()} if the filter matches, and reports the
   * result to {@code outcome}; if the filter discards the event, it reports nothing.
   */
  void send(Event event, Subscription subscription, Outcome outcome);

  /** Result of a delivery attempt, for the auto-unsubscribe after EVT_MAX_TRY (TAB_KON_571). */
  interface Outcome {
    void delivered();

    void failed(String reason);
  }
}

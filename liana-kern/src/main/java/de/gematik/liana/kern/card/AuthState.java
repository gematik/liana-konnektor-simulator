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

import de.gematik.liana.kern.access.Context;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * CARDSESSION.AUTHSTATE (TUC_KON_026, TIP1-A_4560): which PINs are verified in a card session. A
 * card session is card (CardHandle), mandant and Clientsystem; a new CardHandle (insertion, reset)
 * starts without a verified PIN.
 */
public final class AuthState {

  /** A verified PIN for the Admin API (LIANA-149): card session and PinRef, never the PIN value. */
  public record Verified(
      String cardHandle, String mandantId, String clientSystemId, String pinRef) {}

  private record Session(String cardHandle, String mandantId, String clientSystemId) {}

  private record Entry(Session session, String pinRef) {}

  private final Set<Entry> verified = new HashSet<>();

  /** TUC_KON_012 7e: {@code pinRef} is verified in the card session. */
  public synchronized void verified(Context context, String cardHandle, String pinRef) {
    verified.add(new Entry(session(context, cardHandle), pinRef));
  }

  /** TUC_KON_012 7e: the PIN is not (or no longer) verified, e.g. after a wrong entry. */
  public synchronized void notVerified(Context context, String cardHandle, String pinRef) {
    verified.remove(new Entry(session(context, cardHandle), pinRef));
  }

  /** TUC_KON_218 step 3. */
  public synchronized boolean isVerified(Context context, String cardHandle, String pinRef) {
    return verified.contains(new Entry(session(context, cardHandle), pinRef));
  }

  /** All verified PINs, sorted by CardHandle, mandant, Clientsystem and PinRef. */
  public synchronized List<Verified> verified() {
    return verified.stream()
        .map(
            e ->
                new Verified(
                    e.session().cardHandle(),
                    e.session().mandantId(),
                    e.session().clientSystemId(),
                    e.pinRef()))
        .sorted(
            Comparator.comparing(Verified::cardHandle)
                .thenComparing(
                    Verified::mandantId, Comparator.nullsFirst(Comparator.naturalOrder()))
                .thenComparing(
                    Verified::clientSystemId, Comparator.nullsFirst(Comparator.naturalOrder()))
                .thenComparing(Verified::pinRef))
        .toList();
  }

  /** The card was removed: its card sessions end. */
  public synchronized void removed(String cardHandle) {
    verified.removeIf(entry -> entry.session().cardHandle().equals(cardHandle));
  }

  private static Session session(Context context, String cardHandle) {
    return new Session(cardHandle, context.mandantId(), context.clientSystemId());
  }
}

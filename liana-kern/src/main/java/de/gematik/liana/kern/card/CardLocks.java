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
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Card reservations per TUC_KON_023 „Karte reservieren“ (TIP1-A_4571-03), at most one lock per
 * card. The lock is connector-internal: only the caller who obtained it can release the
 * reservation. A reserved card rejects every further reservation (A_25895) and every foreign access
 * via TUC_KON_026 step 2 with 4093.
 */
public final class CardLocks {

  /** A caller's lock on a card; two reservations never have the same lock. */
  public static final class Lock {
    private final String cardHandle;

    private Lock(String cardHandle) {
      this.cardHandle = cardHandle;
    }

    public String cardHandle() {
      return cardHandle;
    }
  }

  private final ConcurrentMap<String, Lock> locks = new ConcurrentHashMap<>();

  /** TUC_KON_023 with doLock=true; 4093 if the card is already reserved (2Ai). */
  public Lock lock(String cardHandle) {
    Lock lock = new Lock(cardHandle);
    if (locks.putIfAbsent(cardHandle, lock) != null) {
      throw ConnectorError.CARD_LOCKED.exception(cardHandle);
    }
    return lock;
  }

  /**
   * TUC_KON_023 with doLock=false. A lock already released (card removed) has no effect, so that
   * the reservation reliably ends even in the error case.
   */
  public void unlock(Lock lock) {
    locks.remove(lock.cardHandle, lock);
  }

  /** Whether the card {@code cardHandle} is reserved. */
  public boolean locked(String cardHandle) {
    return locks.containsKey(cardHandle);
  }

  /** TUC_KON_026 step 2 for a caller without lock: 4093 if the card is reserved. */
  public void checkFree(String cardHandle) {
    if (locked(cardHandle)) {
      throw ConnectorError.CARD_LOCKED.exception(
          cardHandle + " ist durch eine Kartensitzung reserviert");
    }
  }
}

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
package de.gematik.liana.kern.management;

import de.gematik.liana.kern.event.SystemLog;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * The configuration parameters the KMS can read and set (LIANA-55), independent of the vendor:
 * {@code CARD_SESSION_TIMEOUT} (TAB_KON_554) and {@code MGM_LU_ONLINE} (TAB_KON_658). Changes are
 * volatile, {@link #reset()} restores the boot state (decision-4).
 *
 * <p>{@code MGM_LU_ONLINE} is accepted and reported; it only affects the Onlineprüfung
 * (Onlineprüfung) of the Fachmodul VSDM ({@code kern.vsdm.OnlineCheck}, Disabled: no source, result
 * 3); LIANA establishes no further online connections.
 */
public final class ManagementSettings {

  /** Value range of CARD_SESSION_TIMEOUT per TAB_KON_554. */
  public static final Duration SESSION_TIMEOUT_MIN = Duration.ofSeconds(10);

  public static final Duration SESSION_TIMEOUT_MAX = Duration.ofSeconds(180);

  /** Topic of TUC_KON_256 when MGM_LU_ONLINE changes (TAB_KON_658). */
  public static final String LU_ONLINE_CHANGED = "MGM/LU_CHANGED/LU_ONLINE";

  private final Duration bootSessionTimeout;
  private final Duration bootCardTimeout;
  private final SystemLog systemLog;
  private volatile Duration sessionTimeout;
  private volatile Duration cardTimeout;
  private volatile boolean online = true;
  private final List<Runnable> onlineListeners = new CopyOnWriteArrayList<>();

  /**
   * {@code sessionTimeout} and {@code cardTimeout}: CARD_SESSION_TIMEOUT and CARD_TIMEOUT_CARD from
   * the YAML; MGM_LU_ONLINE starts as Enabled.
   */
  public ManagementSettings(Duration sessionTimeout, Duration cardTimeout, SystemLog systemLog) {
    this.bootSessionTimeout = checkSessionTimeout(sessionTimeout);
    this.sessionTimeout = sessionTimeout;
    this.bootCardTimeout = checkCardTimeout(cardTimeout);
    this.cardTimeout = cardTimeout;
    this.systemLog = systemLog;
  }

  /**
   * CARD_TIMEOUT_CARD (TAB_KON_554): longest duration of a reset or an APDU to a card, then 4094.
   */
  public Duration cardTimeout() {
    return cardTimeout;
  }

  /**
   * Sets CARD_TIMEOUT_CARD; applies from the next card command.
   *
   * @throws IllegalArgumentException if not positive
   */
  public void cardTimeout(Duration timeout) {
    cardTimeout = checkCardTimeout(timeout);
  }

  /** CARD_TIMEOUT_CARD from the YAML, target of {@link #reset()}. */
  public Duration bootCardTimeout() {
    return bootCardTimeout;
  }

  /**
   * CARD_SESSION_TIMEOUT: deadline until the first SecureSendAPDU, applies to new card sessions.
   */
  public Duration sessionTimeout() {
    return sessionTimeout;
  }

  /**
   * Sets CARD_SESSION_TIMEOUT for future card sessions.
   *
   * @throws IllegalArgumentException outside 10–180 s (TAB_KON_554)
   */
  public void sessionTimeout(Duration timeout) {
    sessionTimeout = checkSessionTimeout(timeout);
  }

  /** CARD_SESSION_TIMEOUT from the YAML, target of {@link #reset()}. */
  public Duration bootSessionTimeout() {
    return bootSessionTimeout;
  }

  /** MGM_LU_ONLINE: online scope of services (Leistungsumfang Online) enabled. */
  public boolean online() {
    return online;
  }

  /**
   * Sets MGM_LU_ONLINE; a change is reported by TUC_KON_256 MGM/LU_CHANGED/LU_ONLINE (TAB_KON_658)
   * and notifies the listeners (Betriebszustand, A_17085–A_17087).
   */
  public synchronized void online(boolean enabled) {
    if (online != enabled) {
      online = enabled;
      systemLog.write(
          SystemLog.Type.OP,
          SystemLog.Severity.INFO,
          LU_ONLINE_CHANGED,
          Map.of("Active", enabled ? "Enabled" : "Disabled"));
      onlineListeners.forEach(Runnable::run);
    }
  }

  /**
   * Called after every change of MGM_LU_ONLINE via {@link #online(boolean)}, not on {@link
   * #reset()}.
   */
  public void addOnlineListener(Runnable listener) {
    onlineListeners.add(listener);
  }

  /**
   * Restores the boot state: CARD_SESSION_TIMEOUT and CARD_TIMEOUT_CARD from the YAML,
   * MGM_LU_ONLINE Enabled, without event.
   */
  public synchronized void reset() {
    sessionTimeout = bootSessionTimeout;
    cardTimeout = bootCardTimeout;
    online = true;
  }

  private static Duration checkCardTimeout(Duration timeout) {
    if (timeout.isNegative() || timeout.isZero()) {
      throw new IllegalArgumentException("CARD_TIMEOUT_CARD muss positiv sein, ist " + timeout);
    }
    return timeout;
  }

  private static Duration checkSessionTimeout(Duration timeout) {
    if (timeout.compareTo(SESSION_TIMEOUT_MIN) < 0 || timeout.compareTo(SESSION_TIMEOUT_MAX) > 0) {
      throw new IllegalArgumentException(
          "CARD_SESSION_TIMEOUT " + timeout.toMillis() + " ms außerhalb 10–180 s (TAB_KON_554)");
    }
    return timeout;
  }
}

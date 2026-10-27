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

import de.gematik.liana.kern.vendor.Deviation;
import de.gematik.liana.kern.vendor.PeerDeviations;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Configuration values of the Komfortsignatur (Komfortsignatur) per TAB_KON_596 (TIP1-A_4680-03)
 * that the KMS reads and sets (LIANA-112.06): {@code SAK_COMFORT_SIGNATURE} (default Disabled),
 * {@code SAK_COMFORT_SIGNATURE_MAX} (1–250, default 100) and {@code SAK_COMFORT_SIGNATURE_TIMER}
 * (1–24 h, default 6 h). Changes are volatile, {@link #reset()} restores the defaults (decision-4).
 *
 * <p>TAB_KON_596 allows Enabled only with ANCL_TLS_MANDATORY and ANCL_CAUT_MANDATORY; without both,
 * LIANA enables the function anyway and reports the deviation to the Systemprotokoll; with {@code
 * liana.strict} it refuses ({@link Deviation#COMFORT_WITHOUT_CLIENT_TLS}).
 */
public final class ComfortSettings {

  public static final int MAX_MIN = 1;
  public static final int MAX_MAX = 250;
  public static final int DEFAULT_MAX = 100;
  public static final Duration TIMER_MIN = Duration.ofHours(1);
  public static final Duration TIMER_MAX = Duration.ofHours(24);
  public static final Duration DEFAULT_TIMER = Duration.ofHours(6);

  private final ClientSystemBinding binding;
  private final PeerDeviations deviations;
  private final List<Runnable> disabledListeners = new CopyOnWriteArrayList<>();
  private volatile boolean enabled;
  private volatile int max = DEFAULT_MAX;
  private volatile Duration timer = DEFAULT_TIMER;

  public ComfortSettings(ClientSystemBinding binding, PeerDeviations deviations) {
    this.binding = binding;
    this.deviations = deviations;
  }

  /** {@code listener} runs when the function is disabled (TUC_KON_172, trigger administrator). */
  public void onDisabled(Runnable listener) {
    disabledListeners.add(listener);
  }

  /** SAK_COMFORT_SIGNATURE: Komfortsignatur function enabled in the connector. */
  public boolean enabled() {
    return enabled;
  }

  /**
   * Sets SAK_COMFORT_SIGNATURE; Disabled ends all Komfortsignatur sessions (TUC_KON_172).
   *
   * @throws IllegalStateException Enabled without ANCL_TLS_MANDATORY and ANCL_CAUT_MANDATORY with
   *     {@code liana.strict}
   */
  public void enabled(boolean value) {
    boolean was;
    synchronized (this) {
      if (value && !enabled) {
        ClientSystemBinding.State state = binding.state();
        boolean tls =
            state.tlsMandatory()
                && state.authentication() != ClientSystemBinding.Authentication.NONE;
        if (!tls
            && !deviations.tolerate(
                Deviation.COMFORT_WITHOUT_CLIENT_TLS,
                "KMS",
                Map.of(
                    "ANCL_TLS_MANDATORY",
                    String.valueOf(state.tlsMandatory()),
                    "ANCL_CAUT_MODE",
                    state.authentication().name()))) {
          throw new IllegalStateException(
              "SAK_COMFORT_SIGNATURE nur mit ANCL_TLS_MANDATORY und ANCL_CAUT_MANDATORY (TAB_KON_596)");
        }
      }
      was = enabled;
      enabled = value;
    }
    if (was && !value) {
      disabledListeners.forEach(Runnable::run);
    }
  }

  /** SAK_COMFORT_SIGNATURE_MAX: Komfortsignaturen without renewed PIN entry per session. */
  public int max() {
    return max;
  }

  /**
   * Sets SAK_COMFORT_SIGNATURE_MAX; also applies to running sessions.
   *
   * @throws IllegalArgumentException outside 1–250 (TAB_KON_596)
   */
  public void max(int value) {
    if (value < MAX_MIN || value > MAX_MAX) {
      throw new IllegalArgumentException("SAK_COMFORT_SIGNATURE_MAX " + value + " außerhalb 1–250");
    }
    max = value;
  }

  /** SAK_COMFORT_SIGNATURE_TIMER: period from PIN entry in which Komfortsignaturen are allowed. */
  public Duration timer() {
    return timer;
  }

  /**
   * Sets SAK_COMFORT_SIGNATURE_TIMER; also applies to running sessions.
   *
   * @throws IllegalArgumentException outside 1–24 h (TAB_KON_596)
   */
  public void timer(Duration value) {
    if (value.compareTo(TIMER_MIN) < 0 || value.compareTo(TIMER_MAX) > 0) {
      throw new IllegalArgumentException(
          "SAK_COMFORT_SIGNATURE_TIMER " + value + " außerhalb 1–24 h");
    }
    timer = value;
  }

  /** Restores the defaults from TAB_KON_596; if the function was on, its sessions end. */
  public void reset() {
    max = DEFAULT_MAX;
    timer = DEFAULT_TIMER;
    enabled(false);
  }
}

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

import java.time.Duration;

/**
 * Where the Konnektor is located; only sets defaults that the builder can override (LIANA-133).
 * {@code .kon} v1.0.0 has no field for it; from a {@code .kon} it is {@link #LOCAL} unless
 * something else is specified.
 */
public enum Deployment {
  /** Konnektor in the local network or LIANA: short timeouts, PIN entry without hook. */
  LOCAL(Duration.ofSeconds(10), Duration.ofMinutes(3), false),
  /**
   * Konnektor at a KSP (Konnektor service provider): long network path, PIN entry only via a hook
   * (LIANA-137).
   */
  KSP(Duration.ofSeconds(30), Duration.ofMinutes(5), true),
  /** Konnektor cluster in a data center. */
  CLUSTER(Duration.ofSeconds(20), Duration.ofMinutes(5), false);

  private final Duration shortTimeout;
  private final Duration longTimeout;
  private final boolean pinHookRequired;

  Deployment(Duration shortTimeout, Duration longTimeout, boolean pinHookRequired) {
    this.shortTimeout = shortTimeout;
    this.longTimeout = longTimeout;
    this.pinHookRequired = pinHookRequired;
  }

  /** Timeout for {@link Timing#SHORT}. */
  public Duration shortTimeout() {
    return shortTimeout;
  }

  /** Timeout for {@link Timing#LONG}. */
  public Duration longTimeout() {
    return longTimeout;
  }

  /** Whether a hook must run before a PIN entry (LIANA-137). */
  public boolean pinHookRequired() {
    return pinHookRequired;
  }
}

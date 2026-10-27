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
package de.gematik.liana;

import jakarta.annotation.Priority;
import jakarta.enterprise.inject.Alternative;
import jakarta.inject.Singleton;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Clock of the Quarkus tests instead of {@code Clock.systemUTC()} (LIANA-55 AC2): runs with the
 * system time, {@link #advance} moves it forward so tests can let deadlines (CARD_SESSION_TIMEOUT,
 * TimeSpan) expire without real waiting. It never goes back; tests running afterwards only see a
 * later time.
 */
@Singleton
@Alternative
@Priority(1)
public class ShiftableClock extends Clock {

  private final AtomicReference<Duration> offset = new AtomicReference<>(Duration.ZERO);

  /** Like the wait in a Postman pre-request script ({@code setTimeout}), just without waiting. */
  public void advance(Duration duration) {
    offset.accumulateAndGet(duration, Duration::plus);
  }

  @Override
  public Instant instant() {
    return Instant.now().plus(offset.get());
  }

  @Override
  public ZoneId getZone() {
    return ZoneOffset.UTC;
  }

  @Override
  public Clock withZone(ZoneId zone) {
    throw new UnsupportedOperationException("ShiftableClock bleibt in UTC");
  }
}

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
package de.gematik.liana.crypto;

import de.gematik.liana.kern.signature.RevocationSource;
import jakarta.enterprise.inject.Alternative;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.time.Clock;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * {@link SimulatedOcsp} that counts the status requests (LIANA-112.03 AC1: no request offline).
 * Only active where a test profile enables it via {@code getEnabledAlternatives}.
 */
@Alternative
@Singleton
public class CountingRevocation implements RevocationSource {

  private final SimulatedOcsp ocsp;
  private final AtomicInteger requests = new AtomicInteger();

  @Inject
  CountingRevocation(Clock clock) {
    this.ocsp = new SimulatedOcsp(clock);
  }

  @Override
  public Answer status(byte[] certificate) {
    requests.incrementAndGet();
    return ocsp.status(certificate);
  }

  /** Requests since the last call. */
  public int takeRequests() {
    return requests.getAndSet(0);
  }
}

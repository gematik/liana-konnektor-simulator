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
package de.gematik.liana.kern.vsdm;

import java.io.IOException;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Stage {@value #CONFIG_NAME} of the Onlineprüfung (LIANA-141): „Aktualisierungsaufträge ermitteln“
 * (Tab_FM_VSDM_15, 4.3.1) via GetUpdateFlags to an ordered list of UFS endpoints. An endpoint with
 * ProviderID applies only to eGKs with this ProviderID in the AUT certificate (Fachdienst
 * localization 4.3.3, like {@code iinConfig.yml} of the vsdm-e2e suite), one without to all. The
 * UFS Prüfziffer goes unchanged into the Prüfungsnachweis.
 *
 * <p>An endpoint that was unreachable or exceeded the time limit is skipped for {@code retryAfter},
 * so that not every ReadVSD waits for it. Connection setup at most {@code connectTimeout}, response
 * at most TIMEOUT_VSDM, both within the remaining MAXTIME_VSDM.
 */
public final class UfsSource implements OnlineCheck.Source {

  public static final String CONFIG_NAME = "ufs";

  /** A UFS endpoint, {@code providerId} {@code null} for all eGKs. */
  public record Endpoint(URI url, String providerId) {}

  private final List<Endpoint> endpoints;
  private final UpdateFlagService service;
  private final Duration connectTimeout;
  private final Duration timeout;
  private final Duration retryAfter;
  private final Clock clock;
  private final Map<URI, Instant> unreachableUntil = new ConcurrentHashMap<>();

  /**
   * @param timeout TIMEOUT_VSDM (Tab_FM_VSDM_14)
   */
  public UfsSource(
      List<Endpoint> endpoints,
      UpdateFlagService service,
      Duration connectTimeout,
      Duration timeout,
      Duration retryAfter,
      Clock clock) {
    this.endpoints = List.copyOf(endpoints);
    this.service = service;
    this.connectTimeout = connectTimeout;
    this.timeout = timeout;
    this.retryAfter = retryAfter;
    this.clock = clock;
  }

  @Override
  public String name() {
    return CONFIG_NAME;
  }

  @Override
  public Optional<OnlineCheck.Answer> ask(OnlineCheck.Request request, OnlineCheck.Notes notes) {
    List<Endpoint> matching =
        endpoints.stream()
            .filter(e -> e.providerId() == null || e.providerId().equals(request.providerId()))
            .toList();
    if (matching.isEmpty()) {
      notes.add(CONFIG_NAME, "kein Endpunkt für ProviderID " + request.providerId());
      return Optional.empty();
    }
    if (request.iccsn() == null) {
      notes.add(CONFIG_NAME, "ICCSN der eGK nicht lesbar (EF.GDO)");
      return Optional.empty();
    }
    for (Endpoint endpoint : matching) {
      Instant until = unreachableUntil.get(endpoint.url());
      if (until != null && clock.instant().isBefore(until)) {
        notes.add(
            CONFIG_NAME,
            endpoint.url() + " übersprungen bis " + until + " (zuletzt nicht erreichbar)");
        continue;
      }
      Duration remaining = request.budget().remaining();
      if (remaining.isZero()) {
        notes.add(CONFIG_NAME, endpoint.url() + " nicht gefragt, MAXTIME_VSDM abgelaufen");
        return Optional.empty();
      }
      try {
        UpdateFlagService.Answer answer =
            service.getUpdateFlags(
                endpoint.url(),
                request.iccsn(),
                request.providerId(),
                request.context(),
                request.smb(),
                min(connectTimeout, remaining),
                min(timeout, remaining));
        unreachableUntil.remove(endpoint.url());
        return Optional.of(
            switch (answer) {
              case UpdateFlagService.Flags flags -> {
                // VSDM-A_2597 ff.: the Fachmodul ignores optional updates
                var mandatory =
                    flags.flags().stream().filter(UpdateFlagService.UpdateFlag::mandatory).toList();
                yield mandatory.isEmpty()
                    ? new OnlineCheck.NoUpdate(flags.receipt())
                    : new OnlineCheck.UpdatePending(mandatory);
              }
              case UpdateFlagService.Fault fault ->
                  new OnlineCheck.Fault(fault.code(), fault.text());
            });
      } catch (IOException e) {
        unreachableUntil.put(endpoint.url(), clock.instant().plus(retryAfter));
        notes.add(CONFIG_NAME, endpoint.url() + " nicht erreichbar: " + e.getMessage());
      }
    }
    return Optional.empty();
  }

  private static Duration min(Duration a, Duration b) {
    return a.compareTo(b) <= 0 ? a : b;
  }

  /** {@code POST /admin/reset}: ask skipped endpoints again. */
  @Override
  public void reset() {
    unreachableUntil.clear();
  }
}

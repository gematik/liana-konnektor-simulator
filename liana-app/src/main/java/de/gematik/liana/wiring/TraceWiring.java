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
package de.gematik.liana.wiring;

import de.gematik.liana.config.LianaConfig;
import de.gematik.liana.kern.trace.Traffic;
import de.gematik.liana.trace.HttpTrace;
import de.gematik.liana.trace.TraceChannels;
import de.gematik.liana.trace.TrafficPush;
import io.vertx.ext.web.Router;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.enterprise.inject.Disposes;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;
import java.net.URI;
import java.util.Optional;
import java.util.stream.Stream;
import org.jboss.logging.Logger;

/**
 * Tracing (LIANA-27, LIANA-195): with {@code liana.trace.push-url} every channel reports its
 * messages to the Tiger proxy there, without the URL nothing is reported ({@link Traffic#OFF}).
 */
@ApplicationScoped
public class TraceWiring {

  private static final Logger LOG = Logger.getLogger(TraceWiring.class);

  @Produces
  @Singleton
  Traffic traffic(LianaConfig config) {
    return trafficOf(config);
  }

  static Traffic trafficOf(LianaConfig config) {
    return config
        .trace()
        .pushUrl()
        .<Traffic>map(
            url -> {
              TrafficPush push = new TrafficPush(url, config.trace().pushTimeout(), name(config));
              LOG.infof(
                  "Verkehr geht ergänzend per Traffic-Push an %s, LIANA heißt dort %s",
                  push.target(), push.name());
              return push;
            })
        .orElse(Traffic.OFF);
  }

  /**
   * Symbolic name of this connector in the trace (LIANA-195.04): {@code liana.trace.name},
   * otherwise the host of {@code liana.tls.url} or {@code liana.kon-export.url} if it is a name,
   * otherwise {@link Traffic#DEFAULT_NAME}. Tiger takes only a name as server name, not an IP and
   * not {@code localhost}, so a configured one of these stops the startup.
   */
  public static String name(LianaConfig config) {
    return name(config.trace().name(), config.tls().url(), config.konExport().url());
  }

  /** {@link #name(LianaConfig)} from the three settings. */
  static String name(Optional<String> traceName, Optional<String> tlsUrl, Optional<String> konUrl) {
    Optional<String> configured = traceName.map(String::trim);
    if (configured.isPresent()) {
      String name = configured.get();
      if (!Traffic.isName(name)) {
        throw new IllegalArgumentException(
            "liana.trace.name: ein Name wie konnektor-a erwartet (Buchstaben, Ziffern, '.', '-'),"
                + " keine IP und nicht localhost, nicht "
                + name);
      }
      return name;
    }
    return Stream.of(tlsUrl, konUrl)
        .flatMap(Optional::stream)
        .map(TraceWiring::host)
        .filter(Traffic::isName)
        .findFirst()
        .orElse(Traffic.DEFAULT_NAME);
  }

  private static String host(String url) {
    try {
      String host = URI.create(url.trim()).getHost();
      return host == null ? "" : host;
    } catch (IllegalArgumentException e) {
      return "";
    }
  }

  /** The channels, switchable through the Admin API (LIANA-195.05). */
  @Produces
  @Singleton
  TraceChannels channels(Traffic traffic) {
    return new TraceChannels(traffic);
  }

  /** Konnektor interface, HTTP and HTTPS (both serve this router), every path. */
  void konnektor(@Observes Router router, TraceChannels channels) {
    HttpTrace.install(router, channels.traffic(TraceChannels.KONNEKTOR), path -> true);
  }

  void close(@Disposes Traffic traffic) {
    if (traffic instanceof TrafficPush push) {
      push.close();
    }
  }
}

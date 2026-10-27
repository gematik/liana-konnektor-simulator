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

import de.gematik.liana.adapter.cetp.CetpSender;
import de.gematik.liana.config.LianaConfig;
import de.gematik.liana.crypto.CetpTls;
import de.gematik.liana.crypto.TlsIdentity;
import de.gematik.liana.kern.access.Infomodel;
import de.gematik.liana.kern.event.Subscriptions;
import de.gematik.liana.kern.management.ClientSystemBinding;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Disposes;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.time.Clock;
import java.time.Duration;

/**
 * System information service (LIANA-59): subscription management of the core with delivery via
 * CETP; EVT_MAX_TRY from {@code liana.events.max-try}. TAB_KON_852: with ANCL_TLS_MANDATORY Enabled
 * (CETP1) via TLS ({@link CetpTls}, client certificate ID.AK.AUT of the gSMC-K), Disabled (CETP2)
 * via TCP without TLS (LIANA-117); the state at connection setup is what counts, the KMS can switch
 * it. With {@code liana.events.redirect} all connections go to a fixed address instead of the
 * EventTo (Tiger proxy in front of the Ereignissenke, LIANA-183). The card list reports its events
 * to the subscription management in {@link TerminalWiring}.
 */
@ApplicationScoped
public class EventWiring {

  private static final System.Logger LOG = System.getLogger(EventWiring.class.getName());

  @Produces
  @Singleton
  CetpSender cetpSender(LianaConfig config, TlsIdentity identity, ClientSystemBinding binding)
      throws GeneralSecurityException {
    Duration timeout = config.events().connectTimeout();
    CetpTls tls = new CetpTls(identity, timeout);
    CetpSender.Connector connector =
        (host, port) ->
            binding.state().tlsMandatory() ? tls.connect(host, port) : plain(host, port, timeout);
    return new CetpSender(
        config.events().redirect().map(target -> redirected(connector, target)).orElse(connector));
  }

  /**
   * Opens every connection to {@code host:port} instead of the Ereignissenke of the subscription.
   */
  static CetpSender.Connector redirected(CetpSender.Connector connector, String target) {
    int colon = target.lastIndexOf(':');
    if (colon <= 0 || colon == target.length() - 1) {
      throw new IllegalArgumentException(
          "liana.events.redirect: host:port erwartet, nicht " + target);
    }
    String host = target.substring(0, colon);
    int port = Integer.parseInt(target.substring(colon + 1));
    LOG.log(
        System.Logger.Level.INFO,
        "liana.events.redirect: CETP-Verbindungen gehen an "
            + target
            + " statt an das EventTo der Anmeldung");
    return (eventToHost, eventToPort) -> connector.connect(host, port);
  }

  /** CETP2: TCP without TLS, time limit for the connection setup as with TLS. */
  private static Socket plain(String host, int port, Duration timeout) throws IOException {
    Socket tcp = new Socket();
    try {
      tcp.connect(new InetSocketAddress(host, port), Math.toIntExact(timeout.toMillis()));
      return tcp;
    } catch (IOException | RuntimeException e) {
      tcp.close();
      throw e;
    }
  }

  void close(@Disposes CetpSender sender) {
    sender.close();
  }

  @Produces
  @Singleton
  Subscriptions subscriptions(
      Infomodel infomodel, Clock clock, CetpSender sender, LianaConfig config) {
    return new Subscriptions(infomodel, clock, sender, config.events().maxTry());
  }
}

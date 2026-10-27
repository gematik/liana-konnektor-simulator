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
package de.gematik.liana.tls;

import de.gematik.liana.kern.management.ClientSystemBinding;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Singleton;
import org.jboss.logging.Logger;

/**
 * TIP1-A_4515: with ANCL_TLS_MANDATORY Enabled LIANA rejects calls of the Clientsysteme without
 * TLS, except {@code connector.sds} with ANCL_DVD_OPEN Enabled (TAB_KON_852 SOAP1–3, DVD1/DVD2).
 * The HTTP port and {@link KonnektorTlsServer} share the router; therefore every request is checked
 * for whether it came via TLS. Rejection is a 403 and closing the connection (TIP1-A_4518-02: open
 * HTTP connections end after the running operation).
 */
@Singleton
public class PlainHttpGuard {

  private static final Logger LOG = Logger.getLogger(PlainHttpGuard.class);

  static final String SERVICE_DIRECTORY = "/connector.sds";

  private final ClientSystemBinding binding;

  PlainHttpGuard(ClientSystemBinding binding) {
    this.binding = binding;
  }

  void router(@Observes Router router) {
    router.route().order(Integer.MIN_VALUE).handler(this::check);
  }

  private void check(RoutingContext ctx) {
    if (ctx.request().isSSL()
        || binding.state().allowsPlainHttp(SERVICE_DIRECTORY.equals(ctx.request().path()))) {
      ctx.next();
      return;
    }
    LOG.warnf(
        "ANCL_TLS_MANDATORY: %s %s ohne TLS abgelehnt (TIP1-A_4515)",
        ctx.request().method(), ctx.request().path());
    ctx.response()
        .setStatusCode(403)
        .putHeader("Content-Type", "text/plain; charset=UTF-8")
        .putHeader("Connection", "close")
        .end("ANCL_TLS_MANDATORY ist Enabled: Aufrufe nur über TLS (TIP1-A_4515)")
        .onComplete(done -> ctx.request().connection().close());
  }
}

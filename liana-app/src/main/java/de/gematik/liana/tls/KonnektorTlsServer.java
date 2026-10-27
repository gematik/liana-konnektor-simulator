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

import de.gematik.liana.config.LianaConfig;
import de.gematik.liana.crypto.ClientCertificates;
import de.gematik.liana.crypto.KonnektorTls;
import de.gematik.liana.crypto.ServerIdentities;
import de.gematik.liana.crypto.TlsIdentity;
import de.gematik.liana.kern.management.ClientSystemBinding;
import io.quarkus.runtime.ShutdownEvent;
import io.quarkus.runtime.StartupEvent;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServer;
import io.vertx.ext.web.Router;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Singleton;
import java.util.concurrent.ExecutionException;
import org.jboss.logging.Logger;

/**
 * HTTPS port of the connector interface ({@code liana.tls.port}, TIP1-A_4514-01, TIP1-A_4515): the
 * same services as on the HTTP port ({@code connector.sds}, SOAP under {@code /ws/*}), because the
 * server serves the router of the application. A separate Vert.x server instead of Quarkus's HTTPS,
 * because Quarkus builds its TLS context itself and Brainpool does not work there.
 *
 * <p>The server queries server identity and client authentication on every handshake ({@link
 * ServerIdentities}, {@link ClientSystemBinding}, {@link ClientCertificates}): changes via the KMS
 * apply from the next connection (LIANA-65). With ANCL_CAUT_MANDATORY with CERTIFICATE it rejects
 * every handshake without a certificate from ANCL_CCERT_LIST (TIP1-A_4516, TAB_KON_506-01). {@link
 * #restart()} rebuilds the TLS context and closes existing connections (restart via the KMS). Port
 * 0 picks a free port ({@link #port()}).
 */
@Singleton
public class KonnektorTlsServer {

  private static final Logger LOG = Logger.getLogger(KonnektorTlsServer.class);

  private final Vertx vertx;
  private final int configuredPort;
  private final ServerIdentities identities;
  private final ClientSystemBinding binding;
  private final ClientCertificates clients;
  private Router router;
  private volatile HttpServer server;

  KonnektorTlsServer(
      Vertx vertx,
      LianaConfig config,
      ServerIdentities identities,
      ClientSystemBinding binding,
      ClientCertificates clients) {
    this.vertx = vertx;
    this.configuredPort = config.tls().port();
    this.identities = identities;
    this.binding = binding;
    this.clients = clients;
  }

  /** Router of the application, which Quarkus hands to its observers before the start. */
  void router(@Observes Router router) {
    this.router = router;
  }

  void start(@Observes StartupEvent event) throws InterruptedException, ExecutionException {
    listen(configuredPort);
    TlsIdentity identity = identities.current();
    LOG.infof(
        "Konnektor-Schnittstelle auf Port %d (HTTPS, %s, Client-Auth %s), Zertifikat SHA-256 %s",
        server.actualPort(),
        identity.certificate().getSubjectX500Principal().getName(),
        binding.state().authentication(),
        identity.fingerprint());
  }

  private void listen(int port) throws InterruptedException, ExecutionException {
    var authentication =
        new KonnektorTls.ClientAuthentication(
            () ->
                binding.state().authentication() == ClientSystemBinding.Authentication.CERTIFICATE,
            clients.trustManager());
    server =
        vertx
            .createHttpServer(KonnektorTls.serverOptions(identities.keyManager(), authentication))
            .requestHandler(router)
            .listen(port)
            .toCompletionStage()
            .toCompletableFuture()
            .get();
  }

  /**
   * Restart via the KMS: closes the port with all connections and opens it with a new TLS context.
   */
  public synchronized void restart() throws InterruptedException, ExecutionException {
    int port = server.actualPort();
    server.close().toCompletionStage().toCompletableFuture().get();
    listen(port);
    LOG.infof(
        "Konnektor-Schnittstelle auf Port %d neu gestartet, Zertifikat SHA-256 %s",
        port, identities.current().fingerprint());
  }

  void stop(@Observes ShutdownEvent event) {
    if (server != null) {
      server.close();
    }
  }

  /** Actual port, even if {@code liana.tls.port} is 0. */
  public int port() {
    return server.actualPort();
  }
}

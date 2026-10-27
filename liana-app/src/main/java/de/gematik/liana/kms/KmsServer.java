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
package de.gematik.liana.kms;

import de.gematik.liana.config.LianaConfig;
import de.gematik.liana.crypto.ClientCertificates;
import de.gematik.liana.crypto.KonnektorTls;
import de.gematik.liana.crypto.ServerIdentities;
import de.gematik.liana.crypto.TlsIdentity;
import de.gematik.liana.kern.event.SystemLog;
import de.gematik.liana.kern.management.ClientSystemBinding;
import de.gematik.liana.kern.management.ComfortSettings;
import de.gematik.liana.kern.management.ManagementSettings;
import de.gematik.liana.kern.vendor.VendorProfile;
import de.gematik.liana.tls.KonnektorTlsServer;
import io.quarkus.runtime.ShutdownEvent;
import io.quarkus.runtime.StartupEvent;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.json.Json;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import jakarta.enterprise.event.Event;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Singleton;
import java.security.GeneralSecurityException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.concurrent.ExecutionException;
import org.jboss.logging.Logger;

/**
 * KMS of the vendor profile under {@value #MOUNT} on the management port (decision-017, {@code
 * AdminServer}), just as the connectors offer their management separately from the connector
 * interface. The suites reach it via kms-client with the vendor from their environment
 * (decision-10). If the active profile speaks the EHEX KMS ({@link VendorProfile#ehexKms()}),
 * {@link EhexKms} answers its subset; if it speaks the KOCO KMS ({@link VendorProfile#kocoKms()}),
 * {@link KocoKms} answers its subset under the root paths of the KoCoBox ({@code
 * /j_security_check}, {@code /administration/*}, LIANA-96); if it speaks the RISE KMS ({@link
 * VendorProfile#riseKms()}), {@link RiseKms} answers its subset under {@code /api/*} (LIANA-97).
 * Everything else responds with HTTP 501, JSON with vendor profile, method and path, plus a warning
 * in the log (decision-12).
 *
 * <p>konnektor-service-client addresses the RISE KMS on port 8443, which for LIANA is the HTTPS
 * port of the connector interface ({@code liana.tls.port}). That is why the RISE paths are also
 * attached to the router of the connector interface, there only via TLS and only with profile RISE,
 * otherwise 404 as before; they do not overlap with SOAP ({@code /ws/*}) and {@code
 * /connector.sds}.
 *
 * <p>The management port speaks HTTP and HTTPS; TLS according to TIP1-A_4806-01 as at the connector
 * interface ({@link KonnektorTls}, identity from ID.AK.AUT of the gSMC-K), without client auth:
 * login works via password and token. Over HTTP the login goes in plaintext, TIP1-A_5661 allows
 * that in RU/TU (decision-017). With {@code liana.kms.port} LIANA additionally opens its own HTTPS
 * listener with the same routes, as up to 0.6 on 8500 (EHEX, SECUNET) or on 9443, where
 * konnektor-service-client addresses the KMS of the KoCoBox; without the setting it stays closed.
 */
@Singleton
public class KmsServer {

  private static final Logger LOG = Logger.getLogger(KmsServer.class);

  private final Vertx vertx;
  private final VendorProfile vendor;

  /** Path of the KMS on the management port; all paths of the vendor interfaces start with it. */
  public static final String MOUNT = "/rest/mgmt";

  private final Optional<Integer> compatibilityPort;
  private final TlsIdentity identity;
  private final Router router;
  private final KocoKms koco;
  private final RiseKms rise;
  private final Event<KmsChanged> changed;
  private HttpServer server;

  KmsServer(
      Vertx vertx,
      VendorProfile vendor,
      LianaConfig config,
      ManagementSettings settings,
      ComfortSettings comfort,
      SystemLog systemLog,
      TlsIdentity identity,
      ClientSystemBinding binding,
      ClientCertificates certificates,
      ServerIdentities identities,
      KonnektorTlsServer tlsServer,
      Event<KmsChanged> changed) {
    this.vertx = vertx;
    this.identity = identity;
    this.vendor = vendor;
    this.changed = changed;
    this.compatibilityPort = config.kms().port();
    router = Router.router(vertx);
    router
        .route()
        .handler(
            ctx -> {
              if (vendor.ehexKms()) {
                ctx.next();
              } else {
                notImplemented(ctx.request());
              }
            });
    router.route().handler(ctx -> changed(ctx, changed));
    new EhexKms(
            config,
            settings,
            comfort,
            systemLog,
            new EhexClientSystems(config, binding, certificates, identities),
            () -> reboot(tlsServer),
            ctx -> notImplemented(ctx.request()))
        .routes(router);
    koco = new KocoKms(config, settings, comfort, binding, ctx -> notImplemented(ctx.request()));
    rise = new RiseKms(config, settings, comfort, ctx -> notImplemented(ctx.request()));
  }

  /**
   * Reports successful writing calls, also via the compatibility listener (push of the admin API,
   * LIANA-150).
   */
  private static void changed(RoutingContext ctx, Event<KmsChanged> changed) {
    if (ctx.request().method() != HttpMethod.GET) {
      ctx.addEndHandler(
          v -> {
            if (ctx.response().getStatusCode() < 400) {
              changed.fire(new KmsChanged(ctx.request().method().name(), ctx.normalizedPath()));
            }
          });
    }
    ctx.next();
  }

  /**
   * Attaches the KMS to the root {@code root}: EHEX as subrouter under {@link #MOUNT}, KOCO under
   * {@link KocoKms#PATHS}, RISE under {@link RiseKms#PATHS}; each 501 if the active profile does
   * not speak the interface.
   */
  public void mountOn(Router root) {
    root.route(MOUNT + "/*").subRouter(router);
    root.route()
        .pathRegex(KocoKms.PATHS)
        .handler(
            ctx -> {
              if (vendor.kocoKms()) {
                ctx.next();
              } else {
                notImplemented(ctx.request());
              }
            })
        .handler(ctx -> changed(ctx, changed));
    koco.routes(root);
    root.route()
        .pathRegex(RiseKms.PATHS)
        .handler(
            ctx -> {
              if (vendor.riseKms()) {
                ctx.next();
              } else {
                notImplemented(ctx.request());
              }
            })
        .handler(ctx -> changed(ctx, changed));
    rise.routes(root);
  }

  /**
   * RISE KMS on the router of the connector interface (HTTP port and {@link KonnektorTlsServer}),
   * only via TLS and with profile RISE; otherwise 404, as if the paths did not exist.
   */
  void konnektor(@Observes Router konnektor) {
    konnektor
        .route()
        .pathRegex(RiseKms.PATHS)
        .handler(
            ctx -> {
              if (ctx.request().isSSL() && vendor.riseKms()) {
                ctx.next();
              } else {
                ctx.fail(404);
              }
            })
        .handler(ctx -> changed(ctx, changed));
    rise.routes(konnektor);
  }

  /** Path relative to {@link #MOUNT}, as the subrouter of the EHEX KMS sees it. */
  static String relative(String path) {
    if (!path.startsWith(MOUNT + "/")) {
      throw new IllegalArgumentException(path + " liegt nicht unter " + MOUNT);
    }
    return path.substring(MOUNT.length());
  }

  /** Restart via the KMS: new TLS context of the connector interface (LIANA-65). */
  private static void reboot(KonnektorTlsServer tlsServer) {
    LOG.info("KMS: Neustart, TLS-Kontext der Konnektor-Schnittstelle wird neu aufgebaut");
    try {
      tlsServer.restart();
    } catch (ExecutionException e) {
      LOG.error("Neustart der Konnektor-Schnittstelle fehlgeschlagen", e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }

  /** Compatibility listener on {@code liana.kms.port}, only if set. */
  void start(@Observes StartupEvent event)
      throws InterruptedException, ExecutionException, GeneralSecurityException {
    if (compatibilityPort.isEmpty()) {
      return;
    }
    Router root = Router.router(vertx);
    mountOn(root);
    root.route().handler(ctx -> notImplemented(ctx.request()));
    server =
        vertx
            .createHttpServer(KonnektorTls.serverOptions(identity, null))
            .requestHandler(root)
            .listen(compatibilityPort.get())
            .toCompletionStage()
            .toCompletableFuture()
            .get();
    LOG.infof("KMS zusätzlich auf Port %d (HTTPS, liana.kms.port)", server.actualPort());
  }

  /** TLS options for the HTTPS part of the management port: ID.AK.AUT, without client auth. */
  public HttpServerOptions tlsOptions() throws GeneralSecurityException {
    return KonnektorTls.serverOptions(identity, null);
  }

  void stop(@Observes ShutdownEvent event) {
    if (server != null) {
      server.close();
    }
  }

  /**
   * Port of the compatibility listener (actual, also with {@code liana.kms.port} 0); empty if it is
   * closed.
   */
  public OptionalInt compatibilityPort() {
    return server == null ? OptionalInt.empty() : OptionalInt.of(server.actualPort());
  }

  /**
   * decision-12: HTTP 501 with vendor profile, method and path. On the management port for
   * everything outside {@code /admin} and the KMS paths, and for the paths of the vendors that the
   * active profile does not speak.
   */
  public void notImplemented(HttpServerRequest request) {
    String profile = vendor.vendor().value();
    String operation = request.method() + " " + request.path();
    String message =
        "KMS des Herstellerprofils " + profile + ": " + operation + " ist in LIANA nicht umgesetzt";
    LOG.warn(message);
    Map<String, String> body = new LinkedHashMap<>();
    body.put("error", message);
    body.put("vendor", profile);
    body.put("method", request.method().name());
    body.put("path", request.path());
    request
        .response()
        .setStatusCode(501)
        .putHeader("Content-Type", "application/json")
        .end(Json.encode(body));
  }
}

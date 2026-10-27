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
package de.gematik.liana.admin;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.liana.adapter.fake.FakeTerminal;
import de.gematik.liana.adapter.fake.Fault;
import de.gematik.liana.cats.CatsServer;
import de.gematik.liana.config.LianaConfig;
import de.gematik.liana.crypto.CryptoSelfTest;
import de.gematik.liana.kern.error.ConnectorError;
import de.gematik.liana.kern.error.ConnectorException;
import de.gematik.liana.kms.KmsServer;
import de.gematik.liana.tls.ProtocolSwitch;
import io.quarkus.runtime.ShutdownEvent;
import io.quarkus.runtime.StartupEvent;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.json.Json;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.BodyHandler;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Singleton;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.function.Function;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

/**
 * Management port {@code liana.admin.port} (decision-4, decision-017), separate from the connector
 * interface: HTTP and HTTPS on the same port ({@link ProtocolSwitch}), both with the same router.
 * On it the admin API under {@code /admin/*} (JSON, without auth, internal network only) and the
 * KMS of the vendor profile under {@value KmsServer#MOUNT}, or for KOCO/CGM under {@code
 * /administration} (with its login), for RISE under {@code /api} ({@link KmsServer}) and CATS under
 * {@value CatsServer#MOUNT} ({@link CatsServer}, LIANA-147), the Control Center under {@code /}
 * ({@link Gui}, LIANA-148); HTTPS with ID.AK.AUT like the KMS, without client auth. All other paths
 * are management of other vendors and respond with 501 (decision-12), unknown ones under {@code
 * /admin} with 404. Port 0 picks a free port ({@link #port()}).
 */
@Singleton
public class AdminServer {

  private static final Logger LOG = Logger.getLogger(AdminServer.class);

  private final Vertx vertx;
  private final ObjectMapper json;
  private final AdminApi api;
  private final Readiness readiness;
  private final KmsServer kms;
  private final CatsServer cats;
  private final AdminEvents events;
  private final Gui gui = new Gui();
  private final OpenApi openApi;
  private final int configuredPort;
  private ProtocolSwitch server;

  AdminServer(
      Vertx vertx,
      ObjectMapper json,
      AdminApi api,
      Readiness readiness,
      KmsServer kms,
      CatsServer cats,
      LianaConfig config,
      @ConfigProperty(name = "quarkus.application.version") String version,
      AdminEvents events) {
    this.events = events;
    this.openApi = new OpenApi(version);
    this.vertx = vertx;
    this.kms = kms;
    this.cats = cats;
    this.json = json;
    this.api = api;
    this.readiness = readiness;
    this.configuredPort = config.admin().port();
  }

  void start(@Observes StartupEvent event)
      throws InterruptedException, ExecutionException, GeneralSecurityException {
    server = ProtocolSwitch.listen(vertx, configuredPort, router(), kms.tlsOptions());
    LOG.infof(
        "Admin-API auf Port %d (Management-Port, HTTP und HTTPS), KMS unter %s, CATS unter %s",
        server.port(), KmsServer.MOUNT, CatsServer.MOUNT);
  }

  void stop(@Observes ShutdownEvent event) {
    if (server != null) {
      server.close();
    }
  }

  /** Actual port, even if {@code liana.admin.port} is 0. */
  public int port() {
    return server.port();
  }

  /**
   * The routes of the admin API as {@code METHOD /admin/path/{param}}, for comparison with {@code
   * openapi.yaml} ({@code OpenApiTest}).
   */
  List<String> adminRoutes() {
    return router().getRoutes().stream()
        .filter(
            route ->
                route.getPath() != null
                    && route.getPath().startsWith("/admin/")
                    && route.methods() != null
                    && !route.methods().isEmpty())
        .flatMap(
            route ->
                route.methods().stream()
                    .map(
                        method ->
                            method.name()
                                + " "
                                + route.getPath().replaceAll(":([A-Za-z]+)", "{$1}")))
        .distinct()
        .sorted()
        .toList();
  }

  private Router router() {
    Router router = Router.router(vertx);
    router.route("/admin/*").handler(BodyHandler.create());
    router
        .get("/admin/ready")
        .handler(
            ctx -> {
              boolean ready = readiness.ready();
              respond(ctx, ready ? 200 : 503, Map.of("ready", ready));
            });
    get(router, "/admin/info", ctx -> api.info(port()));
    get(router, "/admin/terminals", ctx -> api.terminals());
    get(router, "/admin/terminals/:id", ctx -> api.terminal(ctx.pathParam("id")));
    get(router, "/admin/ct-list", ctx -> api.ctList());
    router.get(AdminEvents.PATH).handler(events::stream);
    terminal(
        router,
        HttpMethod.POST,
        "/admin/terminals/:id/pairing",
        "pairing",
        ctx -> api.pair(ctx.pathParam("id"), optionalBody(ctx, AdminApi.PairingPost.class)));
    terminal(
        router,
        HttpMethod.PUT,
        "/admin/terminals/:id/pairing",
        "pairing",
        ctx -> api.putPairing(ctx.pathParam("id"), body(ctx, AdminApi.PairingPut.class)));
    terminal(
        router,
        HttpMethod.DELETE,
        "/admin/terminals/:id/pairing",
        "pairing",
        ctx -> api.deletePairing(ctx.pathParam("id")));
    terminal(
        router,
        HttpMethod.PUT,
        "/admin/terminals/:id/slots/:slot",
        "card",
        ctx ->
            api.putCard(ctx.pathParam("id"), slot(ctx), card(body(ctx, AdminApi.SlotPut.class))));
    terminal(
        router,
        HttpMethod.DELETE,
        "/admin/terminals/:id/slots/:slot",
        "card",
        ctx -> api.removeCard(ctx.pathParam("id"), slot(ctx)));
    terminal(
        router,
        HttpMethod.PUT,
        "/admin/terminals/:id/slots/:slot/fault",
        "fault",
        ctx ->
            api.putFault(
                ctx.pathParam("id"), slot(ctx), fault(body(ctx, AdminApi.SlotFault.class))));
    terminal(
        router,
        HttpMethod.DELETE,
        "/admin/terminals/:id/slots/:slot/fault",
        "fault",
        ctx -> api.removeFault(ctx.pathParam("id"), slot(ctx)));
    terminal(
        router,
        HttpMethod.POST,
        "/admin/terminals/:id/pin-script",
        "pin-script",
        ctx ->
            api.postPinScript(
                ctx.pathParam("id"), pinScript(body(ctx, AdminApi.PinScriptEntry[].class))));
    terminal(
        router,
        HttpMethod.DELETE,
        "/admin/terminals/:id/pin-script",
        "pin-script",
        ctx -> api.deletePinScript(ctx.pathParam("id")));
    get(router, "/admin/infomodel", ctx -> api.infomodel());
    get(router, "/admin/tls", ctx -> api.tls());
    get(router, "/admin/vendor", ctx -> api.vendor());
    get(router, "/admin/log", ctx -> api.log(instant(ctx, "from"), instant(ctx, "to")));
    router
        .put("/admin/vendor")
        .blockingHandler(
            ctx -> {
              AdminApi.VendorState state = vendor(body(ctx, AdminApi.VendorPut.class));
              events.stateChanged("vendor");
              respond(ctx, 200, state);
            });
    get(router, "/admin/clients/:id/config.kon", ctx -> api.konConfig(ctx.pathParam("id")));
    get(router, "/admin/cards", ctx -> api.cards());
    get(router, "/admin/images", ctx -> api.images());
    get(router, "/admin/subscriptions", ctx -> api.subscriptions());
    get(router, "/admin/sessions", ctx -> api.sessions());
    get(router, "/admin/pki", ctx -> api.pki());
    get(router, "/admin/settings", ctx -> api.settings());
    router
        .put("/admin/settings")
        .blockingHandler(
            ctx -> {
              AdminApi.Settings settings = settings(body(ctx, AdminApi.SettingsPut.class));
              events.stateChanged("settings");
              respond(ctx, 200, settings);
            });
    get(router, "/admin/operating-state", ctx -> api.operatingState());
    router
        .put("/admin/operating-state")
        .blockingHandler(
            ctx -> {
              AdminApi.OperatingStateView state =
                  operatingState(body(ctx, AdminApi.OperatingStatePut.class));
              events.stateChanged("operating-state");
              respond(ctx, 200, state);
            });
    get(router, "/admin/deviations", ctx -> api.deviations());
    get(router, "/admin/vsdm/online-checks", ctx -> api.vsdmOnlineChecks());
    router
        .get("/admin/selftest/crypto/:check")
        .blockingHandler(
            ctx -> {
              CryptoSelfTest.Result result = api.selfTest(ctx.pathParam("check"));
              respond(ctx, result.ok() ? 200 : 500, result);
            });
    router
        .post("/admin/ct-discovery")
        .blockingHandler(
            ctx -> {
              List<Map<String, Object>> ctList =
                  api.discover(optionalBody(ctx, AdminApi.DiscoveryPost.class));
              ctList.forEach(
                  ct -> events.terminalChanged(String.valueOf(ct.get("CTID")), "ct-discovery"));
              respond(ctx, 200, ctList);
            });
    router.get(OpenApi.PATH).handler(openApi::send);
    router
        .post("/admin/reset")
        .blockingHandler(
            ctx -> {
              api.reset();
              events.stateChanged("reset");
              respond(ctx, 200, api.terminals());
            });
    kms.mountOn(router);
    router.route(CatsServer.MOUNT + "/*").subRouter(cats.router());
    gui.routes(router);
    // Outside /admin, the KMS paths and /cats: management of other vendors, 501
    router
        .route()
        .pathRegex("^(?!/admin(/|$)).*")
        .handler(ctx -> kms.notImplemented(ctx.request()));
    router
        .route()
        .handler(
            ctx ->
                error(
                    ctx,
                    404,
                    "unbekannter Pfad " + ctx.request().method() + " " + ctx.request().path()));
    router.route().failureHandler(AdminServer::failure);
    return router;
  }

  /**
   * Writing call on a CT: the response is the CT afterwards, plus a {@code terminal} event
   * (LIANA-150).
   */
  private void terminal(
      Router router,
      HttpMethod method,
      String path,
      String cause,
      Function<RoutingContext, AdminApi.Terminal> call) {
    router
        .route(method, path)
        .blockingHandler(
            ctx -> {
              AdminApi.Terminal terminal = call.apply(ctx);
              events.terminalChanged(terminal.id(), cause);
              respond(ctx, 200, terminal);
            });
  }

  private void get(Router router, String path, Function<RoutingContext, Object> result) {
    router.get(path).blockingHandler(ctx -> respond(ctx, 200, result.apply(ctx)));
  }

  private static int slot(RoutingContext ctx) {
    try {
      return Integer.parseInt(ctx.pathParam("slot"));
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException(
          ctx.pathParam("id") + ": Slot '" + ctx.pathParam("slot") + "' ist keine Zahl");
    }
  }

  /**
   * Without {@code image} → 400 instead of NullPointerException (500), found with GuiTest
   * (LIANA-148).
   */
  private static AdminApi.SlotPut card(AdminApi.SlotPut card) {
    if (card.image() == null || card.image().isBlank()) {
      throw new BadRequest(
          "image fehlt: Dateiname oder ICCSN aus liana.card-images, oder absoluter Pfad");
    }
    return card;
  }

  /** Invalid fault → 400, not 404 like unknown CTs and slots. */
  private static Fault fault(AdminApi.SlotFault fault) {
    try {
      return fault.fault();
    } catch (IllegalArgumentException e) {
      throw new BadRequest(e.getMessage());
    }
  }

  /**
   * Invalid entry → 400 for the whole script, as with kartos; an unknown slot is reported by the CT
   * (404).
   */
  private static List<FakeTerminal.ScriptedPinInput> pinScript(AdminApi.PinScriptEntry[] entries) {
    try {
      return Arrays.stream(entries).map(AdminApi.PinScriptEntry::entry).toList();
    } catch (IllegalArgumentException | NullPointerException e) {
      throw new BadRequest(
          e.getMessage() == null
              ? "PIN-Script: Array von {outcome, slotNo, pin} erwartet"
              : e.getMessage());
    }
  }

  /**
   * Time bound as ISO-8601 instant, e.g. {@code 2026-10-09T12:00:00Z}; if missing, there is no
   * bound.
   */
  private static Instant instant(RoutingContext ctx, String name) {
    String value = ctx.queryParams().get(name);
    if (value == null || value.isBlank()) {
      return null;
    }
    try {
      return Instant.parse(value);
    } catch (DateTimeParseException e) {
      throw new BadRequest(
          name + " '" + value + "' ist kein ISO-8601-Zeitpunkt (z. B. 2026-10-09T12:00:00Z)");
    }
  }

  /** Without fields or CARD_SESSION_TIMEOUT outside 10–180 s → 400. */
  private AdminApi.Settings settings(AdminApi.SettingsPut put) {
    try {
      return api.putSettings(put);
    } catch (IllegalArgumentException e) {
      throw new BadRequest(e.getMessage());
    }
  }

  /** Without fields → 400. */
  private AdminApi.OperatingStateView operatingState(AdminApi.OperatingStatePut put) {
    try {
      return api.putOperatingState(put);
    } catch (IllegalArgumentException e) {
      throw new BadRequest(e.getMessage());
    }
  }

  /** Unknown vendor → 400 with the allowed values. */
  private AdminApi.VendorState vendor(AdminApi.VendorPut put) {
    try {
      return api.putVendor(put);
    } catch (IllegalArgumentException e) {
      throw new BadRequest(e.getMessage());
    }
  }

  private <T> T body(RoutingContext ctx, Class<T> type) {
    try {
      T value = ctx.body().isEmpty() ? null : json.readValue(ctx.body().asString(), type);
      if (value == null) {
        throw new BadRequest("JSON-Body fehlt");
      }
      return value;
    } catch (JsonProcessingException e) {
      throw new BadRequest("ungültiges JSON: " + e.getOriginalMessage());
    }
  }

  /** Like {@link #body}, an empty body yields {@code null}. */
  private <T> T optionalBody(RoutingContext ctx, Class<T> type) {
    return ctx.body().isEmpty() ? null : body(ctx, type);
  }

  private void respond(RoutingContext ctx, int status, Object body) {
    try {
      ctx.response()
          .setStatusCode(status)
          .putHeader("Content-Type", "application/json")
          .end(json.writeValueAsString(body));
    } catch (JsonProcessingException e) {
      ctx.fail(e);
    }
  }

  private static void failure(RoutingContext ctx) {
    Throwable failure = ctx.failure();
    if (failure instanceof BadRequest) {
      error(ctx, 400, failure.getMessage());
    } else if (failure instanceof IllegalArgumentException) {
      error(ctx, 404, failure.getMessage());
    } else if (failure instanceof ConnectorException connector) {
      // TUC error (4007 unknown CT → 404, otherwise 409 with connector error code)
      int status = connector.error() == ConnectorError.INVALID_CT_ID ? 404 : 409;
      ctx.response()
          .setStatusCode(status)
          .putHeader("Content-Type", "application/json")
          .end(
              Json.encode(
                  Map.of("error", connector.getMessage(), "code", connector.error().code())));
    } else if (failure instanceof UnsupportedOperationException) {
      // decision-12: what is not implemented responds with 501 and the path
      LOG.warn(
          "Admin-API nicht umgesetzt: "
              + ctx.request().method()
              + " "
              + ctx.request().path()
              + ": "
              + failure.getMessage());
      error(
          ctx,
          501,
          ctx.request().method() + " " + ctx.request().path() + ": " + failure.getMessage());
    } else {
      LOG.error("Admin-API: " + ctx.request().method() + " " + ctx.request().path(), failure);
      error(ctx, 500, String.valueOf(failure));
    }
  }

  private static void error(RoutingContext ctx, int status, String message) {
    ctx.response()
        .setStatusCode(status)
        .putHeader("Content-Type", "application/json")
        .end(Json.encode(Map.of("error", message)));
  }

  /** Malformed request body → 400. */
  private static final class BadRequest extends RuntimeException {
    BadRequest(String message) {
      super(message);
    }
  }
}

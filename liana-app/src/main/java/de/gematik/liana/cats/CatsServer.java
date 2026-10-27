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
package de.gematik.liana.cats;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.liana.config.LianaConfig;
import io.quarkus.runtime.ShutdownEvent;
import io.quarkus.runtime.StartupEvent;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.Json;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.BodyHandler;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Singleton;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.OptionalInt;
import java.util.concurrent.ExecutionException;
import org.jboss.logging.Logger;

/**
 * CATS REST interface (LIANA-67) for tiger-cats-extensions: per entry in {@code
 * liana.cats.terminals} a router under {@value #MOUNT}{@code /<terminal>} on the management port
 * (decision-017, LIANA-147), requests like {@code CardAction} of the extension; its base URL is
 * {@code http://host:9090/cats/KT-01}. With {@code port} additionally its own HTTP listener as up
 * to 0.6, there without prefix (Konnektor-QES: {@code http://127.0.0.1:9998}). Success is 200
 * without content, errors come as JSON {@code {"error": …}}: 400 invalid request or invalid image,
 * 404 unknown slot or unknown CATS terminal, 409 insert without a loaded image, 501 for
 * unimplemented CATS endpoints and eHealth CTs (decision-12), so that the step turns red.
 */
@Singleton
public class CatsServer {

  /** Prefix on the management port; below it per CATS terminal its CT.CTID. */
  public static final String MOUNT = "/cats";

  private static final Logger LOG = Logger.getLogger(CatsServer.class);

  private final Vertx vertx;
  private final ObjectMapper json;
  private final CatsTerminals cats;
  private final List<LianaConfig.CatsTerminal> configured;
  private final Map<String, HttpServer> servers = new LinkedHashMap<>();

  CatsServer(Vertx vertx, ObjectMapper json, CatsTerminals cats, LianaConfig config) {
    this.vertx = vertx;
    this.json = json;
    this.cats = cats;
    this.configured = config.cats().terminals().orElse(List.of());
  }

  void start(@Observes StartupEvent event) throws InterruptedException, ExecutionException {
    for (LianaConfig.CatsTerminal terminal : configured) {
      if (terminal.port().isEmpty()) {
        LOG.infof(
            "CATS-Schnittstelle für %s unter %s/%s",
            terminal.terminal(), MOUNT, terminal.terminal());
        continue;
      }
      HttpServer server =
          vertx
              .createHttpServer()
              .requestHandler(router(terminal))
              .listen(terminal.port().get())
              .toCompletionStage()
              .toCompletableFuture()
              .get();
      servers.put(terminal.terminal(), server);
      LOG.infof(
          "CATS-Schnittstelle für %s unter %s/%s und auf Port %d",
          terminal.terminal(), MOUNT, terminal.terminal(), server.actualPort());
    }
  }

  void stop(@Observes ShutdownEvent event) {
    servers.values().forEach(HttpServer::close);
  }

  /**
   * Actual port of the own listener for {@code terminal}, even if the configured port is 0; empty
   * without {@code port} (then only under {@value #MOUNT}).
   */
  public OptionalInt compatibilityPort(String terminal) {
    HttpServer server = servers.get(terminal);
    return server == null ? OptionalInt.empty() : OptionalInt.of(server.actualPort());
  }

  /**
   * Router for {@value #MOUNT} on the management port: per CATS terminal its router as subrouter,
   * otherwise 404. The 501 for unimplemented endpoints applies only within a terminal.
   */
  public Router router() {
    Router router = Router.router(vertx);
    for (LianaConfig.CatsTerminal terminal : configured) {
      router.route("/" + terminal.terminal() + "/*").subRouter(router(terminal));
    }
    router
        .route()
        .handler(
            ctx ->
                error(
                    ctx,
                    404,
                    "kein CATS-Terminal (liana.cats.terminals: "
                        + configured.stream().map(LianaConfig.CatsTerminal::terminal).toList()
                        + ")"));
    return router;
  }

  private Router router(LianaConfig.CatsTerminal configuration) {
    String terminal = configuration.terminal();
    Router router = Router.router(vertx);
    router.route().handler(BodyHandler.create());
    router
        .put("/config/card/slot/:slot/cardImage")
        .blockingHandler(
            ctx ->
                ok(
                    ctx,
                    () ->
                        cats.loadImage(
                            terminal,
                            slot(ctx),
                            ctx.body().buffer() == null ? null : ctx.body().buffer().getBytes())));
    router
        .put("/config/card/slot/:slot")
        .blockingHandler(
            ctx ->
                ok(
                    ctx,
                    () ->
                        cats.loadConfiguration(
                            terminal, slot(ctx), text(body(ctx), "cardConfigPath"))));
    router
        .post("/config/card/insert")
        .blockingHandler(
            ctx ->
                ok(
                    ctx,
                    () -> {
                      JsonNode body = body(ctx);
                      if (!body.path("slotNumber").isInt() || !body.path("inserted").isBoolean()) {
                        throw new IllegalArgumentException(
                            "erwartet {\"slotNumber\": n, \"inserted\": true|false}");
                      }
                      cats.insert(
                          terminal,
                          body.get("slotNumber").asInt(),
                          body.get("inserted").asBoolean(),
                          configuration.insertDelay());
                    }));
    router
        .post("/config/card/slots/reset")
        .blockingHandler(ctx -> ok(ctx, () -> cats.resetSlots(terminal)));
    router
        .get("/cardsim/slot/:slot/delay/:ms")
        .blockingHandler(ctx -> ok(ctx, () -> cats.delay(terminal, slot(ctx), number(ctx, "ms"))));
    router
        .post("/cardsim/slot/:slot/manipulateSignatureResponse")
        .blockingHandler(
            ctx ->
                ok(
                    ctx,
                    () ->
                        cats.manipulateSignatureResponse(
                            terminal, slot(ctx), text(body(ctx), "responseReplacement"))));
    // decision-12: all other CATS endpoints (PIN, /action, /sicct, among others
    // userDefinedStatusWord, LIANA-94)
    router
        .route()
        .handler(
            ctx -> {
              throw new UnsupportedOperationException("CATS-Endpunkt in LIANA nicht umgesetzt");
            });
    router.route().failureHandler(CatsServer::failure);
    return router;
  }

  private void ok(RoutingContext ctx, Runnable action) {
    action.run();
    ctx.response().setStatusCode(200).end();
  }

  private static int slot(RoutingContext ctx) {
    return (int) number(ctx, "slot");
  }

  private static long number(RoutingContext ctx, String name) {
    try {
      return Long.parseLong(ctx.pathParam(name));
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException(name + " '" + ctx.pathParam(name) + "' ist keine Zahl");
    }
  }

  private JsonNode body(RoutingContext ctx) {
    try {
      JsonNode body = ctx.body().isEmpty() ? null : json.readTree(ctx.body().asString());
      if (body == null || !body.isObject()) {
        throw new IllegalArgumentException("JSON-Objekt im Body fehlt");
      }
      return body;
    } catch (IOException e) {
      throw new IllegalArgumentException("ungültiges JSON: " + e.getMessage());
    }
  }

  private static String text(JsonNode body, String field) {
    JsonNode value = body.get(field);
    return value == null || !value.isTextual() ? null : value.asText();
  }

  private static void failure(RoutingContext ctx) {
    Throwable failure = ctx.failure();
    String request = ctx.request().method() + " " + ctx.request().path();
    int status;
    if (failure instanceof CatsTerminals.NoSuchSlot) {
      status = 404;
    } else if (failure instanceof IllegalArgumentException) {
      status = 400;
    } else if (failure instanceof IllegalStateException) {
      status = 409;
    } else if (failure instanceof UnsupportedOperationException) {
      status = 501;
    } else {
      status = 500;
    }
    if (status >= 500) {
      LOG.warn("CATS " + request + ": " + failure, status == 500 ? failure : null);
    } else {
      LOG.info("CATS " + request + " → " + status + ": " + failure.getMessage());
    }
    error(ctx, status, failure.getMessage());
  }

  private static void error(RoutingContext ctx, int status, String message) {
    ctx.response()
        .setStatusCode(status)
        .putHeader("Content-Type", "application/json")
        .end(
            Json.encode(
                Map.of(
                    "error",
                    ctx.request().method() + " " + ctx.request().path() + ": " + message)));
  }
}

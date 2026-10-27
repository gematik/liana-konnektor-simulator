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
package de.gematik.liana.robot;

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
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import org.jboss.logging.Logger;

/**
 * Robot interface (LIANA-106) for tiger-ehealth-kt-e2e: {@code POST /api/robot/robotCommand} with
 * {@code {"command": …, "input": …}} as in {@code AutomationRobotGlueCode.performStartAction}.
 * Success is 200 with {@code {}}, errors come as JSON {@code {"error": …}}: 400 invalid request or
 * unknown compartment or terminal, 409 insert without a selected card, 501 unimplemented commands
 * (decision-12). The suite does not evaluate the status; an error shows up in the LIANA log, the
 * step fails because of the missing event.
 */
@Singleton
public class RobotServer {

  private static final Logger LOG = Logger.getLogger(RobotServer.class);

  private final Vertx vertx;
  private final ObjectMapper json;
  private final RobotTerminals robot;
  private final Optional<Integer> port;
  private HttpServer server;

  RobotServer(Vertx vertx, ObjectMapper json, RobotTerminals robot, LianaConfig config) {
    this.vertx = vertx;
    this.json = json;
    this.robot = robot;
    this.port = config.robot().port();
  }

  void start(@Observes StartupEvent event) throws InterruptedException, ExecutionException {
    if (port.isEmpty()) {
      return;
    }
    robot.awaitPinInput();
    server =
        vertx
            .createHttpServer()
            .requestHandler(router())
            .listen(port.get())
            .toCompletionStage()
            .toCompletableFuture()
            .get();
    LOG.infof("Robot-Schnittstelle auf Port %d", server.actualPort());
  }

  void stop(@Observes ShutdownEvent event) {
    if (server != null) {
      server.close();
    }
  }

  /** Actual port, even if the configured port is 0. */
  public int port() {
    if (server == null) {
      throw new IllegalStateException("Robot-Schnittstelle aus (liana.robot.port fehlt)");
    }
    return server.actualPort();
  }

  private Router router() {
    Router router = Router.router(vertx);
    router.route().handler(BodyHandler.create());
    router
        .post("/api/robot/robotCommand")
        .blockingHandler(
            ctx -> {
              JsonNode body = body(ctx);
              robot.command(text(body, "command"), text(body, "input"));
              ctx.response()
                  .setStatusCode(200)
                  .putHeader("Content-Type", "application/json")
                  .end("{}");
            });
    router
        .route()
        .handler(
            ctx -> {
              throw new UnsupportedOperationException("Robot-Aktion in LIANA nicht umgesetzt");
            });
    router.route().failureHandler(RobotServer::failure);
    return router;
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
    if (failure instanceof IllegalArgumentException) {
      status = 400;
    } else if (failure instanceof IllegalStateException) {
      status = 409;
    } else if (failure instanceof UnsupportedOperationException) {
      status = 501;
    } else {
      status = 500;
    }
    // The suite does not check the status: every error belongs in the log so that a red step stays
    // explainable
    LOG.warn(
        "Robot " + request + " → " + status + ": " + failure.getMessage(),
        status == 500 ? failure : null);
    ctx.response()
        .setStatusCode(status)
        .putHeader("Content-Type", "application/json")
        .end(Json.encode(Map.of("error", request + ": " + failure.getMessage())));
  }
}

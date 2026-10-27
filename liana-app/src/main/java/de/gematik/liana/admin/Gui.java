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

import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.Json;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Control Center (LIANA-148, decision-018): static files under {@code gui/} on the class path,
 * {@code /} serves {@code index.html}, {@code /gui/<file>} the rest. The list is fixed so that the
 * native image works without directory listing ({@code quarkus.native.resources.includes}); {@code
 * GuiTest} checks that every file under {@code gui/} is in it. The GUI is a pure client of the
 * admin API; the Content-Security-Policy only allows requests to LIANA itself.
 */
final class Gui {

  /** Prefix of the files; {@code /} is {@code index.html}. */
  static final String MOUNT = "/gui";

  /**
   * Served files relative to {@code gui/}; {@code vendor/SOURCE.md} and the license texts {@code
   * vendor/LICENSE-*.txt} are documentation, not part of the GUI.
   */
  static final List<String> FILES =
      List.of(
          "index.html",
          "app.css",
          "app.js",
          "api.js",
          "ui.js",
          "pages/overview.js",
          "pages/terminals.js",
          "pages/log.js",
          "pages/subscriptions.js",
          "pages/tls.js",
          "pages/profile.js",
          "pages/infomodel.js",
          "vendor/preact-htm.js");

  static final String CSP =
      "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
          + "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

  private record File(Buffer content, String contentType) {}

  private final Map<String, File> served = new LinkedHashMap<>();

  Gui() {
    for (String name : FILES) {
      served.put(name, new File(Buffer.buffer(read("gui/" + name)), contentType(name)));
    }
  }

  /** {@code GET /} and {@code GET /gui/*}; unknown files under {@code /gui} → 404. */
  void routes(Router router) {
    router.get("/").handler(ctx -> send(ctx, "index.html"));
    router
        .get(MOUNT + "/*")
        .handler(
            ctx -> {
              String name = ctx.request().path().substring(MOUNT.length() + 1);
              if (served.containsKey(name)) {
                send(ctx, name);
              } else {
                ctx.response()
                    .setStatusCode(404)
                    .putHeader("Content-Type", "application/json")
                    .end(
                        Json.encode(
                            Map.of(
                                "error",
                                "keine Datei des Control Centers: " + ctx.request().path())));
              }
            });
  }

  private void send(RoutingContext ctx, String name) {
    File file = served.get(name);
    ctx.response()
        .putHeader("Content-Type", file.contentType())
        .putHeader("Cache-Control", "no-cache")
        .putHeader("X-Content-Type-Options", "nosniff")
        .putHeader("Content-Security-Policy", CSP)
        .putHeader("Referrer-Policy", "no-referrer")
        .end(file.content());
  }

  static String contentType(String name) {
    if (name.endsWith(".html")) {
      return "text/html; charset=utf-8";
    } else if (name.endsWith(".css")) {
      return "text/css; charset=utf-8";
    } else if (name.endsWith(".js")) {
      return "text/javascript; charset=utf-8";
    }
    throw new IllegalArgumentException("kein Content-Type für " + name);
  }

  private static byte[] read(String resource) {
    try (InputStream in = Gui.class.getClassLoader().getResourceAsStream(resource)) {
      if (in == null) {
        throw new IllegalStateException("GUI-Datei fehlt auf dem Klassenpfad: " + resource);
      }
      return in.readAllBytes();
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }
}

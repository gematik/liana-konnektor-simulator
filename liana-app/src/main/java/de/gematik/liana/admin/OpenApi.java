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
import io.vertx.ext.web.RoutingContext;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;

/**
 * Description of the admin API as OpenAPI 3.0 (LIANA-149): hand-written in {@code
 * admin/openapi.yaml} on the class path, without smallrye-openapi, because the admin API is not
 * JAX-RS. {@code OpenApiTest} keeps it in sync with the routes of {@link AdminServer}.
 */
final class OpenApi {

  static final String PATH = "/admin/openapi.yaml";
  static final String RESOURCE = "admin/openapi.yaml";

  private final Buffer content;

  /** {@code version} replaces {@code ${version}} in {@code info.version}. */
  OpenApi(String version) {
    try (InputStream in = OpenApi.class.getClassLoader().getResourceAsStream(RESOURCE)) {
      if (in == null) {
        throw new IllegalStateException(
            "OpenAPI-Beschreibung fehlt auf dem Klassenpfad: " + RESOURCE);
      }
      content =
          Buffer.buffer(
              new String(in.readAllBytes(), StandardCharsets.UTF_8).replace("${version}", version));
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  void send(RoutingContext ctx) {
    ctx.response()
        .putHeader("Content-Type", "application/yaml; charset=utf-8")
        .putHeader("Cache-Control", "no-cache")
        .end(content);
  }
}

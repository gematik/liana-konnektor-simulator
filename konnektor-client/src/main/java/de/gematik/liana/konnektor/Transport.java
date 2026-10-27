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
package de.gematik.liana.konnektor;

import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.Map;

/**
 * Path to the Konnektor (LIANA-133). The default is {@link HttpTransport} (JDK {@code HttpClient},
 * BCJSSE); custom implementations e.g. for replay tests (LIANA-139).
 */
public interface Transport extends AutoCloseable {

  /**
   * An HTTP request.
   *
   * @param method {@code GET} or {@code POST}
   * @param uri target
   * @param headers additional headers, without authentication (the transport sets it)
   * @param body body, empty for {@code GET}
   * @param timeout response timeout
   */
  record Request(
      String method, URI uri, Map<String, String> headers, byte[] body, Duration timeout) {
    public Request {
      headers = Map.copyOf(headers);
      body = body.clone();
    }

    @Override
    public byte[] body() {
      return body.clone();
    }
  }

  /** Response with status, {@code Content-Type} (or {@code null}) and body. */
  record Response(int status, String contentType, byte[] body) {
    public Response {
      body = body.clone();
    }

    @Override
    public byte[] body() {
      return body.clone();
    }
  }

  Response send(Request request) throws IOException;

  @Override
  default void close() {}
}

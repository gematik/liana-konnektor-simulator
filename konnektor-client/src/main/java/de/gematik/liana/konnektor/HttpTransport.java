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
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;

/**
 * Default transport (LIANA-133): JDK {@code HttpClient} with HTTP/1.1, optionally via an HTTP proxy
 * (such as a Tiger proxy that records the traffic), TLS via an {@code SSLContext} from BCJSSE
 * ({@link ClientTls}) so that TLS 1.2 with brainpoolP256r1 works. Basic authentication as an {@code
 * Authorization} header per request. Messages never reveal credentials.
 */
public final class HttpTransport implements Transport {

  private final HttpClient client;
  private final String authorization;

  private HttpTransport(HttpClient client, String authorization) {
    this.client = client;
    this.authorization = authorization;
  }

  /**
   * @param trust verification of the Konnektor certificate
   * @param credentials Basic as header, PKCS#12 as TLS client certificate
   * @param proxy HTTP proxy or {@code null}
   * @param connectTimeout timeout for establishing the connection
   */
  public static HttpTransport create(
      Trust trust, Credentials credentials, InetSocketAddress proxy, Duration connectTimeout)
      throws IOException {
    if (credentials instanceof Credentials.SystemStore) {
      throw new UnsupportedOperationException(
          "credentials.type system: Credential-Store des Betriebssystems "
              + "wird noch nicht unterstützt");
    }
    HttpClient.Builder builder =
        HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .connectTimeout(connectTimeout)
            .followRedirects(HttpClient.Redirect.NEVER)
            .sslContext(ClientTls.context(trust, credentials))
            .sslParameters(ClientTls.parameters());
    if (proxy != null) {
      builder.proxy(ProxySelector.of(proxy));
    }
    String authorization =
        credentials instanceof Credentials.Basic basic
            ? "Basic "
                + Base64.getEncoder()
                    .encodeToString(
                        (basic.username() + ":" + basic.password())
                            .getBytes(StandardCharsets.UTF_8))
            : null;
    return new HttpTransport(builder.build(), authorization);
  }

  @Override
  public Response send(Request request) throws IOException {
    HttpRequest.Builder http = HttpRequest.newBuilder(request.uri()).timeout(request.timeout());
    request.headers().forEach(http::header);
    if (authorization != null) {
      http.header("Authorization", authorization);
    }
    byte[] body = request.body();
    http.method(
        request.method(),
        body.length == 0 && "GET".equals(request.method())
            ? HttpRequest.BodyPublishers.noBody()
            : HttpRequest.BodyPublishers.ofByteArray(body));
    try {
      HttpResponse<byte[]> response =
          client.send(http.build(), HttpResponse.BodyHandlers.ofByteArray());
      return new Response(
          response.statusCode(),
          response.headers().firstValue("Content-Type").orElse(null),
          response.body());
    } catch (HttpTimeoutException e) {
      throw new IOException(
          request.method()
              + " "
              + request.uri()
              + ": keine Antwort nach "
              + request.timeout().toSeconds()
              + " s",
          e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IOException(request.method() + " " + request.uri() + ": unterbrochen", e);
    }
  }

  @Override
  public void close() {
    // HttpClient is AutoCloseable from Java 21 on; under 17 the GC cleans up the connections
    if (client instanceof AutoCloseable closeable) {
      try {
        closeable.close();
      } catch (Exception e) {
        // nothing to do
      }
    }
  }
}

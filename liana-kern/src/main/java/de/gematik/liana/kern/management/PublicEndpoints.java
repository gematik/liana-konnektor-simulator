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
package de.gematik.liana.kern.management;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.function.UnaryOperator;

/**
 * Where clients reach the connector interface, for {@code connector.sds} and the {@code .kon}
 * export (LIANA-217). TIP1-A_4530 leaves the URLs to the Konnektor; a real Konnektor reports its
 * configured address, deriving it from the request is a convenience of the simulator so that port
 * mappings and proxies work without configuration.
 *
 * <p>Precedence: the configured URL, then {@code Forwarded} (RFC 7239) or {@code X-Forwarded-Host},
 * {@code -Proto}, {@code -Port} if switched on, then the {@code Host} header. The port of the other
 * scheme is not in the request and comes from the public ports.
 */
public final class PublicEndpoints {

  /** Base URLs without a trailing slash: {@code Endpoint} and {@code EndpointTLS}. */
  public record Bases(String http, String tls) {}

  /** {@code port} is null if the request names none (default port of the scheme). */
  private record Origin(String scheme, String hostname, String port) {}

  private final Optional<String> httpUrl;
  private final Optional<String> tlsUrl;
  private final boolean forwarded;
  private final int publicHttpPort;
  private final int publicTlsPort;

  public PublicEndpoints(
      Optional<String> httpUrl,
      Optional<String> tlsUrl,
      boolean forwarded,
      int publicHttpPort,
      int publicTlsPort) {
    this.httpUrl = httpUrl.map(PublicEndpoints::withoutTrailingSlash);
    this.tlsUrl = tlsUrl.map(PublicEndpoints::withoutTrailingSlash);
    this.forwarded = forwarded;
    this.publicHttpPort = publicHttpPort;
    this.publicTlsPort = publicTlsPort;
  }

  /** For a request to the connector interface with this scheme and these headers. */
  public Bases forRequest(String scheme, UnaryOperator<String> headers) {
    Origin origin = origin(scheme, headers);
    String http =
        "http".equals(origin.scheme())
            ? base(origin)
            : "http://" + origin.hostname() + ":" + publicHttpPort;
    String tls =
        "https".equals(origin.scheme())
            ? base(origin)
            : "https://" + origin.hostname() + ":" + publicTlsPort;
    return new Bases(httpUrl.orElse(http), tlsUrl.orElse(tls));
  }

  /**
   * For a request to another port (management port of the {@code .kon} export): only the host comes
   * from the request, the ports are the public ports of the connector interface.
   */
  public Bases forOtherPort(UnaryOperator<String> headers) {
    String hostname = origin("http", headers).hostname();
    return new Bases(
        httpUrl.orElse("http://" + hostname + ":" + publicHttpPort),
        tlsUrl.orElse("https://" + hostname + ":" + publicTlsPort));
  }

  private Origin origin(String scheme, UnaryOperator<String> headers) {
    Map<String, String> rfc7239 = forwarded ? firstElement(headers.apply("Forwarded")) : Map.of();
    String host = rfc7239.get("host");
    String proto = rfc7239.get("proto");
    String port = null;
    if (forwarded && host == null && proto == null) {
      host = first(headers.apply("X-Forwarded-Host"));
      proto = first(headers.apply("X-Forwarded-Proto"));
      port = first(headers.apply("X-Forwarded-Port"));
    }
    if (host == null) {
      host = headers.apply("Host");
    }
    if (host == null || host.isBlank()) {
      host = "localhost";
    }
    host = host.strip();
    int colon = host.lastIndexOf(':');
    boolean withPort = colon > host.lastIndexOf(']');
    return new Origin(
        proto == null ? scheme : proto.toLowerCase(Locale.ROOT),
        withPort ? host.substring(0, colon) : host,
        withPort ? host.substring(colon + 1) : port);
  }

  private static String base(Origin origin) {
    return origin.scheme()
        + "://"
        + origin.hostname()
        + (origin.port() == null ? "" : ":" + origin.port());
  }

  /** Parameters of the first element, the one closest to the client (RFC 7239 section 4). */
  private static Map<String, String> firstElement(String header) {
    Map<String, String> parameters = new HashMap<>();
    String element = first(header);
    if (element == null) {
      return parameters;
    }
    for (String pair : element.split(";")) {
      int equals = pair.indexOf('=');
      if (equals > 0) {
        parameters.put(
            pair.substring(0, equals).strip().toLowerCase(Locale.ROOT),
            pair.substring(equals + 1).strip().replace("\"", ""));
      }
    }
    return parameters;
  }

  private static String first(String header) {
    if (header == null) {
      return null;
    }
    String value = header.split(",", 2)[0].strip();
    return value.isEmpty() ? null : value;
  }

  private static String withoutTrailingSlash(String url) {
    String result = url;
    while (result.endsWith("/")) {
      result = result.substring(0, result.length() - 1);
    }
    return result;
  }
}

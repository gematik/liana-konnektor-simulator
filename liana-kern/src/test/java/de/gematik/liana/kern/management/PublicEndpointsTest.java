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

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/** LIANA-217: order of precedence of the public endpoints. */
class PublicEndpointsTest {

  private static PublicEndpoints auto(boolean forwarded) {
    return new PublicEndpoints(Optional.empty(), Optional.empty(), forwarded, 8080, 28443);
  }

  @Test
  @DisplayName("LIANA-217 Host über HTTP: Endpoint aus dem Host, EndpointTLS mit öffentlichem Port")
  void hostOverHttp() {
    assertEquals(
        new PublicEndpoints.Bases("http://example.test:28080", "https://example.test:28443"),
        auto(true).forRequest("http", Map.of("Host", "example.test:28080")::get));
  }

  @Test
  @DisplayName(
      "LIANA-217 Host über HTTPS: EndpointTLS aus dem Host, Endpoint mit öffentlichem Port")
  void hostOverHttps() {
    assertEquals(
        new PublicEndpoints.Bases("http://example.test:8080", "https://example.test:9443"),
        auto(true).forRequest("https", Map.of("Host", "example.test:9443")::get));
  }

  @ParameterizedTest
  @CsvSource(
      delimiter = '|',
      value = {
        "[::1]:28080 | http://[::1]:28080 | https://[::1]:28443",
        "[::1]       | http://[::1]       | https://[::1]:28443",
        "example.test | http://example.test | https://example.test:28443"
      })
  @DisplayName("LIANA-217 Host ohne Port oder als IPv6-Adresse")
  void hostForms(String host, String http, String tls) {
    assertEquals(
        new PublicEndpoints.Bases(http, tls),
        auto(true).forRequest("http", Map.of("Host", host)::get));
  }

  @Test
  @DisplayName("LIANA-217 ohne Host: localhost")
  void noHost() {
    assertEquals(
        new PublicEndpoints.Bases("http://localhost:8080", "https://localhost:28443"),
        new PublicEndpoints(Optional.empty(), Optional.empty(), true, 8080, 28443)
            .forOtherPort(Map.<String, String>of()::get));
  }

  @Test
  @DisplayName("LIANA-217 RFC 7239 Forwarded: erstes Element, geht X-Forwarded-* und Host vor")
  void forwarded() {
    Map<String, String> headers =
        Map.of(
            "Host", "liana:8080",
            "X-Forwarded-Host", "other.test",
            "Forwarded", "for=1.2.3.4;Proto=https;host=\"public.test:9443\", host=inner.test");
    assertEquals(
        new PublicEndpoints.Bases("http://public.test:8080", "https://public.test:9443"),
        auto(true).forRequest("http", headers::get));
  }

  @Test
  @DisplayName("LIANA-217 X-Forwarded-Host, -Proto, -Port gehen dem Host vor")
  void xForwarded() {
    Map<String, String> headers =
        Map.of(
            "Host", "liana:8080",
            "X-Forwarded-Host", "public.test, inner.test",
            "X-Forwarded-Proto", "https",
            "X-Forwarded-Port", "9443");
    assertEquals(
        new PublicEndpoints.Bases("http://public.test:8080", "https://public.test:9443"),
        auto(true).forRequest("http", headers::get));
  }

  @Test
  @DisplayName("LIANA-217 Forwarded-Auswertung ausgeschaltet: nur der Host zählt")
  void forwardedOff() {
    Map<String, String> headers =
        Map.of(
            "Host", "liana:8080",
            "Forwarded", "host=public.test;proto=https",
            "X-Forwarded-Host", "other.test");
    assertEquals(
        new PublicEndpoints.Bases("http://liana:8080", "https://liana:28443"),
        auto(false).forRequest("http", headers::get));
  }

  @Test
  @DisplayName(
      "LIANA-217 konfigurierte URLs gehen vor, je Schema einzeln, ohne Schrägstrich am Ende")
  void configuredWins() {
    Map<String, String> headers =
        Map.of("Host", "example.test:28080", "Forwarded", "host=public.test");
    assertEquals(
        new PublicEndpoints.Bases("http://liana:8080", "https://liana:8443"),
        new PublicEndpoints(
                Optional.of("http://liana:8080/"),
                Optional.of("https://liana:8443/"),
                true,
                8080,
                8443)
            .forRequest("http", headers::get));
    assertEquals(
        new PublicEndpoints.Bases("http://liana:8080", "https://public.test:8443"),
        new PublicEndpoints(Optional.of("http://liana:8080"), Optional.empty(), true, 8080, 8443)
            .forRequest("http", headers::get));
  }

  @Test
  @DisplayName("LIANA-217 anderer Port (.kon-Export): Host aus dem Request, Port nie von dort")
  void otherPort() {
    assertEquals(
        new PublicEndpoints.Bases("http://example.test:8080", "https://example.test:28443"),
        auto(true).forOtherPort(Map.of("Host", "example.test:9090")::get));
    assertEquals(
        new PublicEndpoints.Bases("http://public.test:8080", "https://public.test:28443"),
        auto(true)
            .forOtherPort(
                Map.of("Host", "liana:9090", "X-Forwarded-Host", "public.test:443")::get));
  }
}

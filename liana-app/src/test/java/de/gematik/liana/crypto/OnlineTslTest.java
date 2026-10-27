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
package de.gematik.liana.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * LIANA-180: {@code liana.pki.tsl-online} against a local HTTP server instead of the RU. The
 * baked-in TSL is the checked-in one (SequenceNumber 10713); online, the server delivers the same
 * file with SequenceNumber 10714, an older one (10712), one without CAs, and 500.
 */
class OnlineTslTest {

  static final Path BAKED = Path.of("support/pki/tsl/ECC-RSA_TSL-ref.xml");
  static final Duration TIMEOUT = Duration.ofSeconds(5);

  private HttpServer server;

  @BeforeAll
  static void bc() {
    if (Security.getProvider(CryptoProviders.BC) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  @BeforeEach
  void start() throws IOException {
    String tsl = Files.readString(BAKED, StandardCharsets.UTF_8);
    Map<String, byte[]> files =
        Map.of(
            "/newer.xml",
                tsl.replace("<TSLSequenceNumber>10713<", "<TSLSequenceNumber>10714<")
                    .getBytes(StandardCharsets.UTF_8),
            "/older.xml",
                tsl.replace("<TSLSequenceNumber>10713<", "<TSLSequenceNumber>10712<")
                    .getBytes(StandardCharsets.UTF_8),
            "/empty.xml", "<TrustServiceStatusList/>".getBytes(StandardCharsets.UTF_8));
    server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
    server.createContext(
        "/",
        exchange -> {
          byte[] body = files.get(exchange.getRequestURI().getPath());
          exchange.sendResponseHeaders(body == null ? 500 : 200, body == null ? -1 : body.length);
          if (body != null) {
            exchange.getResponseBody().write(body);
          }
          exchange.close();
        });
    server.start();
  }

  @AfterEach
  void stop() {
    server.stop(0);
  }

  private URI url(String path) {
    return URI.create("http://127.0.0.1:" + server.getAddress().getPort() + path);
  }

  private static TrustSpace baked() {
    return TrustSpace.load(BAKED, List.of());
  }

  @Test
  @DisplayName("mode off: kein Abruf, die eingebackene TSL bleibt")
  void off() throws Exception {
    TrustSpace trustSpace = baked();
    assertEquals(
        Optional.empty(),
        OnlineTsl.start(trustSpace, OnlineTsl.Mode.OFF, url("/newer.xml"), TIMEOUT).get());
    assertEquals(BAKED.toString(), trustSpace.tsl().source());
  }

  @Test
  @DisplayName(
      "mode background: nach dem Start tauscht LIANA die CAs gegen die der neueren online-TSL")
  void backgroundTauscht() throws Exception {
    TrustSpace trustSpace = baked();
    TrustSpace.TslInfo online =
        OnlineTsl.start(trustSpace, OnlineTsl.Mode.BACKGROUND, url("/newer.xml"), TIMEOUT)
            .get(10, TimeUnit.SECONDS)
            .orElseThrow();
    assertEquals("10714", online.sequenceNumber());
    assertEquals(online, trustSpace.tsl());
    assertEquals(url("/newer.xml").toString(), trustSpace.tsl().source());
  }

  @Test
  @DisplayName(
      "mode background: HTTP 500, eine TSL ohne CAs oder eine ältere TSL lassen die eingebackene stehen")
  void backgroundBehaeltBeiFehler() throws Exception {
    for (String path : List.of("/missing.xml", "/empty.xml", "/older.xml")) {
      TrustSpace trustSpace = baked();
      assertEquals(
          Optional.empty(),
          OnlineTsl.start(trustSpace, OnlineTsl.Mode.BACKGROUND, url(path), TIMEOUT)
              .get(10, TimeUnit.SECONDS),
          path);
      assertEquals(BAKED.toString(), trustSpace.tsl().source(), path);
      assertEquals("10713", trustSpace.tsl().sequenceNumber(), path);
    }
  }

  @Test
  @DisplayName(
      "mode enforce: synchron beim Start; ohne lesbare TSL IllegalStateException, der Start bricht ab")
  void enforce() {
    TrustSpace trustSpace = baked();
    assertEquals(
        "10714",
        OnlineTsl.start(trustSpace, OnlineTsl.Mode.ENFORCE, url("/newer.xml"), TIMEOUT)
            .join()
            .orElseThrow()
            .sequenceNumber());
    IllegalStateException error =
        assertThrows(
            IllegalStateException.class,
            () -> OnlineTsl.start(baked(), OnlineTsl.Mode.ENFORCE, url("/missing.xml"), TIMEOUT));
    assertTrue(error.getMessage().contains("HTTP 500"), error.getMessage());
  }
}

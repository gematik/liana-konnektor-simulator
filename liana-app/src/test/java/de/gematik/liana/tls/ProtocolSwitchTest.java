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
package de.gematik.liana.tls;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.TlsProbe;
import de.gematik.liana.crypto.CryptoProviders;
import de.gematik.liana.crypto.KonnektorTls;
import de.gematik.liana.crypto.TlsIdentity;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.net.SocketAddress;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.Security;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Switch for HTTP and HTTPS on one port (decision-017, LIANA-146): the handler answers with the
 * protocol and the client address that the internal server sees. Without Quarkus; TLS as on the
 * management port ({@link KonnektorTls}, BCJSSE) with the test identity {@code
 * support/pki/server/ak-aut-bp256.p12}.
 */
class ProtocolSwitchTest {

  private static Vertx vertx;
  private static ProtocolSwitch protocolSwitch;

  @BeforeAll
  static void start() throws Exception {
    if (Security.getProvider(CryptoProviders.BC) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
    vertx = Vertx.vertx();
    // TLS as on the management port: KonnektorTls with an identity from support/pki/server
    TlsIdentity identity =
        TlsIdentity.load(Path.of("support/pki/server/ak-aut-bp256.p12"), TlsProbe.PASSWORD);
    HttpServerOptions tls = KonnektorTls.serverOptions(identity, null);
    protocolSwitch =
        ProtocolSwitch.listen(
            vertx,
            0,
            request ->
                request
                    .response()
                    .end(
                        (request.isSSL() ? "https " : "http ")
                            + request.remoteAddress().hostAddress()
                            + ":"
                            + request.remoteAddress().port()),
            tls);
  }

  @AfterAll
  static void stop() {
    protocolSwitch.close();
    vertx.close();
  }

  @Test
  @DisplayName(
      "Erstes Byte kein 0x16 → interner HTTP-Server; er sieht Adresse und Port des Clients (PROXY v1)")
  void http() throws IOException {
    try (Socket socket = new Socket(InetAddress.getLoopbackAddress(), protocolSwitch.port())) {
      assertEquals("http 127.0.0.1:" + socket.getLocalPort(), get(socket));
    }
  }

  @Test
  @DisplayName(
      "TLS-Handshake (0x16) → interner HTTPS-Server; er sieht Adresse und Port des Clients (PROXY v1)")
  void https() throws Exception {
    SSLContext context = SSLContext.getInstance("TLSv1.2", CryptoProviders.tls());
    context.init(null, new TrustManager[] {new TrustAll()}, null);
    try (Socket socket =
        context
            .getSocketFactory()
            .createSocket(InetAddress.getLoopbackAddress(), protocolSwitch.port())) {
      assertEquals("https 127.0.0.1:" + socket.getLocalPort(), get(socket));
    }
  }

  @Test
  @DisplayName("Mehrere Anfragen auf einer Verbindung (keep-alive) laufen über dieselbe Kopplung")
  void keepAlive() throws IOException {
    try (Socket socket = new Socket(InetAddress.getLoopbackAddress(), protocolSwitch.port())) {
      OutputStream out = socket.getOutputStream();
      out.write(
          "GET / HTTP/1.1\r\nHost: liana\r\n\r\nGET / HTTP/1.1\r\nHost: liana\r\nConnection: close\r\n\r\n"
              .getBytes(StandardCharsets.US_ASCII));
      out.flush();
      String responses =
          new String(socket.getInputStream().readAllBytes(), StandardCharsets.US_ASCII);
      assertEquals(2, responses.split("HTTP/1.1 200 OK", -1).length - 1, responses);
    }
  }

  @Test
  @DisplayName(
      "PROXY-Kopfzeile: TCP4, TCP6 und UNKNOWN ohne Adresse (HAProxy PROXY protocol v1, 2.1)")
  void proxyHeader() {
    assertEquals(
        "PROXY TCP4 10.0.0.1 127.0.0.1 51450 9090\r\n",
        ProtocolSwitch.proxyHeader(
                SocketAddress.inetSocketAddress(51450, "10.0.0.1"),
                SocketAddress.inetSocketAddress(9090, "127.0.0.1"))
            .toString());
    assertTrue(
        ProtocolSwitch.proxyHeader(
                SocketAddress.inetSocketAddress(51450, "::1"),
                SocketAddress.inetSocketAddress(9090, "::1"))
            .toString()
            .startsWith("PROXY TCP6 "));
    assertEquals("PROXY UNKNOWN\r\n", ProtocolSwitch.proxyHeader(null, null).toString());
  }

  /** A request with {@code Connection: close}; the body of the response. */
  private static String get(Socket socket) throws IOException {
    OutputStream out = socket.getOutputStream();
    out.write(
        "GET / HTTP/1.1\r\nHost: liana\r\nConnection: close\r\n\r\n"
            .getBytes(StandardCharsets.US_ASCII));
    out.flush();
    InputStream in = socket.getInputStream();
    String response = new String(in.readAllBytes(), StandardCharsets.US_ASCII);
    assertTrue(response.startsWith("HTTP/1.1 200"), response);
    return response.substring(response.indexOf("\r\n\r\n") + 4);
  }

  private static final class TrustAll implements X509TrustManager {
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) {}

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) {}

    @Override
    public X509Certificate[] getAcceptedIssuers() {
      return new X509Certificate[0];
    }
  }
}

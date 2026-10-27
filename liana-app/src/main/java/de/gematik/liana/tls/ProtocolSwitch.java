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

import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.net.NetClient;
import io.vertx.core.net.NetServer;
import io.vertx.core.net.NetSocket;
import io.vertx.core.net.SocketAddress;
import java.util.concurrent.ExecutionException;
import org.jboss.logging.Logger;

/**
 * HTTP and HTTPS on one port (decision-017): a {@link NetServer} reads the first byte of every
 * connection. A TLS handshake starts with {@code 0x16} (ContentType handshake); these connections
 * go via loopback to the internal HTTPS server, all others to the internal HTTP server. Both carry
 * the same handler. First the switch writes a PROXY protocol v1 header line so that the internal
 * servers see the real client address ({@link HttpServerRequest#remoteAddress()}), then the already
 * read first packet; from then on it couples both directions. If one side closes, it closes the
 * other.
 */
public final class ProtocolSwitch {

  private static final Logger LOG = Logger.getLogger(ProtocolSwitch.class);
  private static final byte TLS_HANDSHAKE = 0x16;
  private static final String LOOPBACK_ADDRESS = "127.0.0.1";

  private final NetServer front;
  private final HttpServer plain;
  private final HttpServer tls;
  private final NetClient loopback;

  private ProtocolSwitch(NetServer front, HttpServer plain, HttpServer tls, NetClient loopback) {
    this.front = front;
    this.plain = plain;
    this.tls = tls;
    this.loopback = loopback;
  }

  /**
   * Opens {@code port} (0 picks a free port) and the two internal servers on free loopback ports.
   *
   * @param tlsOptions options of the internal HTTPS server (certificate, protocols); host, port and
   *     PROXY protocol are set by the switch
   */
  public static ProtocolSwitch listen(
      Vertx vertx, int port, Handler<HttpServerRequest> handler, HttpServerOptions tlsOptions)
      throws InterruptedException, ExecutionException {
    HttpServer plain =
        await(
            vertx
                .createHttpServer(internal(new HttpServerOptions()))
                .requestHandler(handler)
                .listen());
    HttpServer tls =
        await(
            vertx
                .createHttpServer(internal(new HttpServerOptions(tlsOptions)))
                .requestHandler(handler)
                .listen());
    NetClient loopback = vertx.createNetClient();
    NetServer front = vertx.createNetServer();
    front.connectHandler(socket -> route(socket, loopback, plain.actualPort(), tls.actualPort()));
    await(front.listen(port));
    return new ProtocolSwitch(front, plain, tls, loopback);
  }

  private static HttpServerOptions internal(HttpServerOptions options) {
    return options.setHost(LOOPBACK_ADDRESS).setPort(0).setUseProxyProtocol(true);
  }

  private static void route(NetSocket client, NetClient loopback, int plainPort, int tlsPort) {
    client.handler(
        first -> {
          client.pause();
          client.handler(null);
          int target = first.getByte(0) == TLS_HANDSHAKE ? tlsPort : plainPort;
          loopback
              .connect(target, LOOPBACK_ADDRESS)
              .onSuccess(
                  server -> {
                    server.write(proxyHeader(client.remoteAddress(), client.localAddress()));
                    server.write(first);
                    client.closeHandler(v -> server.close());
                    server.closeHandler(v -> client.close());
                    client.exceptionHandler(e -> server.close());
                    server.exceptionHandler(e -> client.close());
                    server.pipeTo(client);
                    client.pipeTo(server);
                  })
              .onFailure(
                  e -> {
                    LOG.warnf(
                        "Weiche: interner Server auf Port %d nicht erreichbar: %s",
                        target, e.getMessage());
                    client.close();
                  });
        });
  }

  /**
   * PROXY protocol version 1 (HAProxy, section 2.1): {@code PROXY TCP4 <source> <dest> <sport>
   * <dport>\r\n}.
   */
  static Buffer proxyHeader(SocketAddress source, SocketAddress destination) {
    if (source == null
        || destination == null
        || source.hostAddress() == null
        || destination.hostAddress() == null) {
      return Buffer.buffer("PROXY UNKNOWN\r\n");
    }
    String family = source.hostAddress().contains(":") ? "TCP6" : "TCP4";
    return Buffer.buffer(
        "PROXY "
            + family
            + " "
            + source.hostAddress()
            + " "
            + destination.hostAddress()
            + " "
            + source.port()
            + " "
            + destination.port()
            + "\r\n");
  }

  /** Port of the switch, even if 0 is configured. */
  public int port() {
    return front.actualPort();
  }

  public void close() {
    front.close();
    loopback.close();
    plain.close();
    tls.close();
  }

  private static <T> T await(Future<T> future) throws InterruptedException, ExecutionException {
    return future.toCompletionStage().toCompletableFuture().get();
  }
}

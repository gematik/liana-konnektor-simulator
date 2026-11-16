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
package de.gematik.liana.trace;

import de.gematik.liana.kern.trace.Traffic;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.ChannelPromise;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpResponse;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.LastHttpContent;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.http.HttpVersion;
import io.vertx.core.net.SocketAddress;
import io.vertx.core.net.impl.ConnectionBase;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

/**
 * Reports the HTTP traffic of a Vert.x router to {@link Traffic} (LIANA-195): every request and its
 * response, as plaintext after TLS, the response paired with the request.
 *
 * <p>The first route handler gives the head of each request; a Netty handler per connection, in
 * front of the Vert.x handler, collects the body and the response as Vert.x writes it. HTTP/1.x
 * answers in the order of the requests, so a queue pairs them. The body is reported decoded, with
 * {@code Content-Length} instead of {@code Transfer-Encoding}.
 */
public final class HttpTrace {

  static final String NAME = "liana-trace";

  private final Traffic traffic;
  private final Predicate<String> traced;

  private HttpTrace(Traffic traffic, Predicate<String> traced) {
    this.traffic = traffic;
    this.traced = traced;
  }

  /** Reports the requests on {@code router} whose path {@code traced} accepts. */
  public static void install(Router router, Traffic traffic, Predicate<String> traced) {
    if (traffic.active()) {
      router.route().order(Integer.MIN_VALUE).handler(new HttpTrace(traffic, traced)::handle);
    }
  }

  private void handle(RoutingContext ctx) {
    HttpServerRequest request = ctx.request();
    if (request.version() != HttpVersion.HTTP_2
        && request.connection() instanceof ConnectionBase connection) {
      ChannelPipeline pipeline = connection.channel().pipeline();
      Recorder recorder = (Recorder) pipeline.get(NAME);
      if (recorder == null) {
        recorder = new Recorder(traffic);
        pipeline.addBefore("handler", NAME, recorder);
      }
      recorder.begin(request, traced.test(request.path()));
    }
    ctx.next();
  }

  /** One request or response: start line, headers, body so far. */
  private static final class Message {
    final Instant time = Instant.now();
    String startLine;
    final List<Map.Entry<String, String>> headers = new ArrayList<>();
    final ByteArrayOutputStream body = new ByteArrayOutputStream();

    void add(ByteBuf content) {
      byte[] bytes = new byte[content.readableBytes()];
      content.getBytes(content.readerIndex(), bytes);
      body.writeBytes(bytes);
    }

    byte[] bytes() {
      StringBuilder head = new StringBuilder(startLine).append("\r\n");
      for (Map.Entry<String, String> header : headers) {
        String name = header.getKey();
        if (!name.equalsIgnoreCase("transfer-encoding")
            && !name.equalsIgnoreCase("content-length")) {
          head.append(name).append(": ").append(header.getValue()).append("\r\n");
        }
      }
      if (body.size() > 0 || startLine.startsWith("HTTP/")) {
        head.append("Content-Length: ").append(body.size()).append("\r\n");
      }
      byte[] start = head.append("\r\n").toString().getBytes(StandardCharsets.ISO_8859_1);
      byte[] result = new byte[start.length + body.size()];
      System.arraycopy(start, 0, result, 0, start.length);
      System.arraycopy(body.toByteArray(), 0, result, start.length, body.size());
      return result;
    }
  }

  /** A request on its way: who sent it, whether it is reported, its UUID once reported. */
  private static final class Exchange {
    final Message request = new Message();
    boolean traced;
    String client;
    String liana;
    String uuid;
    Message response;
    boolean answered;
  }

  /** Per connection, on its event loop. */
  private static final class Recorder extends ChannelDuplexHandler {

    private final Traffic traffic;
    private Exchange receiving;
    private final Deque<Exchange> answering = new ArrayDeque<>();

    Recorder(Traffic traffic) {
      this.traffic = traffic;
    }

    /** Head of the request that is being received, from the first route handler. */
    void begin(HttpServerRequest request, boolean traced) {
      if (receiving == null) {
        receiving = new Exchange();
      }
      receiving.traced = traced;
      receiving.client = address(request.remoteAddress());
      // LIANA-195.04: name/IP:Port of the connection as on the wire
      receiving.liana =
          Traffic.address(
              traffic.name(), request.localAddress().hostAddress(), request.localAddress().port());
      receiving.request.startLine =
          request.method().name() + " " + request.uri() + " " + version(request.version());
      request
          .headers()
          .forEach((name, value) -> receiving.request.headers.add(Map.entry(name, value)));
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
      if (msg instanceof io.netty.handler.codec.http.HttpRequest) {
        receiving = new Exchange();
      }
      if (msg instanceof HttpContent content && receiving != null) {
        receiving.request.add(content.content());
        if (msg instanceof LastHttpContent) {
          received(receiving);
          receiving = null;
        }
      }
      super.channelRead(ctx, msg);
    }

    private void received(Exchange exchange) {
      if (exchange.traced && exchange.request.startLine != null) {
        exchange.uuid =
            traffic.report(
                exchange.request.bytes(),
                exchange.client,
                exchange.liana,
                exchange.request.time,
                null);
      }
      if (exchange.answered) {
        // answered while the request was still coming in, e.g. by a synchronous route
        answered(exchange);
      } else {
        answering.addLast(exchange);
      }
    }

    @Override
    public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise)
        throws Exception {
      if (msg instanceof HttpResponse response
          && !response.status().equals(HttpResponseStatus.CONTINUE)) {
        Exchange exchange = answering.isEmpty() ? receiving : answering.peekFirst();
        if (exchange != null) {
          exchange.response = new Message();
          exchange.response.startLine = response.protocolVersion() + " " + response.status();
          response.headers().forEach(exchange.response.headers::add);
        }
      }
      if (msg instanceof HttpContent content) {
        Exchange exchange = answering.isEmpty() ? receiving : answering.peekFirst();
        if (exchange != null && exchange.response != null) {
          exchange.response.add(content.content());
          if (msg instanceof LastHttpContent) {
            if (exchange == receiving) {
              exchange.answered = true;
            } else {
              answered(answering.pollFirst());
            }
          }
        }
      }
      super.write(ctx, msg, promise);
    }

    private void answered(Exchange exchange) {
      if (exchange.traced && exchange.uuid != null) {
        traffic.report(
            exchange.response.bytes(),
            exchange.liana,
            exchange.client,
            exchange.response.time,
            exchange.uuid);
      }
    }
  }

  private static String address(SocketAddress address) {
    return address == null ? "unknown:0" : address.hostAddress() + ":" + address.port();
  }

  private static String version(HttpVersion version) {
    return version == HttpVersion.HTTP_1_0 ? "HTTP/1.0" : "HTTP/1.1";
  }
}

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
package de.gematik.liana.adapter.cetp;

import de.gematik.liana.kern.error.ConnectorError;
import de.gematik.liana.kern.event.Event;
import de.gematik.liana.kern.event.EventSink;
import de.gematik.liana.kern.event.Subscription;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Delivery via CETP (Connector Event Transport Protocol) to the Ereignissenke {@code
 * cetp://host:port} of a subscription: the Konnektor opens the connection (TIP1-A_4594), over TCP,
 * with TLS from {@link Connector} (TIP1-A_5536, TIP1-A_4595), and sends {@code "CETP"}, the length
 * as four bytes big-endian and the event XML (TIP1-A_4596); the Konnektor expects no response. One
 * queue per Ereignissenke, so that the order is kept and an unreachable sink does not hold up the
 * others.
 *
 * <p>The connection stays open per Ereignissenke and carries the following events, as with the
 * Konnektors in the field; the spec leaves this open. A Tiger proxy as sink (cetpProxy of the
 * Konnektor QES suite) loses an event if the connection ends right after sending (LIANA-91,
 * LIANA-95). If the sink closes the connection or writing fails on an already used connection, the
 * Konnektor reopens it once for this event.
 */
public final class CetpSender implements EventSink, AutoCloseable {

  private static final System.Logger LOG = System.getLogger(CetpSender.class.getName());
  private static final byte[] MAGIC = "CETP".getBytes(StandardCharsets.US_ASCII);

  /**
   * Opens the connection to the Ereignissenke, including the TLS handshake; the Connector sets the
   * time limits.
   */
  @FunctionalInterface
  public interface Connector {
    Socket connect(String host, int port) throws IOException;
  }

  private final Connector connector;
  private final Map<String, ExecutorService> queues = new ConcurrentHashMap<>();

  /** Open connection per Ereignissenke; used only from its queue. */
  private final Map<String, Connection> connections = new ConcurrentHashMap<>();

  public CetpSender(Connector connector) {
    this.connector = connector;
  }

  @Override
  public void send(Event event, Subscription subscription, Outcome outcome) {
    byte[] xml = EventXml.render(event, subscription.id());
    try {
      if (!EventXml.matches(subscription.filter(), xml)) {
        return;
      }
    } catch (EventXml.FilterException e) {
      LOG.log(
          System.Logger.Level.WARNING,
          "TUC_KON_256 "
              + ConnectorError.FILTER_FAILED.code()
              + " "
              + ConnectorError.FILTER_FAILED.text()
              + ", Anmeldung "
              + subscription.id()
              + ": "
              + e.getMessage());
      return;
    }
    String eventTo = subscription.eventTo();
    queues
        .computeIfAbsent(
            eventTo,
            target ->
                Executors.newSingleThreadExecutor(
                    Thread.ofVirtual().name("liana-cetp " + target).factory()))
        .execute(() -> deliver(eventTo, event.topic(), xml, outcome));
  }

  private void deliver(String eventTo, String topic, byte[] xml, Outcome outcome) {
    try {
      Connection connection = connections.get(eventTo);
      boolean reused = connection != null && connection.open();
      if (!reused) {
        connection = connect(eventTo);
      }
      try {
        connection.write(frame(xml));
      } catch (IOException e) {
        if (!reused) {
          throw e;
        }
        connection.close();
        connect(eventTo).write(frame(xml));
      }
    } catch (IOException | RuntimeException e) {
      Optional.ofNullable(connections.remove(eventTo)).ifPresent(Connection::close);
      LOG.log(
          System.Logger.Level.WARNING, "CETP " + topic + " an " + eventTo + " gescheitert: " + e);
      outcome.failed(e.toString());
      return;
    }
    LOG.log(System.Logger.Level.INFO, "CETP " + topic + " an " + eventTo);
    outcome.delivered();
  }

  private Connection connect(String eventTo) throws IOException {
    URI uri = URI.create(eventTo);
    Connection connection =
        new Connection(connector.connect(uri.getHost(), uri.getPort()), eventTo);
    Optional.ofNullable(connections.put(eventTo, connection)).ifPresent(Connection::close);
    return connection;
  }

  /**
   * A connection to the Ereignissenke. The sink sends nothing; a reader only notices when it closes
   * the connection, so that the next event does not end up on a dead connection.
   */
  private static final class Connection {
    private final Socket socket;
    private volatile boolean open = true;

    Connection(Socket socket, String eventTo) {
      this.socket = socket;
      Thread.ofVirtual().name("liana-cetp-reader " + eventTo).start(this::drain);
    }

    private void drain() {
      try (InputStream in = socket.getInputStream()) {
        while (in.read() >= 0) {
          // the sink does not respond at application level
        }
      } catch (IOException e) {
        // closed
      } finally {
        close();
      }
    }

    boolean open() {
      return open && !socket.isClosed();
    }

    void write(byte[] frame) throws IOException {
      OutputStream out = socket.getOutputStream();
      out.write(frame);
      out.flush();
    }

    void close() {
      open = false;
      try {
        socket.close();
      } catch (IOException e) {
        // already closed
      }
    }
  }

  /** TIP1-A_4596: {@code "CETP"}, length in bytes as four bytes big-endian, event message. */
  static byte[] frame(byte[] xml) {
    return ByteBuffer.allocate(MAGIC.length + 4 + xml.length)
        .put(MAGIC)
        .putInt(xml.length)
        .put(xml)
        .array();
  }

  @Override
  public void close() {
    queues.values().forEach(ExecutorService::shutdownNow);
    queues.clear();
    connections.values().forEach(Connection::close);
    connections.clear();
  }
}

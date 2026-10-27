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

import de.gematik.liana.konnektor.ws.conn.eventservice.v7_2.Event;
import jakarta.xml.bind.JAXBException;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;

/**
 * CETP receiver (LIANA-137): accepts connections from the Konnektor (TIP1-A_4594), reads {@code
 * "CETP"} per event, the length as four bytes big-endian and the event XML (TIP1-A_4596), and stays
 * connected as long as the Konnektor keeps the connection open (LIANA-95). TLS via the client's own
 * BCJSSE instance.
 */
final class CetpServer implements AutoCloseable {

  private static final System.Logger LOG = System.getLogger(CetpServer.class.getName());
  private static final byte[] MAGIC = "CETP".getBytes(StandardCharsets.US_ASCII);
  private static final int MAX_EVENT = 1 << 20;

  private final ServerSocket server;
  private final Consumer<KonnektorEvent> listener;
  private final CopyOnWriteArrayList<Socket> connections = new CopyOnWriteArrayList<>();
  private final Thread acceptor;

  CetpServer(EventSink sink, Consumer<KonnektorEvent> listener) throws IOException {
    this.listener = listener;
    this.server = sink.tls() == null ? new ServerSocket() : tls(sink.tls());
    server.bind(new InetSocketAddress(InetAddress.getByName("0.0.0.0"), sink.port()));
    acceptor = new Thread(this::accept, "cetp-accept");
    acceptor.setDaemon(true);
    acceptor.start();
  }

  int port() {
    return server.getLocalPort();
  }

  private static ServerSocket tls(Credentials.Pkcs12 identity) throws IOException {
    try {
      KeyStore store = KeyStore.getInstance("PKCS12", Bc.PROVIDER);
      store.load(new ByteArrayInputStream(identity.data()), identity.password());
      KeyManagerFactory keys = KeyManagerFactory.getInstance("PKIX", Bc.JSSE);
      keys.init(store, identity.password());
      SSLContext context = SSLContext.getInstance(ClientTls.PROTOCOL, Bc.JSSE);
      context.init(keys.getKeyManagers(), null, new SecureRandom());
      return new GroupsContext(context).getServerSocketFactory().createServerSocket();
    } catch (GeneralSecurityException e) {
      throw new IOException("Ereignissenke: TLS-Identität nicht lesbar", e);
    }
  }

  private void accept() {
    while (!server.isClosed()) {
      try {
        Socket socket = server.accept();
        connections.add(socket);
        Thread reader = new Thread(() -> read(socket), "cetp-read");
        reader.setDaemon(true);
        reader.start();
      } catch (IOException e) {
        if (!server.isClosed()) {
          LOG.log(System.Logger.Level.WARNING, "CETP: accept gescheitert: " + e.getMessage());
        }
      }
    }
  }

  private void read(Socket socket) {
    try (socket;
        DataInputStream in = new DataInputStream(socket.getInputStream())) {
      while (true) {
        byte[] magic = new byte[4];
        try {
          in.readFully(magic);
        } catch (EOFException e) {
          return;
        }
        if (!java.util.Arrays.equals(MAGIC, magic)) {
          LOG.log(System.Logger.Level.WARNING, "CETP: Rahmen ohne CETP, Verbindung geschlossen");
          return;
        }
        int length = in.readInt();
        if (length < 0 || length > MAX_EVENT) {
          LOG.log(System.Logger.Level.WARNING, "CETP: Länge " + length + " ungültig");
          return;
        }
        byte[] xml = new byte[length];
        in.readFully(xml);
        try {
          listener.accept(parse(xml));
        } catch (JAXBException | XMLStreamException | RuntimeException e) {
          LOG.log(System.Logger.Level.WARNING, "CETP: Ereignis nicht lesbar: " + e.getMessage());
        }
      }
    } catch (IOException e) {
      if (!server.isClosed()) {
        LOG.log(System.Logger.Level.DEBUG, "CETP: Verbindung beendet: " + e.getMessage());
      }
    } finally {
      connections.remove(socket);
    }
  }

  static KonnektorEvent parse(byte[] xml) throws JAXBException, XMLStreamException {
    XMLInputFactory factory = XMLInputFactory.newFactory();
    factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
    factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
    Object value =
        Soap.context(Binding.EVENT_SERVICE_7_2)
            .createUnmarshaller()
            .unmarshal(factory.createXMLStreamReader(new ByteArrayInputStream(xml)));
    if (value instanceof jakarta.xml.bind.JAXBElement<?> element) {
      value = element.getValue();
    }
    Event event = (Event) value;
    Map<String, String> parameters = new LinkedHashMap<>();
    if (event.getMessage() != null) {
      event.getMessage().getParameter().forEach(p -> parameters.put(p.getKey(), p.getValue()));
    }
    return new KonnektorEvent(
        event.getTopic(),
        event.getType() == null ? null : event.getType().value(),
        event.getSeverity() == null ? null : event.getSeverity().value(),
        event.getSubscriptionID(),
        parameters);
  }

  @Override
  public void close() {
    try {
      server.close();
    } catch (IOException e) {
      // nothing to do
    }
    for (Socket socket : connections) {
      try {
        socket.close();
      } catch (IOException e) {
        // nothing to do
      }
    }
  }
}

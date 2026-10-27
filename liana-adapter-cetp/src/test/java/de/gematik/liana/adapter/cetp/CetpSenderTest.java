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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.kern.access.Context;
import de.gematik.liana.kern.event.Event;
import de.gematik.liana.kern.event.EventSink;
import de.gematik.liana.kern.event.Subscription;
import java.io.DataInputStream;
import java.io.IOException;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Delivery over TCP to a local receiver; TLS is added in liana-app ({@code CetpTls}). */
class CetpSenderTest {

  private static final Context CTX = new Context("M1", "CS1", "WP1", null);

  private final BlockingQueue<String> outcomes = new LinkedBlockingQueue<>();
  private final CetpSender sender = new CetpSender((host, port) -> new Socket(host, port));

  @AfterEach
  void close() {
    sender.close();
  }

  private static Event event(String topic) {
    return new Event(topic, Event.Type.OPERATION, Event.Severity.INFO, Map.of("CtID", "KT-01"));
  }

  private static Subscription subscription(String id, int port, String filter) {
    return new Subscription(id, Instant.now(), CTX, "cetp://127.0.0.1:" + port, "CARD", filter);
  }

  private EventSink.Outcome outcome(String name) {
    return new EventSink.Outcome() {
      @Override
      public void delivered() {
        outcomes.add(name + " delivered");
      }

      @Override
      public void failed(String reason) {
        outcomes.add(name + " failed");
      }
    };
  }

  /** Reads a CETP message: marker, length, event XML. */
  private static String read(DataInputStream in) throws IOException {
    byte[] magic = in.readNBytes(4);
    assertArrayEquals("CETP".getBytes(StandardCharsets.US_ASCII), magic);
    byte[] xml = in.readNBytes(in.readInt());
    return new String(xml, StandardCharsets.UTF_8);
  }

  @Test
  @DisplayName(
      "TIP1-A_4594 / TIP1-A_4596: Verbindung zur Ereignissenke aus EventTo, CETP + Länge Big-Endian + "
          + "Event-XML mit der SubscriptionID, Reihenfolge je Senke bleibt, die Verbindung trägt beide Ereignisse")
  void zustellung() throws Exception {
    try (ServerSocket server = new ServerSocket(0, 10, InetAddress.getLoopbackAddress())) {
      server.setSoTimeout(5000);
      sender.send(
          event("CARD/INSERTED"), subscription("sub-1", server.getLocalPort(), null), outcome("1"));
      sender.send(
          event("CARD/REMOVED"), subscription("sub-1", server.getLocalPort(), null), outcome("2"));

      try (Socket socket = server.accept();
          DataInputStream in = new DataInputStream(socket.getInputStream())) {
        String first = read(in);
        assertTrue(first.contains("<Topic>CARD/INSERTED</Topic>"), first);
        assertTrue(first.contains("<SubscriptionID>sub-1</SubscriptionID>"), first);
        assertTrue(read(in).contains("<Topic>CARD/REMOVED</Topic>"));
        assertEquals("1 delivered", outcomes.poll(5, TimeUnit.SECONDS));
        assertEquals("2 delivered", outcomes.poll(5, TimeUnit.SECONDS));
        // the connection stays open (LIANA-91: Tiger proxy as sink)
        socket.setSoTimeout(200);
        assertThrows(SocketTimeoutException.class, in::read);
      }
    }
  }

  @Test
  @DisplayName(
      "TIP1-A_4594: schließt die Ereignissenke die Verbindung, baut der Konnektor für das nächste "
          + "Ereignis eine neue auf")
  void neueVerbindungNachSchliessen() throws Exception {
    try (ServerSocket server = new ServerSocket(0, 10, InetAddress.getLoopbackAddress())) {
      server.setSoTimeout(5000);
      sender.send(
          event("CARD/INSERTED"), subscription("sub-1", server.getLocalPort(), null), outcome("1"));
      try (Socket socket = server.accept();
          DataInputStream in = new DataInputStream(socket.getInputStream())) {
        assertTrue(read(in).contains("<Topic>CARD/INSERTED</Topic>"));
      }
      assertEquals("1 delivered", outcomes.poll(5, TimeUnit.SECONDS));

      Thread.sleep(200); // the reader notices the close
      sender.send(
          event("CARD/REMOVED"), subscription("sub-1", server.getLocalPort(), null), outcome("2"));
      try (Socket socket = server.accept();
          DataInputStream in = new DataInputStream(socket.getInputStream())) {
        assertTrue(read(in).contains("<Topic>CARD/REMOVED</Topic>"));
      }
      assertEquals("2 delivered", outcomes.poll(5, TimeUnit.SECONDS));
    }
  }

  @Test
  @DisplayName("TIP1-A_4596: Rahmen ist „CETP“, vier Byte Länge (höchstwertiges zuerst), Nachricht")
  void rahmen() {
    byte[] xml = new byte[0x0102];
    byte[] frame = CetpSender.frame(xml);
    assertEquals(4 + 4 + 0x0102, frame.length);
    assertArrayEquals(
        new byte[] {'C', 'E', 'T', 'P', 0, 0, 1, 2}, java.util.Arrays.copyOf(frame, 8));
  }

  @Test
  @DisplayName(
      "Ereignissenke nicht erreichbar → failed (für EVT_MAX_TRY); passt der Filter nicht oder ist er "
          + "fehlerhaft (4095), geht nichts raus und es gibt kein Ergebnis")
  void fehlschlagUndFilter() throws Exception {
    int closed;
    try (ServerSocket probe = new ServerSocket(0)) {
      closed = probe.getLocalPort();
    }
    sender.send(event("CARD/INSERTED"), subscription("sub-1", closed, null), outcome("weg"));
    assertEquals("weg failed", outcomes.poll(5, TimeUnit.SECONDS));

    sender.send(
        event("CARD/INSERTED"),
        subscription("sub-2", closed, "/Event[Topic='CARD/REMOVED']"),
        outcome("filter"));
    sender.send(
        event("CARD/INSERTED"), subscription("sub-3", closed, "/Event["), outcome("kaputt"));
    CetpSender failing =
        new CetpSender(
            (host, port) -> {
              throw new ConnectException("abgelehnt");
            });
    failing.send(event("CARD/INSERTED"), subscription("sub-4", closed, null), outcome("connector"));
    assertEquals("connector failed", outcomes.poll(5, TimeUnit.SECONDS));
    failing.close();
    assertEquals(List.of(), List.copyOf(outcomes));
  }
}

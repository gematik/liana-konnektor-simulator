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
package de.gematik.liana.adapter.fake;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import de.gematik.liana.kern.terminal.CardTerminal;
import de.gematik.liana.kern.terminal.SlotListener;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** LIANA-27: card APDUs via {@code POST /traffic} to a Tiger proxy, here a local HTTP stub. */
class TrafficPushTest {

  private static final HexFormat HEX = HexFormat.of().withUpperCase();
  private static final byte[] SELECT = HEX.parseHex("00A4040C07D2760001448000");
  private static final byte[] OK = HEX.parseHex("9000");

  /** A received push: headers and body. */
  record Pushed(String sender, String receiver, String timestamp, byte[] body) {}

  private HttpServer stub;
  private final LinkedBlockingQueue<Pushed> received = new LinkedBlockingQueue<>();
  private final CountDownLatch release = new CountDownLatch(1);

  @AfterEach
  void stop() {
    release.countDown();
    if (stub != null) {
      stub.stop(0);
    }
  }

  private URI stub(boolean hang) throws IOException {
    stub = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
    stub.createContext(
        "/traffic",
        exchange -> {
          if (hang) {
            try {
              release.await();
            } catch (InterruptedException e) {
              Thread.currentThread().interrupt();
            }
          }
          var headers = exchange.getRequestHeaders();
          received.add(
              new Pushed(
                  headers.getFirst("tgr-sender"),
                  headers.getFirst("tgr-receiver"),
                  headers.getFirst("tgr-timestamp"),
                  exchange.getRequestBody().readAllBytes()));
          exchange.sendResponseHeaders(200, -1);
          exchange.close();
        });
    stub.start();
    return URI.create("http://localhost:" + stub.getAddress().getPort());
  }

  /** KT with a card in slot 1 that answers 9000 to everything. */
  private static CardTerminal kt() {
    return new CardTerminal() {
      public String id() {
        return "KT-01";
      }

      public int slots() {
        return 1;
      }

      public void addSlotListener(SlotListener listener) {}

      public boolean cardPresent(int slot) {
        return true;
      }

      public byte[] reset(int slot) {
        return new byte[] {0x3B};
      }

      public byte[] transmit(int slot, byte[] commandApdu) {
        return OK;
      }
    };
  }

  private Pushed next() throws InterruptedException {
    Pushed pushed = received.poll(5, TimeUnit.SECONDS);
    assertTrue(pushed != null, "kein Push angekommen");
    return pushed;
  }

  @Test
  @DisplayName(
      "LIANA-28: Klartext einer terminierten SM-APDU mit eigenem Absender liana-sm-klartext und Empfänger "
          + "KT-SM-sm-klartext:1")
  void klartext() throws Exception {
    try (var push = new TrafficPush(stub(false), Duration.ofSeconds(2))) {
      push.plaintext("KT-SM", 1, SELECT, Instant.now(), HEX.parseHex("9000"), Instant.now());
      Pushed command = next();
      Pushed response = next();
      assertEquals("liana-sm-klartext", command.sender());
      assertEquals("KT-SM-sm-klartext:1", command.receiver());
      assertTrue(HEX.formatHex(command.body()).endsWith(HEX.formatHex(SELECT)));
      assertEquals("KT-SM-sm-klartext:1", response.sender());
      assertEquals("liana-sm-klartext", response.receiver());
      assertTrue(HEX.formatHex(response.body()).endsWith("9000"));
      assertTrue(received.isEmpty());
    }
  }

  @Test
  @DisplayName(
      "Jede APDU erzeugt genau zwei POST /traffic: Kommando liana → KT-01:1 (C_COMMAND), Antwort KT-01:1 → liana "
          + "(R_RESPONSE), gleiche Sequenznummer, Zeitstempel ISO-8601")
  void zweiNachrichtenJeApdu() throws Exception {
    try (var push = new TrafficPush(stub(false), Duration.ofSeconds(2))) {
      var terminal = new TrafficPushingTerminal(kt(), push);
      assertArrayEquals(OK, terminal.transmit(1, SELECT));
      terminal.transmit(1, SELECT);

      Pushed command = next();
      Pushed response = next();
      assertEquals("liana", command.sender());
      assertEquals("KT-01:1", command.receiver());
      assertEquals("KT-01:1", response.sender());
      assertEquals("liana", response.receiver());
      Instant.parse(command.timestamp());
      // SICCT envelope: type, slot 1, sequence 0, RFU, length 12, APDU
      assertEquals(
          "6B" + "0001" + "0000" + "00" + "0000000C" + "00A4040C07D2760001448000",
          HEX.formatHex(command.body()));
      assertEquals(
          "83" + "0001" + "0000" + "00" + "00000002" + "9000", HEX.formatHex(response.body()));
      assertEquals("6B" + "0001" + "0001", HEX.formatHex(next().body()).substring(0, 10));
      assertEquals("83" + "0001" + "0001", HEX.formatHex(next().body()).substring(0, 10));
      assertTrue(received.isEmpty());
    }
  }

  @Test
  @DisplayName(
      "Proxy nicht erreichbar: transmit liefert die Kartenantwort, der Fehler wird einmal geloggt, nicht je APDU")
  void proxyNichtErreichbar() throws Exception {
    int closedPort;
    try (var socket = new ServerSocket(0)) {
      closedPort = socket.getLocalPort();
    }
    var warnings = warnings();
    try (var push =
        new TrafficPush(URI.create("http://localhost:" + closedPort), Duration.ofMillis(300))) {
      var terminal = new TrafficPushingTerminal(kt(), push);
      for (int i = 0; i < 5; i++) {
        assertArrayEquals(OK, terminal.transmit(1, SELECT));
      }
    }
    assertEquals(1, warnings.size(), warnings.toString());
    assertTrue(warnings.getFirst().contains("fehlgeschlagen"));
  }

  @Test
  @DisplayName(
      "Proxy hängt: transmit kehrt sofort mit der Kartenantwort zurück, der Push wartet höchstens push-timeout")
  void proxyHaengt() throws Exception {
    var warnings = warnings();
    try (var push = new TrafficPush(stub(true), Duration.ofMillis(300))) {
      var terminal = new TrafficPushingTerminal(kt(), push);
      assertTimeoutPreemptively(
          Duration.ofMillis(200),
          () -> {
            for (int i = 0; i < 3; i++) {
              assertArrayEquals(OK, terminal.transmit(1, SELECT));
            }
          });
    }
    assertEquals(1, warnings.size(), warnings.toString());
    assertTrue(warnings.getFirst().contains("HttpTimeoutException"), warnings.toString());
  }

  @Test
  @DisplayName("Andere Operationen gehen unverändert an das KT, ohne Push")
  void nurApdus() throws Exception {
    try (var push = new TrafficPush(stub(false), Duration.ofSeconds(2))) {
      var terminal = new TrafficPushingTerminal(kt(), push);
      assertEquals("KT-01", terminal.id());
      assertArrayEquals(new byte[] {0x3B}, terminal.reset(1));
      assertTrue(terminal.cardPresent(1));
    }
    assertTrue(received.isEmpty());
  }

  /** WARNING messages from {@link TrafficPush} during the test (System.Logger → JUL). */
  private static List<String> warnings() {
    List<String> messages = Collections.synchronizedList(new ArrayList<>());
    Logger logger = Logger.getLogger(TrafficPush.class.getName());
    logger.addHandler(
        new Handler() {
          @Override
          public void publish(LogRecord record) {
            if (record.getLevel().intValue() >= Level.WARNING.intValue()) {
              messages.add(record.getMessage());
            }
          }

          @Override
          public void flush() {}

          @Override
          public void close() {}
        });
    return messages;
  }
}

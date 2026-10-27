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
package de.gematik.liana.adapter.sicct;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.kern.event.SystemLog;
import de.gematik.liana.kern.terminal.CardTimeoutException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.time.Clock;
import java.time.Duration;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The SICCT connection over a socket, with a test card terminal at the other end (without TLS,
 * without kartos): matching of R-commands via the sequence number (SICCT 1.2.3 §6.2.4.3), events
 * (§6.2.4.4), timeout and connection end (TIP1-A_4537).
 */
class SicctConnectionTest {

  static final HexFormat HEX = HexFormat.of();
  static final Duration WAIT = Duration.ofSeconds(2);

  private ServerSocket server;
  private Socket kt;
  private InputStream ktIn;
  private OutputStream ktOut;
  private final BlockingQueue<SicctEnvelope> events = new LinkedBlockingQueue<>();
  private final List<String> disconnects = new CopyOnWriteArrayList<>();
  private final SystemLog log = new SystemLog(Clock.systemUTC(), 100);
  private SicctConnection connection;

  @BeforeEach
  void verbinden() throws IOException {
    server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
    Socket konnektor = new Socket(InetAddress.getLoopbackAddress(), server.getLocalPort());
    kt = server.accept();
    ktIn = kt.getInputStream();
    ktOut = kt.getOutputStream();
    connection =
        new SicctConnection(
            "KT-S1",
            "kt-s1.local",
            konnektor,
            events::add,
            (ctId, host, reason) -> {
              disconnects.add(ctId + " " + host + ": " + reason);
              log.ctDisconnected(ctId, host, reason);
            });
  }

  @AfterEach
  void schliessen() throws IOException {
    connection.close();
    kt.close();
    server.close();
  }

  private void ktSends(SicctEnvelope envelope) throws IOException {
    ktOut.write(envelope.encode());
    ktOut.flush();
  }

  private static SicctEnvelope response(SicctEnvelope command, String payload) {
    return new SicctEnvelope(
        SicctEnvelope.Type.R_COMMAND, command.fu(), command.seq(), HEX.parseHex(payload));
  }

  @Test
  @DisplayName(
      "§6.2.4.3: R-Kommandos finden ihr C-Kommando über die Sequenznummer, auch in anderer Reihenfolge; "
          + "Ereignisse dazwischen gehen an den Empfänger")
  void antwortenUndEreignisse() throws Exception {
    CompletableFuture<byte[]> first = CompletableFuture.supplyAsync(() -> transmit(1, "00A4040C"));
    SicctEnvelope c1 = SicctEnvelope.read(ktIn);
    CompletableFuture<byte[]> second =
        CompletableFuture.supplyAsync(() -> transmit(0, "8013006300"));
    SicctEnvelope c2 = SicctEnvelope.read(ktIn);
    assertEquals(SicctEnvelope.Type.C_COMMAND, c1.type());
    assertEquals(1, c1.fu());
    assertEquals(0, c2.fu());
    assertTrue(c1.seq() != c2.seq() && c1.seq() <= SicctEnvelope.MAX_COMMAND_SEQ);

    ktSends(response(c2, "63009000"));
    ktSends(new SicctEnvelope(SicctEnvelope.Type.EVENT, 0, 0xFD00, HEX.parseHex("84020002")));
    ktSends(response(c1, "6A82"));
    assertArrayEquals(HEX.parseHex("63009000"), second.get(2, TimeUnit.SECONDS));
    assertArrayEquals(HEX.parseHex("6A82"), first.get(2, TimeUnit.SECONDS));
    SicctEnvelope event = events.poll(2, TimeUnit.SECONDS);
    assertEquals(
        new SicctEnvelope(SicctEnvelope.Type.EVENT, 0, 0xFD00, HEX.parseHex("84020002")), event);
    assertTrue(connection.connected());
  }

  @Test
  @DisplayName(
      "Ohne Antwort in der Frist: CardTimeoutException (TUC_KON_200: 4094); eine späte Antwort stört nicht")
  void zeitueberschreitung() throws Exception {
    CardTimeoutException timeout =
        assertThrows(
            CardTimeoutException.class,
            () -> connection.transmit(1, HEX.parseHex("00B0000000"), Duration.ofMillis(200)));
    assertTrue(timeout.getMessage().contains("KT-S1"), timeout.getMessage());
    SicctEnvelope late = SicctEnvelope.read(ktIn);
    ktSends(response(late, "9000"));
    CompletableFuture<byte[]> next = CompletableFuture.supplyAsync(() -> transmit(1, "00A4040C"));
    ktSends(response(SicctEnvelope.read(ktIn), "9000"));
    assertArrayEquals(HEX.parseHex("9000"), next.get(2, TimeUnit.SECONDS));
  }

  @Test
  @DisplayName(
      "TIP1-A_4537: schließt das KT die Verbindung, scheitert ein wartendes Kommando mit IOException, der Kern "
          + "erfährt es genau einmal (CT/DISCONNECTED mit CtID und Hostname), weitere Kommandos scheitern sofort")
  void abbruchDurchKt() throws Exception {
    CompletableFuture<byte[]> waiting =
        CompletableFuture.supplyAsync(() -> transmit(1, "00A4040C"));
    SicctEnvelope.read(ktIn);
    kt.close();
    Exception failure = assertThrows(Exception.class, () -> waiting.get(2, TimeUnit.SECONDS));
    assertInstanceOf(IOException.class, failure.getCause().getCause());
    assertTimeoutPreemptively(
        WAIT,
        () -> {
          while (disconnects.isEmpty()) {
            Thread.sleep(10);
          }
        });
    assertFalse(connection.connected());
    assertTimeoutPreemptively(
        WAIT,
        () ->
            assertThrows(
                IOException.class, () -> connection.transmit(1, HEX.parseHex("00A4040C"), WAIT)));
    connection.close();
    assertEquals(List.of("KT-S1 kt-s1.local: Verbindung vom KT geschlossen"), disconnects);
    SystemLog.Entry entry = log.entries(null, null).getFirst();
    assertEquals("CT/DISCONNECTED", entry.topic());
    assertEquals(SystemLog.Type.OP, entry.type());
    assertEquals(SystemLog.Severity.INFO, entry.severity());
    assertEquals(Map.of("CtID", "KT-S1", "Hostname", "kt-s1.local"), entry.parameters());
  }

  @Test
  @DisplayName("TIP1-A_4537: ein unlesbarer Umschlag vom KT beendet die Verbindung mit Grund")
  void kaputterUmschlag() throws Exception {
    ktOut.write(HEX.parseHex("770000000100000000029000"));
    ktOut.flush();
    assertTimeoutPreemptively(
        WAIT,
        () -> {
          while (disconnects.isEmpty()) {
            Thread.sleep(10);
          }
        });
    assertTrue(disconnects.getFirst().contains("Lesefehler"), disconnects.getFirst());
  }

  @Test
  @DisplayName(
      "close() durch den Konnektor beendet wartende Kommandos und meldet CT/DISCONNECTED einmal")
  void abbauDurchKonnektor() throws Exception {
    CompletableFuture<byte[]> waiting =
        CompletableFuture.supplyAsync(() -> transmit(1, "00A4040C"));
    SicctEnvelope.read(ktIn);
    connection.close();
    connection.close();
    assertThrows(Exception.class, () -> waiting.get(2, TimeUnit.SECONDS));
    assertTimeoutPreemptively(
        WAIT,
        () -> {
          while (disconnects.isEmpty()) {
            Thread.sleep(10);
          }
        });
    Thread.sleep(100);
    assertEquals(List.of("KT-S1 kt-s1.local: vom Konnektor beendet"), disconnects);
  }

  private byte[] transmit(int fu, String apdu) {
    try {
      return connection.transmit(fu, HEX.parseHex(apdu), WAIT);
    } catch (IOException e) {
      throw new java.io.UncheckedIOException(e);
    }
  }
}

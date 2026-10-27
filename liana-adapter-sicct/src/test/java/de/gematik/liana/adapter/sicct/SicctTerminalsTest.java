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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.kern.error.ConnectorError;
import de.gematik.liana.kern.error.ConnectorException;
import de.gematik.liana.kern.event.SystemLog;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.time.Clock;
import java.time.Duration;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

/**
 * TUC_KON_054 "Kartenterminal hinzufügen" (add card terminal) and TUC_KON_055 "Befülle CT-Object"
 * (populate CT object) (gemSpec_Kon 4.1.4.3.2/4.1.4.3.4), TIP1-A_4540 (service announcement
 * packets), against a test card terminal on loopback: service discovery via UDP, SICCT over TCP
 * without TLS with the GET STATUS responses of kartos ({@link GetStatusTest}).
 */
class SicctTerminalsTest {

  static final HexFormat HEX = HexFormat.of();
  static final InetAddress LOOPBACK = InetAddress.getLoopbackAddress();
  static final String MAC = "02:00:00:4C:49:41";
  static final String NAME = "kartos-terminal-0001";

  private TestKt kt;
  private DiscoveryChannel channel;
  private final SystemLog log = new SystemLog(Clock.systemUTC(), 100);
  private final AtomicInteger connects = new AtomicInteger();

  /**
   * Test card terminal: answers service enquiries (UDP) and SICCT commands (TCP) like kartos
   * terminal.
   */
  static final class TestKt implements AutoCloseable {
    final DatagramSocket udp = new DatagramSocket(0, LOOPBACK);
    final ServerSocket tcp = new ServerSocket(0, 5, LOOPBACK);
    volatile byte[] ctm = GetStatusTest.CTM;

    /** Leave service enquiries unanswered, like a card terminal that is not running yet. */
    volatile boolean silent;

    TestKt() throws IOException {
      Thread discovery = new Thread(this::discovery, "test-kt-udp");
      discovery.setDaemon(true);
      discovery.start();
      Thread sicct = new Thread(this::sicct, "test-kt-tcp");
      sicct.setDaemon(true);
      sicct.start();
    }

    private void discovery() {
      byte[] buffer = new byte[512];
      while (!udp.isClosed()) {
        try {
          DatagramPacket enquiry = new DatagramPacket(buffer, buffer.length);
          udp.receive(enquiry);
          if (silent) {
            continue;
          }
          List<Tlv> fields =
              Tlv.parse(
                  Tlv.parse(Arrays.copyOf(enquiry.getData(), enquiry.getLength()))
                      .getFirst()
                      .value());
          InetAddress client =
              InetAddress.getByAddress(Tlv.find(fields, 0x81).orElseThrow().value());
          byte[] p = Tlv.find(fields, 0x82).orElseThrow().value();
          byte[] answer =
              ServiceDiscovery.encode(
                  new ServiceDiscovery.Announcement(
                      LOOPBACK, MAC, NAME, tcp.getLocalPort(), List.of(0x30)));
          udp.send(
              new DatagramPacket(
                  answer, answer.length, client, ((p[0] & 0xFF) << 8) | (p[1] & 0xFF)));
        } catch (IOException e) {
          // closed
        }
      }
    }

    private void sicct() {
      while (!tcp.isClosed()) {
        try (Socket socket = tcp.accept()) {
          for (SicctEnvelope c; (c = SicctEnvelope.read(socket.getInputStream())) != null; ) {
            byte[] apdu = c.payload();
            byte[] answer =
                switch (apdu[1]) {
                  case 0x28 -> HEX.parseHex("691213001300130c47454d3536353239303833329000");
                  case 0x13 ->
                      switch (apdu[3]) {
                        case 0x63 -> GetStatusTest.CTS;
                        case 0x46 -> ctm;
                        case 0x67 -> GetStatusTest.DSPLC;
                        default -> HEX.parseHex("6a86");
                      };
                  default -> HEX.parseHex("9000");
                };
            socket
                .getOutputStream()
                .write(
                    new SicctEnvelope(SicctEnvelope.Type.R_COMMAND, c.fu(), c.seq(), answer)
                        .encode());
          }
        } catch (IOException e) {
          // connection or server closed
        }
      }
    }

    @Override
    public void close() throws IOException {
      udp.close();
      tcp.close();
    }
  }

  @BeforeEach
  void starten() throws IOException {
    kt = new TestKt();
  }

  @AfterEach
  void beenden() throws IOException {
    kt.close();
    if (channel != null) {
      channel.close();
    }
  }

  private SicctTerminals terminals(
      List<SicctTerminals.Spec> specs, int discoveryPort, List<String> versions)
      throws IOException {
    SicctTerminals terminals =
        new SicctTerminals(
            specs,
            (host, port) -> {
              connects.incrementAndGet();
              return new Socket(host, port);
            },
            new SicctTerminals.Settings(
                discoveryPort, Duration.ofMillis(500), Duration.ofSeconds(2), versions),
            log);
    channel = new DiscoveryChannel(new InetSocketAddress(LOOPBACK, 0), terminals::announced);
    return terminals;
  }

  @Test
  @DisplayName(
      "TUC_KON_054 ManuallyAdded + TUC_KON_055: das konfigurierte KT bekommt per Dienstsuche MAC, Hostname und "
          + "Port, Korrelation „zugewiesen“, aus GET STATUS SLOTCOUNT 4, Version 1.0.0 (unterstützt), Display")
  void konfiguriertesKt() throws IOException {
    SicctTerminals terminals =
        terminals(
            List.of(new SicctTerminals.Spec("KT-S1", "127.0.0.1")),
            kt.udp.getLocalPort(),
            List.of("1.0.0"));
    terminals.start(channel);
    Map<String, Object> ct = terminals.ct("KT-S1").orElseThrow().snapshot();
    assertEquals("KT-S1", ct.get("CTID"));
    assertEquals(true, ct.get("IS_PHYSICAL"));
    assertEquals(MAC, ct.get("MAC_ADRESS"));
    assertEquals(NAME, ct.get("HOSTNAME"));
    assertEquals("127.0.0.1", ct.get("IP_ADRESS"));
    assertEquals(kt.tcp.getLocalPort(), ct.get("TCP_PORT"));
    assertEquals(4, ct.get("SLOTCOUNT"));
    assertEquals("1.0.0", ct.get("EHEALTH_INTERFACE_VERSION"));
    assertEquals(true, ct.get("VALID_VERSION"));
    assertEquals(
        new CtObject.DisplayCapabilities(20, 4, 48, 4, true).toMap(),
        ct.get("DISPLAY_CAPABILITIES"));
    assertEquals("zugewiesen", ct.get("CORRELATION"));
    assertEquals(
        false, ct.get("CONNECTED"), "TUC_KON_050 Schritt 4b: niedrige Korrelation, keine Nutzung");
    assertEquals(4, terminals.terminals().getFirst().slots());
    assertEquals(1, connects.get(), "eine Verbindung für TUC_KON_055, danach getrennt");
  }

  @Test
  @DisplayName(
      "TUC_KON_055 Schritt 3: eine Version außerhalb CTM_SUPPORTED_KT_VERSIONS ergibt VALID_VERSION = false")
  void versionNichtUnterstuetzt() throws IOException {
    SicctTerminals terminals =
        terminals(
            List.of(new SicctTerminals.Spec("KT-S1", "127.0.0.1")),
            kt.udp.getLocalPort(),
            List.of("1.0.1"));
    terminals.start(channel);
    assertFalse(terminals.ct("KT-S1").orElseThrow().validVersion());
  }

  @Test
  @DisplayName(
      "TUC_KON_054 Fehlerfall (1): ohne Antwort auf die Dienstanfrage 4033, CT/CT_ADDING_ERROR im "
          + "Systemprotokoll, CTM_CT_LIST unverändert")
  void ktAntwortetNicht() throws IOException {
    int closed;
    try (DatagramSocket nobody = new DatagramSocket(0, LOOPBACK)) {
      closed = nobody.getLocalPort();
    }
    SicctTerminals terminals =
        terminals(List.of(new SicctTerminals.Spec("KT-S1", "127.0.0.1")), closed, List.of("1.0.0"));
    terminals.start(channel);
    assertTrue(terminals.ctList().isEmpty());
    assertEquals(0, terminals.terminals().getFirst().slots());
    SystemLog.Entry entry = log.entries(null, null).getFirst();
    assertEquals("CT/CT_ADDING_ERROR", entry.topic());
    assertEquals(SystemLog.Severity.ERR, entry.severity());
    assertEquals("4033", entry.parameters().get("Error"));
    assertEquals("127.0.0.1", entry.parameters().get("IP"));
  }

  @Test
  @DisplayName(
      "TUC_KON_054 ManuallyAdded erneut (LIANA-149, POST /admin/ct-discovery): das beim Start stumme KT "
          + "bekommt sein CT-Object, ein zweiter Lauf behält es; nicht konfiguriert 4007, stumm 4033 im Protokoll")
  void erneutSuchen() throws IOException {
    kt.silent = true;
    SicctTerminals terminals =
        terminals(
            List.of(new SicctTerminals.Spec("KT-S1", "127.0.0.1")),
            kt.udp.getLocalPort(),
            List.of("1.0.0"));
    terminals.start(channel);
    assertTrue(terminals.ctList().isEmpty());
    assertError(ConnectorError.CT_NOT_ANSWERING, () -> terminals.discover("KT-S1"));
    assertEquals(
        2,
        log.entries(null, null).stream()
            .filter(e -> e.topic().equals("CT/CT_ADDING_ERROR"))
            .count());

    kt.silent = false;
    CtObject ct = terminals.discover("KT-S1");
    assertEquals("zugewiesen", ct.snapshot().get("CORRELATION"));
    assertEquals(4, terminals.terminals().getFirst().slots());
    assertEquals(ct, terminals.discover("KT-S1"), "vorhandenes CT-Object bleibt");
    assertError(ConnectorError.INVALID_CT_ID, () -> terminals.discover("KT-99"));
  }

  @Test
  @DisplayName(
      "TIP1-A_4540: eine Dienstbeschreibung einer unbekannten MAC legt ein CT-Object „bekannt“ an, ohne "
          + "Verbindung (TUC_KON_054 Schritt 6 erst ab „zugewiesen“)")
  void angekuendigtesKt() throws Exception {
    SicctTerminals terminals = terminals(List.of(), kt.udp.getLocalPort(), List.of("1.0.0"));
    byte[] announcement =
        ServiceDiscovery.encode(
            new ServiceDiscovery.Announcement(
                LOOPBACK, "AA:BB:CC:00:11:22", "kt-neu", 4742, List.of(0x30)));
    try (DatagramSocket sender = new DatagramSocket()) {
      sender.send(new DatagramPacket(announcement, announcement.length, LOOPBACK, channel.port()));
    }
    long deadline = System.nanoTime() + Duration.ofSeconds(2).toNanos();
    while (terminals.ctList().isEmpty() && System.nanoTime() < deadline) {
      Thread.sleep(10);
    }
    Map<String, Object> ct = terminals.ctList().getFirst().snapshot();
    assertEquals("KT-AABBCC001122", ct.get("CTID"));
    assertEquals("bekannt", ct.get("CORRELATION"));
    assertEquals("kt-neu", ct.get("HOSTNAME"));
    assertEquals(4742, ct.get("TCP_PORT"));
    assertEquals(0, ct.get("SLOTCOUNT"));
    assertEquals(0, connects.get());
  }

  @Test
  @DisplayName(
      "TUC_KON_054 Schritt 2/5: eine Dienstbeschreibung mit der MAC eines konfigurierten KT aktualisiert dessen "
          + "Adresse, CT.CTID bleibt")
  void bekannteMacAktualisiert() throws IOException {
    SicctTerminals terminals =
        terminals(
            List.of(new SicctTerminals.Spec("KT-S1", "127.0.0.1")),
            kt.udp.getLocalPort(),
            List.of("1.0.0"));
    terminals.start(channel);
    terminals.announced(
        new ServiceDiscovery.Announcement(
            LOOPBACK, MAC.toLowerCase(), "kt-umbenannt", kt.tcp.getLocalPort(), List.of(0x30)));
    assertEquals(1, terminals.ctList().size());
    assertEquals("kt-umbenannt", terminals.ct("KT-S1").orElseThrow().hostname());
  }

  @Test
  @DisplayName(
      "TAB_KON_525: abweichende MAC 4035, abweichender Hostname 4036, ManuallyModified ohne Eintrag 4037")
  void abweichungen() throws IOException {
    SicctTerminals terminals = terminals(List.of(), kt.udp.getLocalPort(), List.of("1.0.0"));
    terminals.start(channel);
    assertError(
        ConnectorError.CT_MAC_MISMATCH,
        () ->
            terminals.add(
                SicctTerminals.Mode.MANUALLY_ADDED,
                "KT-X",
                LOOPBACK,
                null,
                "02:00:00:00:00:01",
                null));
    assertError(
        ConnectorError.CT_HOSTNAME_MISMATCH,
        () ->
            terminals.add(
                SicctTerminals.Mode.MANUALLY_ADDED, "KT-X", LOOPBACK, null, MAC, "anderer-name"));
    assertError(
        ConnectorError.CT_LIST_INCONSISTENT,
        () ->
            terminals.add(SicctTerminals.Mode.MANUALLY_MODIFIED, null, LOOPBACK, null, null, null));
    assertTrue(terminals.ctList().isEmpty());
  }

  @Test
  @DisplayName("TUC_KON_055: scheitert die Verbindung zum KT, 4028")
  void verbindungScheitert() throws IOException {
    SicctTerminals terminals =
        new SicctTerminals(
            List.of(),
            (host, port) -> {
              throw new IOException("Handshake abgelehnt");
            },
            new SicctTerminals.Settings(
                kt.udp.getLocalPort(),
                Duration.ofMillis(500),
                Duration.ofSeconds(2),
                List.of("1.0.0")),
            log);
    channel = new DiscoveryChannel(new InetSocketAddress(LOOPBACK, 0), terminals::announced);
    terminals.start(channel);
    ConnectorException e =
        assertThrows(
            ConnectorException.class,
            () ->
                terminals.add(
                    SicctTerminals.Mode.MANUALLY_ADDED, "KT-S1", LOOPBACK, null, null, null));
    assertEquals(ConnectorError.CT_CONNECT_FAILED, e.error());
    assertTrue(e.getMessage().contains("Handshake abgelehnt"), e.getMessage());
  }

  private static void assertError(ConnectorError expected, Executable call) {
    assertEquals(expected, assertThrows(ConnectorException.class, call).error());
  }
}

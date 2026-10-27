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

import de.gematik.liana.kern.event.SystemLog;
import de.gematik.liana.kern.terminal.PinCommand;
import de.gematik.liana.kern.terminal.PinDialog;
import de.gematik.liana.kern.terminal.SlotListener;
import de.gematik.liana.kern.vendor.PeerDeviations;
import java.io.IOException;
import java.io.OutputStream;
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
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.BooleanSupplier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The working connection of a paired card terminal (TUC_KON_050) against a test card terminal
 * without TLS: step 11 reports the inserted cards, slot events 84/85 become CT/SLOT_IN_USE and
 * CT/SLOT_FREE (TIP1-A_4541-02, TIP1-A_4542-02), the heartbeat keeps the connection alive and drops
 * a silent card terminal (TIP1-A_4536), afterwards all slots are free and CT/DISCONNECTED is in the
 * Systemprotokoll (TIP1-A_4537).
 */
class SicctWorkingConnectionTest {

  static final HexFormat HEX = HexFormat.of();
  static final InetAddress LOOPBACK = InetAddress.getLoopbackAddress();
  static final byte[] SECRET = HEX.parseHex("00112233445566778899aabbccddeeff");
  static final Duration INTERVAL = Duration.ofMillis(300);

  /** Test card terminal with pairing for {@link #SECRET}; can go silent and send events. */
  static final class PairedKt implements AutoCloseable {
    final DatagramSocket udp = new DatagramSocket(0, LOOPBACK);
    final ServerSocket tcp = new ServerSocket(0, 5, LOOPBACK);
    volatile boolean mute;
    final List<String> commands = new CopyOnWriteArrayList<>();
    volatile OutputStream current;
    volatile Socket connection;

    /**
     * Response to MODIFY VERIFICATION DATA per spec ({@code 80 19} with CMD DO, control byte {@code
     * 02}).
     */
    volatile String modifyAnswer = "9000";

    int eventSeq = 0xFD00;

    PairedKt() throws IOException {
      daemon(this::discovery);
      daemon(this::sicct);
    }

    private static void daemon(Runnable body) {
      Thread thread = new Thread(body);
      thread.setDaemon(true);
      thread.start();
    }

    private void discovery() {
      byte[] buffer = new byte[512];
      while (!udp.isClosed()) {
        try {
          DatagramPacket enquiry = new DatagramPacket(buffer, buffer.length);
          udp.receive(enquiry);
          List<Tlv> fields =
              Tlv.parse(
                  Tlv.parse(Arrays.copyOf(enquiry.getData(), enquiry.getLength()))
                      .getFirst()
                      .value());
          byte[] p = Tlv.find(fields, 0x82).orElseThrow().value();
          byte[] answer =
              ServiceDiscovery.encode(
                  new ServiceDiscovery.Announcement(
                      LOOPBACK,
                      "02:00:00:4C:49:41",
                      "kt-paired",
                      tcp.getLocalPort(),
                      List.of(0x30)));
          udp.send(
              new DatagramPacket(
                  answer, answer.length, LOOPBACK, ((p[0] & 0xFF) << 8) | (p[1] & 0xFF)));
        } catch (IOException e) {
          // closed
        }
      }
    }

    private void sicct() {
      while (!tcp.isClosed()) {
        try (Socket socket = tcp.accept()) {
          connection = socket;
          current = socket.getOutputStream();
          for (SicctEnvelope c; (c = SicctEnvelope.read(socket.getInputStream())) != null; ) {
            commands.add(HEX.formatHex(c.payload()));
            if (mute) {
              continue;
            }
            byte[] apdu = c.payload();
            byte[] answer =
                switch (apdu[1]) {
                  case 0x28 -> HEX.parseHex("691213001300130c47454d3536353239303833329000");
                  case 0x13 ->
                      switch (apdu[3]) {
                        case 0x63 -> HEX.parseHex("6310810800010002000300048004151500159000");
                        case 0x46 -> GetStatusTest.CTM;
                        case 0x67 -> GetStatusTest.DSPLC;
                        default -> HEX.parseHex("6a86");
                      };
                  case (byte) 0xAA -> {
                    byte[] challenge =
                        Tlv.parse(Arrays.copyOfRange(apdu, 5, 5 + (apdu[4] & 0xFF)))
                            .getFirst()
                            .value();
                    byte[] hash = TerminalAuthenticate.expectedValidation(challenge, SECRET);
                    byte[] r = Arrays.copyOf(hash, hash.length + 2);
                    r[hash.length] = (byte) 0x90;
                    yield r;
                  }
                  case 0x19 ->
                      HEX.parseHex(HEX.formatHex(apdu).contains("5f2f") ? "9000" : modifyAnswer);
                  default -> HEX.parseHex("9000");
                };
            send(new SicctEnvelope(SicctEnvelope.Type.R_COMMAND, c.fu(), c.seq(), answer));
          }
        } catch (IOException e) {
          // connection or server closed
        }
      }
    }

    synchronized void send(SicctEnvelope envelope) throws IOException {
      current.write(envelope.encode());
      current.flush();
    }

    /**
     * The terminal closes the working connection (like kartos behind the Tiger proxy in ehkt.sh,
     * LIANA-112.15).
     */
    void drop() throws IOException {
      connection.close();
    }

    void event(String tlv) throws IOException {
      send(new SicctEnvelope(SicctEnvelope.Type.EVENT, 0, eventSeq++, HEX.parseHex(tlv)));
    }

    @Override
    public void close() throws IOException {
      udp.close();
      tcp.close();
    }
  }

  private PairedKt kt;
  private DiscoveryChannel channel;
  private SicctTerminals terminals;
  private final SystemLog log = new SystemLog(Clock.systemUTC(), 100);
  private final PeerDeviations deviations = new PeerDeviations(false, log);
  private final List<String> slotEvents = new CopyOnWriteArrayList<>();

  @BeforeEach
  void verbinden() throws IOException {
    kt = new PairedKt();
    terminals =
        new SicctTerminals(
            List.of(new SicctTerminals.Spec("KT-W1", "127.0.0.1", SECRET)),
            (host, port) -> new Socket(host, port),
            new SicctTerminals.Settings(
                kt.udp.getLocalPort(),
                Duration.ofMillis(500),
                Duration.ofSeconds(2),
                List.of("1.0.0"),
                "liana",
                INTERVAL,
                3),
            log,
            (certificate, message, signature) -> false,
            deviations);
    terminals
        .terminals()
        .getFirst()
        .addSlotListener(
            new SlotListener() {
              @Override
              public void slotInUse(String ctId, int slot) {
                slotEvents.add("IN_USE " + ctId + "/" + slot);
              }

              @Override
              public void slotFree(String ctId, int slot) {
                slotEvents.add("FREE " + ctId + "/" + slot);
              }
            });
    channel = new DiscoveryChannel(new InetSocketAddress(LOOPBACK, 0), terminals::announced);
    terminals.start(channel);
  }

  @AfterEach
  void beenden() throws IOException {
    terminals.close();
    channel.close();
    kt.close();
  }

  private static void await(BooleanSupplier condition) throws InterruptedException {
    long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
    while (!condition.getAsBoolean()) {
      if (System.nanoTime() > deadline) {
        throw new AssertionError("Bedingung nicht erfüllt");
      }
      Thread.sleep(20);
    }
  }

  @Test
  @DisplayName(
      "TUC_KON_050 Schritt 11: nach VALIDATE meldet die Arbeitsverbindung die gesteckten Karten (Slots 1, 2 "
          + "und 4) als CT/SLOT_IN_USE; 85/84 aus der Ereignisnachricht werden SLOT_FREE/SLOT_IN_USE")
  void slotEreignisse() throws Exception {
    CtObject ct = terminals.ct("KT-W1").orElseThrow();
    assertTrue(ct.connected());
    await(() -> slotEvents.size() == 3);
    assertEquals(List.of("IN_USE KT-W1/1", "IN_USE KT-W1/2", "IN_USE KT-W1/4"), slotEvents);
    assertEquals(List.of(1, 2, 4), terminals.terminals().getFirst().slotsUsed());

    kt.event("85020002");
    kt.event("8402000384020002");
    await(() -> slotEvents.size() == 6);
    assertEquals(
        List.of("FREE KT-W1/2", "IN_USE KT-W1/3", "IN_USE KT-W1/2"), slotEvents.subList(3, 6));
    assertTrue(terminals.terminals().getFirst().cardPresent(3));
    assertEquals("CT/CONNECTED", log.entries(null, null).getFirst().topic());
  }

  @Test
  @DisplayName(
      "TIP1-A_4536/4537: antwortet das KT nicht mehr, trennt LIANA nach CTM_KEEP_ALIVE_TRY_COUNT Heartbeats; "
          + "erst CT/SLOT_FREE je Karte, dann CT/DISCONNECTED, CT.CONNECTED = Nein")
  void stummesKtWirdGetrennt() throws Exception {
    await(() -> slotEvents.size() == 3);
    kt.mute = true;
    await(() -> !terminals.ct("KT-W1").orElseThrow().connected());
    await(() -> slotEvents.size() == 6);
    assertEquals(List.of("FREE KT-W1/1", "FREE KT-W1/2", "FREE KT-W1/4"), slotEvents.subList(3, 6));
    await(
        () -> log.entries(null, null).stream().anyMatch(e -> e.topic().equals("CT/DISCONNECTED")));
    SystemLog.Entry disconnected =
        log.entries(null, null).stream()
            .filter(e -> e.topic().equals("CT/DISCONNECTED"))
            .findFirst()
            .orElseThrow();
    assertEquals("KT-W1", disconnected.parameters().get("CtID"));
    assertFalse(terminals.terminals().getFirst().cardPresent(1));
  }

  @Test
  @DisplayName(
      "TIP1-A_4538-02 / TIP1-A_4540: schließt das KT die Verbindung, schickt LIANA im Takt "
          + "CTM_SERVICE_DISCOVERY_CYCLE eine Dienstanfrage als Unicast und verbindet das aktive KT wieder "
          + "(TUC_KON_050): CT/CONNECTED, die Karten erneut als CT/SLOT_IN_USE")
  void getrenntesKtWirdWiederVerbunden() throws Exception {
    terminals.close();
    channel.close();
    List<String> events = new CopyOnWriteArrayList<>();
    terminals =
        new SicctTerminals(
            List.of(new SicctTerminals.Spec("KT-W1", "127.0.0.1", SECRET)),
            (host, port) -> new Socket(host, port),
            new SicctTerminals.Settings(
                kt.udp.getLocalPort(),
                Duration.ofMillis(500),
                Duration.ofSeconds(2),
                List.of("1.0.0"),
                "liana",
                INTERVAL,
                3,
                Duration.ofMillis(300)),
            log,
            (certificate, message, signature) -> false,
            deviations);
    terminals
        .terminals()
        .getFirst()
        .addSlotListener(
            new SlotListener() {
              @Override
              public void slotInUse(String ctId, int slot) {
                events.add("IN_USE " + ctId + "/" + slot);
              }

              @Override
              public void slotFree(String ctId, int slot) {
                events.add("FREE " + ctId + "/" + slot);
              }
            });
    channel = new DiscoveryChannel(new InetSocketAddress(LOOPBACK, 0), terminals::announced);
    terminals.start(channel);
    await(() -> events.size() == 3);

    kt.drop();
    await(() -> events.size() >= 6);
    assertEquals(List.of("FREE KT-W1/1", "FREE KT-W1/2", "FREE KT-W1/4"), events.subList(3, 6));
    await(() -> events.size() == 9);
    assertEquals(
        List.of("IN_USE KT-W1/1", "IN_USE KT-W1/2", "IN_USE KT-W1/4"), events.subList(6, 9));
    assertTrue(terminals.ct("KT-W1").orElseThrow().connected());
    List<String> connections =
        log.entries(null, null).stream()
            .map(SystemLog.Entry::topic)
            .filter(t -> t.equals("CT/CONNECTED") || t.equals("CT/DISCONNECTED"))
            .toList()
            .reversed();
    assertEquals(
        List.of("CT/CONNECTED", "CT/DISCONNECTED", "CT/CONNECTED"),
        connections.subList(connections.size() - 3, connections.size()),
        "davor die erste Instanz");
  }

  @Test
  @DisplayName(
      "SICCT §6.2.4.5: KEEP ALIVE des KT zählt als Lebenszeichen – ohne Antworten, aber mit KEEP ALIVE bleibt "
          + "die Verbindung")
  void keepAliveDesKtGenuegt() throws Exception {
    await(() -> slotEvents.size() == 3);
    kt.mute = true;
    long end = System.nanoTime() + INTERVAL.multipliedBy(6).toNanos();
    while (System.nanoTime() < end) {
      kt.event("80020000");
      Thread.sleep(INTERVAL.toMillis() / 3);
    }
    assertTrue(terminals.ct("KT-W1").orElseThrow().connected());
  }

  @Test
  @DisplayName(
      "TIP1-A_4536, SICCT §6.2.4.5: auch während das KT KEEP ALIVE schickt, sendet LIANA spätestens nach "
          + "CTM_KEEP_ALIVE_INTERVAL ohne Kommando GET STATUS; sonst baut ein KT nach 120 s mit TERMINAL SIGN OFF ab")
  void heartbeatTrotzKeepAlive() throws Exception {
    await(() -> slotEvents.size() == 3);
    String getStatus = HEX.formatHex(GetStatus.command(GetStatus.CTS_DO));
    long before = kt.commands.stream().filter(getStatus::equals).count();
    long end = System.nanoTime() + INTERVAL.multipliedBy(6).toNanos();
    while (System.nanoTime() < end) {
      kt.event("80020000");
      Thread.sleep(INTERVAL.toMillis() / 3);
    }
    long heartbeats = kt.commands.stream().filter(getStatus::equals).count() - before;
    assertTrue(heartbeats >= 3, "GET STATUS in 6 Intervallen mit KEEP ALIVE: " + heartbeats);
    assertTrue(terminals.ct("KT-W1").orElseThrow().connected());
  }

  private static final PinCommand CHANGE =
      new PinCommand(
          HEX.parseHex("00240001"),
          PinCommand.Mode.OLD_NEW,
          List.of("alt", "neu", "nochmal"),
          PinCommand.CHANGED,
          PinDialog.WRONG,
          PinCommand.MISMATCH_TEXT);

  private List<String> modifyCommands() {
    return kt.commands.stream().filter(c -> c.startsWith("80190")).toList();
  }

  private List<SystemLog.Entry> deviationLog() {
    return log.entries(null, null).stream()
        .filter(e -> e.topic().equals(PeerDeviations.TOPIC))
        .toList();
  }

  @Test
  @DisplayName(
      "LIANA-127 SICCT §5.20.6: ein KT nach Spec beantwortet MODIFY VERIFICATION DATA mit dem Statuswort der "
          + "Karte (9000) bzw. 6402; ein Kommando, kein Eintrag LIANA/DEVIATION")
  void modifyVerificationDataNachSpec() throws Exception {
    await(() -> slotEvents.size() == 3);
    SicctTerminal terminal = terminals.terminals().getFirst();
    assertEquals("9000", HEX.formatHex(terminal.pinCommand(1, CHANGE)));
    kt.modifyAnswer = "6402";
    assertEquals("6402", HEX.formatHex(terminal.pinCommand(1, CHANGE)));
    assertEquals(2, modifyCommands().size());
    assertTrue(deviationLog().isEmpty());
  }

  @Test
  @DisplayName(
      "LIANA-126/127 ohne strict: 6700 auf das Kommando nach Spec ist KARTOS_MODIFY_VERIFICATION_DATA – "
          + "TUC_KON_271 Op/Warning LIANA/DEVIATION, dann dasselbe Kommando im kartos-Format (5F2F), dessen "
          + "Statuswort gilt")
  void kartosToleriert() throws Exception {
    await(() -> slotEvents.size() == 3);
    kt.modifyAnswer = "6700";
    assertEquals("9000", HEX.formatHex(terminals.terminals().getFirst().pinCommand(1, CHANGE)));
    List<String> sent = modifyCommands();
    assertEquals(2, sent.size());
    assertTrue(sent.get(0).contains("02060e0024000110"), sent.get(0));
    assertTrue(sent.get(1).contains("5f2f0602080102040c"), sent.get(1));
    SystemLog.Entry entry = deviationLog().getFirst();
    assertEquals(SystemLog.Severity.WARN, entry.severity());
    assertEquals("KARTOS_MODIFY_VERIFICATION_DATA", entry.parameters().get("Deviation"));
    assertEquals("KT-W1", entry.parameters().get("Peer"));
    assertEquals("6700", entry.parameters().get("StatusWord"));
  }

  @Test
  @DisplayName(
      "LIANA-126/127 mit strict: kein Ausweichen, IOException (TUC_KON_019/021 → 4044), Eintrag als Error")
  void kartosStrict() throws Exception {
    await(() -> slotEvents.size() == 3);
    kt.modifyAnswer = "6700";
    deviations.setStrict(true);
    assertThrows(IOException.class, () -> terminals.terminals().getFirst().pinCommand(1, CHANGE));
    assertEquals(1, modifyCommands().size());
    SystemLog.Entry entry = deviationLog().getFirst();
    assertEquals(SystemLog.Severity.ERR, entry.severity());
    assertEquals("abgewiesen (strict)", entry.parameters().get("Action"));
  }
}

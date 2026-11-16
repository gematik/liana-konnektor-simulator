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

import static org.assertj.core.api.Assertions.assertThat;

import com.sun.net.httpserver.HttpServer;
import de.gematik.rbellogger.RbelLogger;
import de.gematik.rbellogger.configuration.RbelConfiguration;
import de.gematik.rbellogger.data.RbelElement;
import de.gematik.rbellogger.data.RbelMessageMetadata;
import de.gematik.rbellogger.data.core.RbelTcpIpMessageFacet;
import de.gematik.rbellogger.data.core.TracingMessagePairFacet;
import de.gematik.rbellogger.util.RbelSocketAddress;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * LIANA-27: card APDUs via traffic push. LIANA runs with {@code liana.trace.push-url} pointing to a
 * stub that passes the pushes to Rbel the way the Tiger proxy's TrafficPushController does ({@code
 * parseMessage} with sender, receiver, time). At startup LIANA reads the inserted egk-valid and
 * smcb-valid (TUC_KON_001) – those are the APDUs. Over SICCT (LIANA-195) LIANA pushes the envelopes
 * as on the wire: terminal commands and events in between, the CT's TCP port instead of the slot.
 */
class TrafficPushIT {

  /**
   * The CT in the trace (LIANA-195.04): a fake CT as {@code <name>-KT-01:<Slot>}, an eHealth CT
   * under its CT ID with IP and port, because the IT configures no host name for it.
   */
  static final String KT = LianaProcess.sicct() ? "KT-01" : "konnektor-KT-01";

  /** A push as the Tiger proxy receives it. */
  record Pushed(
      byte[] body,
      String sender,
      String receiver,
      String timestamp,
      String uuid,
      String responseTo) {
    boolean card() {
      return sender.startsWith(KT) || receiver.startsWith(KT);
    }

    /** SICCT address (FU): 0 is the terminal itself. */
    int fu() {
      return ((body[1] & 0xFF) << 8) | (body[2] & 0xFF);
    }
  }

  private static final LinkedBlockingQueue<Pushed> PUSHED = new LinkedBlockingQueue<>();
  private static HttpServer stub;
  private static LianaProcess liana;
  private static List<Pushed> pushes;
  private static List<RbelElement> messages;

  @BeforeAll
  static void start() throws Exception {
    Assumptions.assumeTrue(
        LianaProcess.kartosBin().isPresent(),
        "kein eingechecktes kartos für dieses System: LIANA_KARTOS_BIN setzen");
    stub = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
    stub.createContext(
        "/traffic",
        exchange -> {
          var headers = exchange.getRequestHeaders();
          PUSHED.add(
              new Pushed(
                  exchange.getRequestBody().readAllBytes(),
                  headers.getFirst("tgr-sender"),
                  headers.getFirst("tgr-receiver"),
                  headers.getFirst("tgr-timestamp"),
                  headers.getFirst("tgr-uuid"),
                  headers.getFirst("tgr-response-to")));
          exchange.sendResponseHeaders(200, -1);
          exchange.close();
        });
    stub.start();
    liana =
        LianaProcess.start(
            "TrafficPushIT",
            List.of("liana.trace.push-url=http://localhost:" + stub.getAddress().getPort()));
    pushes = awaitPushes(4).stream().filter(Pushed::card).toList();
    messages = parse(pushes);
  }

  @AfterAll
  static void stop() {
    if (liana != null) {
      liana.close();
    }
    if (stub != null) {
      stub.stop(0);
    }
  }

  /** Waits until at least {@code count} pushes have arrived and nothing more comes for a while. */
  private static List<Pushed> awaitPushes(int count) throws InterruptedException {
    List<Pushed> pushes = new ArrayList<>();
    var deadline = Instant.now().plus(Duration.ofSeconds(20));
    while (Instant.now().isBefore(deadline)) {
      Pushed next = PUSHED.poll(500, TimeUnit.MILLISECONDS);
      if (next != null) {
        pushes.add(next);
      } else if (pushes.size() >= count) {
        return pushes;
      }
    }
    throw new AssertionError("nur " + pushes.size() + " Pushes angekommen");
  }

  /**
   * Like {@code TrafficPushController.postNewMessage}, with SICCT parsing like {@code
   * activateRbelParsingFor: [sicct]}.
   */
  private static List<RbelElement> parse(List<Pushed> pushes) {
    var converter =
        RbelLogger.build(new RbelConfiguration().activateConversionFor("sicct")).getRbelConverter();
    return pushes.stream()
        .map(
            push ->
                converter.parseMessage(
                    push.body(),
                    new RbelMessageMetadata()
                        .withSender(RbelSocketAddress.fromString(push.sender()).orElse(null))
                        .withReceiver(RbelSocketAddress.fromString(push.receiver()).orElse(null))
                        .withTransmissionTime(ZonedDateTime.parse(push.timestamp()))))
        .toList();
  }

  private static Object value(RbelElement message, String rbelPath) {
    return message
        .findElement(rbelPath)
        .flatMap(RbelElement::seekValue)
        .orElseThrow(
            () -> new AssertionError(rbelPath + " fehlt in\n" + message.printTreeStructure()));
  }

  private static String hex(RbelElement message, String rbelPath) {
    return message
        .findElement(rbelPath)
        .map(e -> HexFormat.of().withUpperCase().formatHex(e.getRawContent()))
        .orElseThrow(
            () -> new AssertionError(rbelPath + " fehlt in\n" + message.printTreeStructure()));
  }

  /** Index of the response to the push at {@code command}, by {@code tgr-response-to}. */
  private static int responseTo(int command) {
    String uuid = pushes.get(command).uuid();
    for (int i = command + 1; i < pushes.size(); i++) {
      if (uuid.equals(pushes.get(i).responseTo())) {
        return i;
      }
    }
    throw new AssertionError("keine Antwort auf Push " + command);
  }

  /** Indices of the C-commands to a card, without terminal commands (FU 0). */
  private static List<Integer> cardCommands() {
    List<Integer> commands = new ArrayList<>();
    for (int i = 0; i < pushes.size(); i++) {
      if (hex(messages.get(i), "$.messageType").equals("6B") && pushes.get(i).fu() != 0) {
        commands.add(i);
      }
    }
    return commands;
  }

  private static int firstSelect() {
    return cardCommands().stream()
        .filter(i -> "SELECT".equals(value(messages.get(i), "$.command.name")))
        .findFirst()
        .orElseThrow();
  }

  @Test
  @DisplayName(
      "Rbel zerlegt das Kommando nach ISO 7816-4 (Tiger 4.5.0): die erste APDU ist SELECT eGK-Root, "
          + "Fall 3 kurz mit Lc und Daten, ohne Le")
  void kommando() {
    RbelElement select = messages.get(firstSelect());
    assertThat(hex(select, "$.messageType")).isEqualTo("6B");
    assertThat(value(select, "$.command.name")).isEqualTo("SELECT");
    assertThat(hex(select, "$.command.cla")).isEqualTo("00");
    assertThat(hex(select, "$.command.ins")).isEqualTo("A4");
    assertThat(hex(select, "$.command.p1")).isEqualTo("04");
    assertThat(hex(select, "$.command.p2")).isEqualTo("0C");
    assertThat(value(select, "$.command.case")).isEqualTo("3S");
    assertThat(hex(select, "$.command.data")).startsWith("D2760001448000");
    assertThat(value(select, "$.command.lc")).isEqualTo(hex(select, "$.command.data").length() / 2);
    assertThat(select.findElement("$.command.le")).isEmpty();
  }

  @Test
  @DisplayName("Kein Kommando ist <unknown>, und READ BINARY trägt sein Le als eigenes Element")
  void kommandonamen() {
    var commands = cardCommands().stream().map(messages::get).toList();
    assertThat(commands)
        .allSatisfy(c -> assertThat(String.valueOf(value(c, "$.command.name"))).isNotBlank());
    assertThat(commands).noneMatch(c -> c.printTreeStructure().contains("<unknown>"));
    assertThat(commands)
        .filteredOn(c -> "READ BINARY".equals(value(c, "$.command.name")))
        .isNotEmpty()
        .allSatisfy(c -> assertThat(c.findElement("$.command.le")).isPresent());
  }

  @Test
  @DisplayName(
      "Rbel zerlegt die Antwort: Typ R_RESPONSE, Statuswort 9000 als eigenes Element mit Bedeutung")
  void antwort() {
    RbelElement response = messages.get(responseTo(firstSelect()));
    assertThat(hex(response, "$.messageType")).isEqualTo("83");
    assertThat(hex(response, "$.response.sw")).isEqualTo("9000");
    assertThat(value(response, "$.response.sw.meaning")).isEqualTo("Normal processing");
  }

  @Test
  @DisplayName(
      "Absender und Empfänger: konnektor → konnektor-KT-01:<Slot> und zurück (eGK in Slot 1, SMC-B in Slot 2; "
          + "über SICCT konnektor/IP:Port → KT-01/IP:<TCP-Port>), jede Antwort trägt tgr-response-to ihres "
          + "Kommandos")
  void adressen() {
    var slots = List.of(1, 2);
    for (int i : cardCommands()) {
      int j = responseTo(i);
      var command = messages.get(i).getFacetOrFail(RbelTcpIpMessageFacet.class);
      var response = messages.get(j).getFacetOrFail(RbelTcpIpMessageFacet.class);
      assertThat(command.getSenderAddress().printHostname()).isEqualTo("konnektor");
      assertThat(command.getReceiverAddress().printHostname()).isEqualTo(KT);
      if (!LianaProcess.sicct()) {
        assertThat(command.getReceiverAddress().getPort()).isIn(slots);
      }
      assertThat(response.getSenderAddress().printHostname()).isEqualTo(KT);
      assertThat(response.getSenderAddress().getPort())
          .isEqualTo(command.getReceiverAddress().getPort());
      assertThat(response.getReceiverAddress().printHostname()).isEqualTo("konnektor");
      assertThat(hex(messages.get(j), "$.messageType")).isEqualTo("83");
    }
  }

  @Test
  @DisplayName(
      "Paarung: Rbel ordnet jede Antwort ihrem Kommando zu (SICCT-Sequenznummer und Adresse), "
          + "auch bei gepushtem Verkehr")
  void paarung() {
    for (int i : cardCommands()) {
      Optional<RbelElement> paired =
          messages
              .get(responseTo(i))
              .getFacet(TracingMessagePairFacet.class)
              .map(TracingMessagePairFacet::getRequest);
      assertThat(paired).as("Antwort auf %d", i).containsSame(messages.get(i));
    }
  }
}

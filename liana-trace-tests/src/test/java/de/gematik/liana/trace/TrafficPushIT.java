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
 * smcb-valid (TUC_KON_001) – those are the APDUs.
 */
class TrafficPushIT {

  /** A push as the Tiger proxy receives it. */
  record Pushed(byte[] body, String sender, String receiver, String timestamp) {}

  private static final LinkedBlockingQueue<Pushed> PUSHED = new LinkedBlockingQueue<>();
  private static HttpServer stub;
  private static LianaProcess liana;
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
                  headers.getFirst("tgr-timestamp")));
          exchange.sendResponseHeaders(200, -1);
          exchange.close();
        });
    stub.start();
    liana =
        LianaProcess.start(
            "TrafficPushIT",
            List.of("liana.trace.push-url=http://localhost:" + stub.getAddress().getPort()));
    messages = parse(awaitPushes(4));
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

  private static String hex(RbelElement message, String rbelPath) {
    return message
        .findElement(rbelPath)
        .map(e -> HexFormat.of().withUpperCase().formatHex(e.getRawContent()))
        .orElseThrow(
            () -> new AssertionError(rbelPath + " fehlt in\n" + message.printTreeStructure()));
  }

  @Test
  @DisplayName(
      "Rbel zerlegt das Kommando: CLA, INS, P1, P2 per RbelPath – die erste APDU ist SELECT eGK-Root")
  void kommando() {
    RbelElement select = messages.getFirst();
    assertThat(hex(select, "$.messageType")).isEqualTo("6B");
    assertThat(hex(select, "$.command.header.cla")).isEqualTo("00");
    assertThat(hex(select, "$.command.header.ins")).isEqualTo("A4");
    assertThat(hex(select, "$.command.header.p1")).isEqualTo("04");
    assertThat(hex(select, "$.command.header.p2")).isEqualTo("0C");
    assertThat(hex(select, "$.command.body")).startsWith("07D2760001448000");
  }

  @Test
  @DisplayName(
      "Rbel zerlegt die Antwort: Typ R_RESPONSE, Statuswort 9000 am Ende des Kommandoteils")
  void antwort() {
    RbelElement response = messages.get(1);
    assertThat(hex(response, "$.messageType")).isEqualTo("83");
    assertThat(hex(response, "$.command")).endsWith("9000");
  }

  @Test
  @DisplayName(
      "Absender und Empfänger: liana → KT-01:<Slot> und zurück (eGK in Slot 1, SMC-B in Slot 2; über SICCT "
          + "auch die gSMC-KT, die kartos terminal in Slot 3 führt), Kommando und Antwort abwechselnd")
  void adressen() {
    var slots = LianaProcess.sicct() ? List.of(1, 2, 3) : List.of(1, 2);
    for (int i = 0; i + 1 < messages.size(); i += 2) {
      var command = messages.get(i).getFacetOrFail(RbelTcpIpMessageFacet.class);
      var response = messages.get(i + 1).getFacetOrFail(RbelTcpIpMessageFacet.class);
      assertThat(command.getSenderAddress().printHostname()).isEqualTo("liana");
      assertThat(command.getReceiverAddress().printHostname()).isEqualTo("KT-01");
      assertThat(command.getReceiverAddress().getPort()).isIn(slots);
      assertThat(response.getSenderAddress().printHostname()).isEqualTo("KT-01");
      assertThat(response.getSenderAddress().getPort())
          .isEqualTo(command.getReceiverAddress().getPort());
      assertThat(response.getReceiverAddress().printHostname()).isEqualTo("liana");
      assertThat(hex(messages.get(i), "$.messageType")).isEqualTo("6B");
      assertThat(hex(messages.get(i + 1), "$.messageType")).isEqualTo("83");
    }
  }

  @Test
  @DisplayName("Paarung (AC5): ob Rbel die Antwort dem Kommando zuordnet, steht im Log des Tests")
  @SuppressWarnings("java:S2699") // AC5 only asks for the result in the test log, see DisplayName
  void paarung() {
    var response = messages.get(1);
    Optional<RbelElement> paired =
        response.getFacet(TracingMessagePairFacet.class).map(TracingMessagePairFacet::getRequest);
    System.out.println(
        "LIANA-27 Paarung: Antwort gepaart = "
            + paired.isPresent()
            + (paired.isPresent()
                ? ", mit Kommando = " + (paired.get() == messages.getFirst())
                : ""));
  }
}

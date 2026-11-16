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

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpServer;
import de.gematik.rbellogger.RbelLogger;
import de.gematik.rbellogger.data.RbelElement;
import de.gematik.rbellogger.data.RbelMessageMetadata;
import de.gematik.rbellogger.util.RbelSocketAddress;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Predicate;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * LIANA-195: LIANA pushes SOAP, CETP and UFS traffic as supplementary messages; Rbel takes them
 * apart like the Tiger proxy, and {@code tgr-response-to} pairs request and response.
 */
class TracePushIT {

  record Pushed(Headers headers, byte[] body) {
    String header(String name) {
      return headers.getFirst(name);
    }

    String text() {
      return new String(body, StandardCharsets.UTF_8);
    }
  }

  private static final String VSD = "http://ws.gematik.de/conn/vsds/VSDService/v5.2";
  private static final String NO_UPDATE =
      """
      <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>\
      <r:GetUpdateFlagsResponse xmlns:r="http://ws.gematik.de/cm/uf/CmUfServiceResponse/v2.0" \
      xmlns:CM="http://ws.gematik.de/cm/common/CmCommon/v2.0"><CM:ServiceReceipt><CM:ServiceLocalization>\
      <CM:Type>UFS</CM:Type><CM:Provider>109500969</CM:Provider></CM:ServiceLocalization>\
      <CM:Receipt>UHLDvGZ6aWZmZXIgZGVzIFVGUw==</CM:Receipt></CM:ServiceReceipt>\
      </r:GetUpdateFlagsResponse></soap:Body></soap:Envelope>""";

  private static final List<Pushed> PUSHED = new CopyOnWriteArrayList<>();
  private static HttpServer stub;
  private static HttpServer ufs;
  private static LianaProcess liana;
  private static Pssim pssim;

  @BeforeAll
  static void start() throws Exception {
    Assumptions.assumeTrue(
        LianaProcess.kartosBin().isPresent(),
        "kein eingechecktes kartos für dieses System: LIANA_KARTOS_BIN setzen");
    stub = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
    stub.createContext(
        "/traffic",
        exchange -> {
          PUSHED.add(
              new Pushed(exchange.getRequestHeaders(), exchange.getRequestBody().readAllBytes()));
          exchange.sendResponseHeaders(200, -1);
          exchange.close();
        });
    stub.start();
    ufs = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    ufs.createContext(
        "/ufs",
        exchange -> {
          exchange.getRequestBody().readAllBytes();
          byte[] body = NO_UPDATE.getBytes(StandardCharsets.UTF_8);
          exchange.getResponseHeaders().add("Content-Type", "text/xml; charset=utf-8");
          exchange.sendResponseHeaders(200, body.length);
          exchange.getResponseBody().write(body);
          exchange.close();
        });
    ufs.start();
    liana =
        LianaProcess.start(
            "TracePushIT",
            List.of(
                "liana.trace.push-url=http://localhost:" + stub.getAddress().getPort(),
                "liana.vsdm.online.sources=ufs",
                "liana.vsdm.online.ufs.endpoints[0].url=http://127.0.0.1:"
                    + ufs.getAddress().getPort()
                    + "/ufs",
                "liana.vsdm.online.ufs.retry-after=0s"));
    pssim = new Pssim(liana);
  }

  @AfterAll
  static void stop() {
    if (liana != null) {
      liana.close();
    }
    if (stub != null) {
      stub.stop(0);
    }
    if (ufs != null) {
      ufs.stop(0);
    }
  }

  /** Waits for the first push after {@code from} that {@code matches}. */
  private static Pushed await(int from, Predicate<Pushed> matches) throws InterruptedException {
    Instant deadline = Instant.now().plus(Duration.ofSeconds(10));
    while (Instant.now().isBefore(deadline)) {
      Optional<Pushed> found = PUSHED.stream().skip(from).filter(matches).findFirst();
      if (found.isPresent()) {
        return found.get();
      }
      Thread.sleep(100);
    }
    throw new AssertionError("kein passender Push, " + (PUSHED.size() - from) + " andere");
  }

  private static Pushed responseTo(int from, Pushed request) throws InterruptedException {
    return await(from, p -> request.header("tgr-uuid").equals(p.header("tgr-response-to")));
  }

  /** Like {@code TrafficPushController.postNewMessage}. */
  private static RbelElement rbel(Pushed push) {
    return RbelLogger.build()
        .getRbelConverter()
        .parseMessage(
            push.body(),
            new RbelMessageMetadata()
                .withSender(RbelSocketAddress.fromString(push.header("tgr-sender")).orElse(null))
                .withReceiver(
                    RbelSocketAddress.fromString(push.header("tgr-receiver")).orElse(null))
                .withTransmissionTime(ZonedDateTime.parse(push.header("tgr-timestamp"))));
  }

  private static String text(RbelElement message, String rbelPath) {
    return message
        .findElement(rbelPath)
        .map(RbelElement::getRawStringContent)
        .orElseThrow(
            () -> new AssertionError(rbelPath + " fehlt in\n" + message.printTreeStructure()));
  }

  @Test
  @DisplayName(
      "SOAP: GetCards als HTTP-Anfrage mit zerlegtem SOAP-Body, die Antwort gepaart, beide ergänzend")
  void soap() throws Exception {
    int from = PUSHED.size();
    pssim.cardHandle("EGK", "KT-01", 1);
    Pushed request = await(from, p -> p.text().contains(":GetCards "));
    Pushed response = responseTo(from, request);

    assertThat(request.header("tgr-supplementary")).isEqualTo("true");
    RbelElement rbelRequest = rbel(request);
    assertThat(text(rbelRequest, "$.method")).isEqualTo("POST");
    assertThat(text(rbelRequest, "$.path")).isEqualTo("/ws/EventService");
    assertThat(rbelRequest.findElement("$..GetCards")).isPresent();
    RbelElement rbelResponse = rbel(response);
    assertThat(text(rbelResponse, "$.responseCode")).isEqualTo("200");
    assertThat(rbelResponse.findElement("$..GetCardsResponse")).isPresent();
  }

  @Test
  @DisplayName(
      "UFS: ReadVSD mit Onlineprüfung schickt GetUpdateFlags an den UFS; Anfrage und Antwort zerlegt "
          + "und gepaart, liana → UFS und zurück")
  void ufs() throws Exception {
    String egk = pssim.cardHandle("EGK", "KT-01", 1);
    String smcb = pssim.cardHandle("SMC-B", "KT-01", 2);
    pssim.verifyPin(smcb, "PIN.SMC");
    int from = PUSHED.size();
    pssim.soap(
        "VSDService",
        VSD,
        "ReadVSD",
        Pssim.envelope(
            VSD,
            "ReadVSD",
            "",
            "<ns4:EhcHandle>"
                + egk
                + "</ns4:EhcHandle><ns4:HpcHandle>"
                + smcb
                + "</ns4:HpcHandle><ns4:PerformOnlineCheck>true</ns4:PerformOnlineCheck>"
                + "<ns4:ReadOnlineReceipt>true</ns4:ReadOnlineReceipt>"
                + Pssim.CONTEXT));
    String server = "127.0.0.1:" + ufs.getAddress().getPort();
    Pushed request = await(from, p -> server.equals(p.header("tgr-receiver")));
    Pushed response = responseTo(from, request);

    // LIANA-195.04: name/IP:Port of LIANA's socket
    assertThat(request.header("tgr-sender")).matches("konnektor/127\\.0\\.0\\.1:\\d+");
    assertThat(response.header("tgr-sender")).isEqualTo(server);
    assertThat(rbel(request).findElement("$..GetUpdateFlags")).isPresent();
    assertThat(text(rbel(response), "$.responseCode")).isEqualTo("200");
    assertThat(rbel(response).findElement("$..GetUpdateFlagsResponse")).isPresent();
  }

  @Test
  @DisplayName(
      "CETP: das Ereignis CARD/INSERTED an die Ereignissenke, Rbel zerlegt Länge und Event-XML")
  void cetp() throws Exception {
    Assumptions.assumeFalse(
        LianaProcess.sicct(),
        "im SICCT-Aufbau gehört KT-02 keinem Arbeitsplatz, das Ereignis geht an keine Senke");
    try (ServerSocket sink = new ServerSocket(0, 10, InetAddress.getLoopbackAddress())) {
      sink.setSoTimeout(10_000);
      pssim.subscribe("cetp://127.0.0.1:" + sink.getLocalPort(), "CARD/INSERTED");
      int from = PUSHED.size();
      HttpClient.newHttpClient()
          .send(
              HttpRequest.newBuilder(
                      URI.create(liana.adminUrl() + "/admin/terminals/KT-02/slots/1"))
                  .header("Content-Type", "application/json")
                  .PUT(HttpRequest.BodyPublishers.ofString("{\"image\":\"egk-valid\"}"))
                  .build(),
              HttpResponse.BodyHandlers.discarding());
      try (Socket ignored = sink.accept()) {
        String receiver = "127.0.0.1:" + sink.getLocalPort();
        Pushed event = await(from, p -> receiver.equals(p.header("tgr-receiver")));

        assertThat(event.header("tgr-sender")).matches("konnektor/127\\.0\\.0\\.1:\\d+");
        assertThat(event.header("tgr-response-to")).isNull();
        RbelElement cetp = rbel(event);
        assertThat(cetp.findElement("$.messageLength")).isPresent();
        assertThat(text(cetp, "$.body..Topic.text")).isEqualTo("CARD/INSERTED");
      }
    } finally {
      pssim.deleteSubscriptions();
    }
  }
}

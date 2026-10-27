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
package de.gematik.liana.admin;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.adapter.fake.FakeTerminals;
import de.gematik.liana.kern.access.Context;
import de.gematik.liana.kern.card.CardList;
import de.gematik.liana.kern.card.CardSessions;
import de.gematik.liana.kern.card.PinVerification;
import de.gematik.liana.kern.event.Subscriptions;
import de.gematik.liana.kern.event.SystemLog;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.path.json.JsonPath;
import io.vertx.core.Vertx;
import jakarta.inject.Inject;
import java.net.ServerSocket;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** LIANA-150: push of the Admin API as server-sent events under {@code GET /admin/events}. */
@QuarkusTest
class AdminEventsTest {

  private static final Context WP1 = new Context("M1", "CS1", "WP1", null);

  @Inject AdminServer server;

  @Inject AdminEvents events;

  @Inject Vertx vertx;

  @Inject SystemLog systemLog;

  @Inject CardList cards;

  @Inject PinVerification pins;

  @Inject FakeTerminals fakeTerminals;

  @Inject Subscriptions subscriptions;

  @Inject CardSessions cardSessions;

  private final List<SseClient> clients = new ArrayList<>();

  @AfterEach
  void schliessen() throws Exception {
    for (SseClient client : clients) {
      client.close();
    }
    given().port(server.port()).post("/admin/reset").then().statusCode(200);
    // The server reports closing asynchronously; the next test should have the full limit
    awaitOpenStreams(0);
  }

  private SseClient open(boolean https, String lastEventId) throws Exception {
    SseClient client = SseClient.open(vertx, server.port(), https, lastEventId);
    clients.add(client);
    return client;
  }

  /** Waits until the stream is registered: a heartbeat only goes to registered streams. */
  private SseClient connected(boolean https, String lastEventId) throws Exception {
    SseClient client = open(https, lastEventId);
    assertEquals(200, client.status());
    events.heartbeat();
    client.next(f -> "heartbeat".equals(f.comment()), Duration.ofSeconds(5));
    return client;
  }

  private static JsonPath data(SseClient.Frame frame) {
    return new JsonPath(frame.data());
  }

  @ParameterizedTest(name = "https={0}")
  @ValueSource(booleans = {false, true})
  @DisplayName(
      "Karte stecken über die API: card CARD/INSERTED (TUC_KON_256), log (TUC_KON_271) und terminal mit dem KT "
          + "danach, binnen 500 ms; per HTTP und HTTPS auf dem Management-Port (decision-017)")
  void karteGesteckt(boolean https) throws Exception {
    SseClient client = connected(https, null);
    assertTrue(client.contentType().startsWith("text/event-stream"), client.contentType());
    // The first REST Assured request of the JVM is slow on the client side; it must not count
    given().port(server.port()).get("/admin/terminals/KT-02").then().statusCode(200);
    long start = System.nanoTime();
    given()
        .port(server.port())
        .contentType("application/json")
        .body("{\"image\":\"egk-valid\"}")
        .put("/admin/terminals/KT-02/slots/1")
        .then()
        .statusCode(200);

    // Order between the kinds is not fixed (the Systemprotokoll listens before the admin events)
    SseClient.Frame card = null;
    SseClient.Frame terminal = null;
    SseClient.Frame log = null;
    while (card == null || terminal == null || log == null) {
      SseClient.Frame frame = client.next(f -> f.event() != null, Duration.ofSeconds(5));
      JsonPath data = data(frame);
      if ("card".equals(frame.event()) && "CARD/INSERTED".equals(data.getString("topic"))) {
        card = frame;
        long millis = (System.nanoTime() - start) / 1_000_000;
        assertTrue(millis < 500, millis + " ms");
      } else if ("terminal".equals(frame.event()) && "KT-02".equals(data.getString("id"))) {
        terminal = frame;
      } else if ("log".equals(frame.event()) && "CARD/INSERTED".equals(data.getString("topic"))) {
        log = frame;
      }
    }
    assertEquals("KT-02", data(card).getString("parameters.CtID"));
    assertNotNull(card.id());
    assertEquals("egk-valid", data(terminal).getString("terminal.slots[0].image"));
    assertEquals("KT-02", data(log).getString("parameters.CtID"));
  }

  @Test
  @DisplayName(
      "card auch für CARD/PIN/VERIFY_* (TUC_KON_256, nicht im Systemprotokoll); terminal für Anzeige, "
          + "Störung und PIN-Script; state für Profil, Einstellungen und Reset")
  void arten() throws Exception {
    SseClient client = connected(false, null);
    String smcb = cards.card("KT-01", 2).orElseThrow().cardHandle();
    pins.verify(WP1, smcb, "PIN.SMC");
    assertEquals("CARD/PIN/VERIFY_STARTED", data(client.next("card")).getString("topic"));
    assertEquals("CARD/PIN/VERIFY_FINISHED", data(client.next("card")).getString("topic"));

    CompletableFuture<Boolean> request =
        CompletableFuture.supplyAsync(
            () -> {
              try {
                return fakeTerminals
                    .terminal("KT-02")
                    .requestCard(2, "Bitte Karte stecken", Duration.ofMillis(300));
              } catch (java.io.IOException e) {
                throw new java.io.UncheckedIOException(e);
              }
            });
    SseClient.Frame shown =
        client.next(
            f -> "terminal".equals(f.event()) && "display".equals(data(f).getString("cause")),
            Duration.ofSeconds(5));
    assertEquals("KT-02", data(shown).getString("id"));
    request.get();
    client.next(
        f -> "terminal".equals(f.event()) && "display".equals(data(f).getString("cause")),
        Duration.ofSeconds(5));

    given()
        .port(server.port())
        .contentType("application/json")
        .body("{\"type\":\"io-error\"}")
        .put("/admin/terminals/KT-01/slots/1/fault")
        .then()
        .statusCode(200);
    SseClient.Frame fault =
        client.next(
            f -> "terminal".equals(f.event()) && "fault".equals(data(f).getString("cause")),
            Duration.ofSeconds(5));
    assertEquals("io-error", data(fault).getString("terminal.slots[0].fault.type"));
    given()
        .port(server.port())
        .contentType("application/json")
        .body("[{\"outcome\":\"cancel\"}]")
        .post("/admin/terminals/KT-01/pin-script")
        .then()
        .statusCode(200);
    assertEquals(
        "pin-script",
        data(client.next(
                f ->
                    "terminal".equals(f.event()) && "pin-script".equals(data(f).getString("cause")),
                Duration.ofSeconds(5)))
            .getString("cause"));

    given()
        .port(server.port())
        .contentType("application/json")
        .body("{\"vendor\":\"KOCO\"}")
        .put("/admin/vendor")
        .then()
        .statusCode(200);
    SseClient.Frame vendor = client.next("state");
    assertEquals("vendor", data(vendor).getString("cause"));
    assertEquals("KOCO", data(vendor).getString("vendor.vendor"));
    given()
        .port(server.port())
        .contentType("application/json")
        .body("{\"cardSessionTimeout\":30}")
        .put("/admin/settings")
        .then()
        .statusCode(200);
    assertEquals(30, data(client.next("state")).getInt("settings.cardSessionTimeout"));
    given().port(server.port()).post("/admin/reset").then().statusCode(200);
    SseClient.Frame reset = client.next("state");
    assertEquals("reset", data(reset).getString("cause"));
    assertEquals("neutral", data(reset).getString("vendor.vendor"));
  }

  @Test
  @DisplayName(
      "LIANA-151: subscription für Subscribe (TIP1-A_4608), den Zustellversuch per CETP (TUC_KON_256 "
          + "Schritt 6) und Unsubscribe (TIP1-A_4609); session für Start und Ende der Kartensitzung (A_25970-01, "
          + "TUC_KON_224)")
  void aboUndSitzung() throws Exception {
    SseClient client = connected(false, null);
    int closed;
    try (ServerSocket socket = new ServerSocket(0)) {
      closed = socket.getLocalPort();
    }
    String id =
        subscriptions.subscribe(WP1, "cetp://127.0.0.1:" + closed, "CARD/INSERTED", null).id();
    SseClient.Frame subscribed = client.next(AdminEvents.SUBSCRIPTION);
    assertEquals("subscribe", data(subscribed).getString("cause"));
    assertEquals(id, data(subscribed).getString("id"));
    given()
        .port(server.port())
        .contentType("application/json")
        .body("{\"image\":\"egk-valid\"}")
        .put("/admin/terminals/KT-02/slots/1")
        .then()
        .statusCode(200);
    SseClient.Frame delivery = client.next(AdminEvents.SUBSCRIPTION);
    assertEquals("delivery", data(delivery).getString("cause"));
    assertEquals(id, data(delivery).getString("id"));
    subscriptions.unsubscribe(WP1, id, null);
    assertEquals("unsubscribe", data(client.next(AdminEvents.SUBSCRIPTION)).getString("cause"));

    String egk = cards.card("KT-01", 1).orElseThrow().cardHandle();
    String session = cardSessions.start(WP1, egk);
    SseClient.Frame started = client.next(AdminEvents.SESSION);
    assertEquals(session, data(started).getString("sessionId"));
    assertTrue(data(started).getBoolean("open"));
    cardSessions.stop(session);
    SseClient.Frame stopped = client.next(AdminEvents.SESSION);
    assertEquals(session, data(stopped).getString("sessionId"));
    assertEquals(false, data(stopped).getBoolean("open"));
  }

  @Test
  @DisplayName(
      "TAB_KON_554: CARD_SESSION_TIMEOUT über das KMS (EHEX) gesetzt → state mit Anlass kms und dem neuen Wert")
  void kms() throws Exception {
    given()
        .port(server.port())
        .contentType("application/json")
        .body("{\"vendor\":\"EHEX\"}")
        .put("/admin/vendor")
        .then()
        .statusCode(200);
    SseClient client = connected(false, null);
    var kms = given().relaxedHTTPSValidation().baseUri("https://localhost").port(server.port());
    String token =
        kms.contentType("application/json")
            .body("{\"username\":\"super\",\"password\":\"33ee§§EE\"}")
            .post("/rest/mgmt/ak/konten/login")
            .then()
            .statusCode(204)
            .extract()
            .header("Authorization");
    given()
        .relaxedHTTPSValidation()
        .baseUri("https://localhost")
        .port(server.port())
        .header("Authorization", token)
        .contentType("application/json")
        .body("{\"cardSessionTimeout\":{\"amount\":40,\"unit\":\"SECONDS\"}}")
        .put("/rest/mgmt/ak/dienste/karten/einstellungen")
        .then()
        .statusCode(200);
    SseClient.Frame state =
        client.next(
            f -> "state".equals(f.event()) && data(f).getInt("settings.cardSessionTimeout") == 40,
            Duration.ofSeconds(5));
    assertEquals("kms", data(state).getString("cause"));
  }

  @Test
  @DisplayName(
      "Abbruch und Wiederaufnahme mit Last-Event-ID: alle Ereignisse dazwischen kommen in Reihenfolge, keines "
          + "fehlt, keines doppelt")
  void wiederaufnahme() throws Exception {
    SseClient first = connected(false, null);
    systemLog.write(SystemLog.Type.OP, SystemLog.Severity.INFO, "LIANA/TEST", Map.of("n", "0"));
    SseClient.Frame seen = first.next("log");
    first.close();
    clients.remove(first);

    for (int n = 1; n <= 5; n++) {
      systemLog.write(
          SystemLog.Type.OP, SystemLog.Severity.INFO, "LIANA/TEST", Map.of("n", String.valueOf(n)));
    }
    SseClient second = open(false, seen.id());
    String prefix = seen.id().substring(0, seen.id().lastIndexOf('-') + 1);
    long last = Long.parseLong(seen.id().substring(prefix.length()));
    for (int n = 1; n <= 5; n++) {
      SseClient.Frame frame = second.next("log");
      assertEquals(prefix + (last + n), frame.id(), "lückenlos");
      assertEquals(String.valueOf(n), data(frame).getString("parameters.n"));
    }
    systemLog.write(SystemLog.Type.OP, SystemLog.Severity.INFO, "LIANA/TEST", Map.of("n", "6"));
    SseClient.Frame live = second.next("log");
    assertEquals("6", data(live).getString("parameters.n"), "danach live weiter, ohne Doppel");
    assertEquals(prefix + (last + 6), live.id());
  }

  @Test
  @DisplayName(
      "Last-Event-ID aus einem früheren Start oder nicht mehr im Ringpuffer → resync mit Grund")
  void resync() throws Exception {
    SseClient foreign = open(false, "frueher-12");
    assertEquals(200, foreign.status());
    SseClient.Frame frame = foreign.next(AdminEvents.RESYNC);
    assertTrue(data(frame).getString("reason").contains("nicht aus diesem Start"), frame.data());

    SseClient client = connected(false, null);
    systemLog.write(SystemLog.Type.OP, SystemLog.Severity.INFO, "LIANA/TEST", Map.of());
    String old = client.next("log").id();
    for (int n = 0; n < 1001; n++) {
      systemLog.write(SystemLog.Type.OP, SystemLog.Severity.INFO, "LIANA/TEST", Map.of());
    }
    SseClient lost = open(false, old);
    assertEquals(200, lost.status());
    frame = lost.next(AdminEvents.RESYNC);
    assertTrue(data(frame).getString("reason").contains("nicht mehr im Puffer"), frame.data());
    assertNotNull(frame.id(), "Wiederaufnahme ab dem aktuellen Stand");
  }

  @Test
  @DisplayName(
      "Heartbeat als Kommentar (Proxies); höchstens 16 gleichzeitige Streams, der 17. bekommt 503")
  void heartbeatUndGrenze() throws Exception {
    SseClient client = connected(false, null);
    events.heartbeat();
    assertEquals(
        "heartbeat",
        client
            .next(f -> f.comment() != null && f.event() == null, Duration.ofSeconds(5))
            .comment());
    for (int n = 1; n < 16; n++) {
      open(false, null);
    }
    SseClient refused = open(false, null);
    assertEquals(503, refused.status());
    assertTrue(refused.body().contains("max-streams"));
    clients.remove(refused);
    refused.close();
    clients.getLast().close();
    clients.removeLast();
    awaitOpenStreams(15);
  }

  /**
   * Waits at most 5 s until {@code expected} streams are open (the server reports closing
   * asynchronously).
   */
  private void awaitOpenStreams(int expected) throws InterruptedException {
    long end = System.nanoTime() + 5_000_000_000L;
    while (events.openStreams() != expected && System.nanoTime() < end) {
      Thread.sleep(10);
    }
    assertEquals(expected, events.openStreams());
  }
}

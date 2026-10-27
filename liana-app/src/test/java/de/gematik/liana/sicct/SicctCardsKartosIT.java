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
package de.gematik.liana.sicct;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.admin.AdminServer;
import de.gematik.liana.kern.access.Context;
import de.gematik.liana.kern.card.CardObject;
import de.gematik.liana.kern.event.GetCardTerminals;
import de.gematik.liana.kern.event.GetCards;
import de.gematik.liana.kern.terminal.CardTerminalInfo;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.common.QuarkusTestResourceLifecycleManager;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.path.json.JsonPath;
import jakarta.inject.Inject;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.function.BooleanSupplier;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

/**
 * LIANA-78 against {@code kartos terminal}: the working connection of a paired KT (CT session, GET
 * STATUS), slot events from inserting and removing via the kartos control interface as
 * CARD/INSERTED and CARD/REMOVED with CardHandle as with the fake terminal, GetCards, and the end
 * without KEEP ALIVE (kartos stopped).
 */
@QuarkusTest
@QuarkusTestResource(value = SicctCardsKartosIT.Kartos.class, restrictToAnnotatedClass = true)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class SicctCardsKartosIT {

  static final String SECRET = "0f0e0d0c0b0a09080706050403020100";
  static final Context CTX = new Context("M1", "CS1", "WP1", null);
  static final Duration WAIT = Duration.ofSeconds(20);

  public static class Kartos implements QuarkusTestResourceLifecycleManager {
    static KartosTerminal kt;

    @Override
    public Map<String, String> start() {
      kt = KartosTerminal.start("02:00:00:4C:49:43", "kartos-kt-c1", 0, Map.of(), SECRET);
      int announcements;
      try {
        announcements = KartosTerminal.freeUdpPort();
      } catch (IOException e) {
        throw new UncheckedIOException(e);
      }
      Map<String, String> config =
          new java.util.HashMap<>(
              Map.of(
                  "liana.infrastructure.terminals.KT-C1.type", "sicct",
                  "liana.infrastructure.terminals.KT-C1.host", "127.0.0.1",
                  "liana.infrastructure.terminals.KT-C1.shared-secret", SECRET,
                  "liana.ctm.service-discovery-port", String.valueOf(kt.port()),
                  "liana.ctm.service-announcement-port", String.valueOf(announcements),
                  "liana.ctm.service-discovery-timeout", "2s",
                  "liana.ctm.keep-alive-interval", "1s",
                  "liana.ctm.keep-alive-try-count", "3",
                  "liana.infomodel.workplaces[0].terminals", "KT-C1"));
      // LIANA-67: the CATS terminal of the test profile points to the eHealth KT (501)
      config.put("liana.cats.terminals[0].terminal", "KT-C1");
      return config;
    }

    @Override
    public void stop() {
      if (kt != null) {
        kt.close();
      }
    }
  }

  @Inject AdminServer admin;

  @Inject GetCards getCards;

  @Inject GetCardTerminals getCardTerminals;

  private static void await(String what, BooleanSupplier condition) throws InterruptedException {
    long deadline = System.nanoTime() + WAIT.toNanos();
    while (!condition.getAsBoolean()) {
      if (System.nanoTime() > deadline) {
        throw new AssertionError(what + "\nkartos: " + Kartos.kt.log());
      }
      Thread.sleep(100);
    }
  }

  /** LIANA-108: KT-C1 from GetCardTerminals for WP1. */
  private CardTerminalInfo terminal() {
    return getCardTerminals.execute(CTX, false).stream()
        .map(GetCardTerminals.Entry::info)
        .filter(t -> t.ctId().equals("KT-C1"))
        .findFirst()
        .orElseThrow();
  }

  private List<CardObject> cards() {
    return getCards.execute(new GetCards.Request(CTX, "KT-C1", null, null, false));
  }

  private JsonPath kt() {
    return given()
        .port(admin.port())
        .get("/admin/terminals/KT-C1")
        .then()
        .statusCode(200)
        .extract()
        .jsonPath();
  }

  /** Events of KT-C1; the fake KTs from application.yaml keep running alongside (LIANA-98). */
  private List<Map<String, Object>> log(String topic) {
    return given()
        .port(admin.port())
        .get("/admin/log")
        .then()
        .statusCode(200)
        .extract()
        .jsonPath()
        .getList("findAll { it.topic == '" + topic + "' && it.parameters.CtID == 'KT-C1' }");
  }

  @Test
  @Order(1)
  @DisplayName(
      "TUC_KON_050: nach dem Verbindungsaufbau besteht die CT-Sitzung, GET STATUS liefert Version und "
          + "Displaygröße ins CT-Object; die gesteckten Karten stehen in GetCards (Schritt 11); LIANA-108: GetCardTerminals "
          + "zeigt KT-C1 verbunden mit Slots, MAC, Name und IP aus dem CT-Object")
  void arbeitsverbindung() throws InterruptedException {
    await("KT-C1 verbunden", () -> kt().get("ct") != null && kt().getBoolean("ct.CONNECTED"));
    JsonPath kt = kt();
    assertEquals("1.0.0", kt.getString("ct.EHEALTH_INTERFACE_VERSION"));
    assertEquals(20, kt.getInt("ct.DISPLAY_CAPABILITIES.visibleCharacters"));
    assertEquals(4, kt.getInt("ct.DISPLAY_CAPABILITIES.visibleLines"));
    assertEquals(List.of(1, 2, 3, 4), kt.getList("ct.SLOTS_USED"));
    await("4 Karten in GetCards", () -> cards().size() == 4);
    assertEquals(List.of(1, 2, 3, 4), cards().stream().map(CardObject::slotNo).sorted().toList());
    assertEquals(4, log("CARD/INSERTED").size());
    // LIANA-108 TAB_KON_563: GetCardTerminals from the CT object, CtId as in GetCards
    CardTerminalInfo info = terminal();
    assertEquals(cards().getFirst().ctId(), info.ctId());
    assertTrue(info.connected());
    assertEquals(4, info.slots());
    assertEquals("02-00-00-4C-49-43", info.macAddress());
    assertEquals("kartos-kt-c1", info.name());
    assertEquals("127.0.0.1", info.ipAddress());
  }

  @Test
  @Order(2)
  @DisplayName(
      "TIP1-A_4541-02/4542-02: Ziehen und Stecken über die kartos-Steuerschnittstelle (Kartenbibliothek) erzeugen CARD/REMOVED "
          + "und CARD/INSERTED mit neuem CardHandle wie beim Fake-Terminal")
  void steckenUndZiehen() throws InterruptedException {
    String before =
        cards().stream().filter(c -> c.slotNo() == 3).findFirst().orElseThrow().cardHandle();
    String iccsn = Kartos.kt.iccsn(3);
    Kartos.kt.eject(3);
    await("Slot 3 frei", () -> cards().stream().noneMatch(c -> c.slotNo() == 3));
    Map<?, ?> removed = (Map<?, ?>) log("CARD/REMOVED").getLast().get("parameters");
    assertEquals("KT-C1", removed.get("CtID"));
    assertEquals("3", removed.get("SlotID"));
    assertEquals(before, removed.get("CardHandle"));

    Kartos.kt.insert(3, iccsn);
    await("Slot 3 wieder belegt", () -> cards().stream().anyMatch(c -> c.slotNo() == 3));
    String after =
        cards().stream().filter(c -> c.slotNo() == 3).findFirst().orElseThrow().cardHandle();
    assertNotEquals(before, after);
    Map<?, ?> inserted = (Map<?, ?>) log("CARD/INSERTED").getLast().get("parameters");
    assertEquals("3", inserted.get("SlotID"));
    assertEquals(after, inserted.get("CardHandle"));
  }

  @Test
  @Order(3)
  @DisplayName(
      "TIP1-A_4536/4537: bleibt das KT stumm (kartos angehalten, kein KEEP ALIVE, keine Antwort), trennt LIANA "
          + "nach CTM_KEEP_ALIVE_TRY_COUNT Heartbeats: KT nicht erreichbar, seine Karten verschwinden aus GetCards, "
          + "GetCardTerminals meldet Connected false")
  void ohneKeepAlive() throws Exception {
    long pid = Kartos.kt.pid();
    signal("STOP", pid);
    try {
      await("KT-C1 getrennt", () -> !kt().getBoolean("ct.CONNECTED"));
      await("Karten weg", () -> cards().isEmpty());
      assertFalse(
          terminal().connected(), "LIANA-108: GetCardTerminals meldet KT-C1 nicht verbunden");
      Map<?, ?> disconnected = (Map<?, ?>) log("CT/DISCONNECTED").getLast().get("parameters");
      assertEquals("KT-C1", disconnected.get("CtID"));
      assertTrue(log("CARD/REMOVED").size() >= 4);
    } finally {
      signal("CONT", pid);
    }
  }

  /**
   * {@code kill} as a shell builtin: there is no {@code /usr/bin/kill} in the Mandrel container.
   */
  private static void signal(String name, long pid) throws Exception {
    int exit =
        new ProcessBuilder("sh", "-c", "kill -" + name + " " + pid).inheritIO().start().waitFor();
    assertEquals(0, exit, "kill -" + name + " " + pid);
  }
}

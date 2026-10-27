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
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.gematik.liana.admin.AdminServer;
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
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * LIANA-76 against {@code kartos terminal}: an eHealth KT configured via YAML (TUC_KON_054
 * ManuallyAdded, TUC_KON_055) and a KT that announces itself (TIP1-A_4540, TUC_KON_054 AutoAdded),
 * both visible via the Admin API; fake KTs run alongside ({@code mode: mixed}).
 */
@QuarkusTest
@QuarkusTestResource(value = SicctTerminalsKartosIT.Kartos.class, restrictToAnnotatedClass = true)
class SicctTerminalsKartosIT {

  static final String MAC = "02:00:00:4C:49:41";
  static final String MAC_NEU = "02:00:00:4C:49:42";
  static final Duration WAIT = Duration.ofSeconds(15);

  /**
   * Starts the configured KT before LIANA; LIANA listens for service descriptions on {@code
   * announcementPort}.
   */
  public static class Kartos implements QuarkusTestResourceLifecycleManager {
    static KartosTerminal configured;
    static int announcementPort;

    @Override
    public Map<String, String> start() {
      try {
        announcementPort = KartosTerminal.freeUdpPort();
      } catch (IOException e) {
        throw new UncheckedIOException(e);
      }
      configured = KartosTerminal.start(MAC, "kartos-kt-s1", 0, Map.of());
      return Map.of(
          "liana.infrastructure.terminals.KT-S1.type", "sicct",
          "liana.infrastructure.terminals.KT-S1.host", "127.0.0.1",
          "liana.ctm.service-discovery-port", String.valueOf(configured.port()),
          "liana.ctm.service-announcement-port", String.valueOf(announcementPort),
          "liana.ctm.service-discovery-timeout", "2s",
          "liana.infomodel.workplaces[0].terminals", "KT-01,KT-02,KT-S1");
    }

    @Override
    public void stop() {
      if (configured != null) {
        configured.close();
      }
    }
  }

  @Inject AdminServer admin;

  private static KartosTerminal announced;

  @AfterAll
  static void beenden() {
    if (announced != null) {
      announced.close();
    }
  }

  private JsonPath awaitJson(String path, java.util.function.Predicate<JsonPath> ready)
      throws InterruptedException {
    long deadline = System.nanoTime() + WAIT.toNanos();
    JsonPath json;
    do {
      json = given().port(admin.port()).get(path).then().statusCode(200).extract().jsonPath();
      if (ready.test(json)) {
        return json;
      }
      Thread.sleep(100);
    } while (System.nanoTime() < deadline);
    throw new AssertionError(
        path + " nicht bereit: " + json.prettify() + "\nkartos: " + Kartos.configured.log());
  }

  @Test
  @DisplayName(
      "TUC_KON_054 ManuallyAdded + TUC_KON_055: das YAML-KT KT-S1 steht mit den CT-Object-Attributen in "
          + "GET /admin/terminals – Gerätedaten per Dienstanfrage, SLOTCOUNT/Version/Display per GET STATUS über TLS")
  void konfiguriertesKt() throws InterruptedException {
    JsonPath kt =
        awaitJson(
            "/admin/terminals/KT-S1",
            json -> json.get("ct") != null && json.getInt("ct.SLOTCOUNT") > 0);
    assertEquals("sicct", kt.getString("mode"));
    assertEquals("KT-S1", kt.getString("ct.CTID"));
    assertEquals(true, kt.getBoolean("ct.IS_PHYSICAL"));
    assertEquals(MAC, kt.getString("ct.MAC_ADRESS"));
    assertEquals("kartos-kt-s1", kt.getString("ct.HOSTNAME"));
    assertEquals("127.0.0.1", kt.getString("ct.IP_ADRESS"));
    assertEquals(Kartos.configured.port(), kt.getInt("ct.TCP_PORT"));
    assertEquals(4, kt.getInt("ct.SLOTCOUNT"));
    assertEquals(4, kt.getList("slots").size());
    assertEquals("1.0.0", kt.getString("ct.EHEALTH_INTERFACE_VERSION"));
    assertEquals(true, kt.getBoolean("ct.VALID_VERSION"));
    assertEquals("ORGA6100", kt.getString("ct.PRODUCTINFORMATION.ProductCode"));
    assertEquals(
        Map.of(
            "visibleCharacters",
            20,
            "visibleLines",
            4,
            "virtualCharacters",
            48,
            "virtualLines",
            4,
            "beeper",
            true),
        kt.getMap("ct.DISPLAY_CAPABILITIES"));
    assertEquals("zugewiesen", kt.getString("ct.CORRELATION"));
    assertEquals(false, kt.getBoolean("ct.CONNECTED"));

    // fake KTs run alongside
    given()
        .port(admin.port())
        .get("/admin/terminals")
        .then()
        .statusCode(200)
        .body("id", equalTo(List.of("KT-01", "KT-02", "KT-S1")))
        .body("mode", equalTo(List.of("fake", "fake", "sicct")));
    given().port(admin.port()).get("/admin/info").then().body("terminalMode", equalTo("mixed"));
  }

  @Test
  @DisplayName(
      "TIP1-A_4540: ein KT, das sich per Service Announcement meldet, nimmt TUC_KON_054 (AutoAdded) als "
          + "„bekannt“ in CTM_CT_LIST auf")
  void angekuendigtesKt() throws InterruptedException {
    announced = KartosTerminal.start(MAC_NEU, "kartos-neu", Kartos.announcementPort, Map.of());
    JsonPath list =
        awaitJson("/admin/ct-list", json -> json.getList("MAC_ADRESS").contains(MAC_NEU));
    Map<String, Object> ct =
        list.getList("findAll { it.MAC_ADRESS == '" + MAC_NEU + "' }", Map.class).getFirst();
    assertEquals("KT-0200004C4942", ct.get("CTID"), "TUC_KON_054 Schritt 3a: CT.CTID neu erzeugt");
    assertEquals("bekannt", ct.get("CORRELATION"));
    assertEquals("kartos-neu", ct.get("HOSTNAME"));
    assertEquals(announced.port(), ct.get("TCP_PORT"));
    assertEquals(0, ct.get("SLOTCOUNT"), "TUC_KON_055 erst ab „zugewiesen“");
  }

  @Test
  @DisplayName(
      "decision-12: Karten eines eHealth-KT steckt die kartos-Steuerschnittstelle, die Admin-API antwortet 501")
  void steckenNichtUeberLiana() {
    given()
        .port(admin.port())
        .contentType("application/json")
        .body("{\"image\":\"egk-valid\"}")
        .put("/admin/terminals/KT-S1/slots/1")
        .then()
        .statusCode(501)
        .body(
            "error",
            startsWith("PUT /admin/terminals/KT-S1/slots/1: KT-S1 ist ein eHealth-KT (SICCT)"));
    given().port(admin.port()).get("/admin/terminals").then().body("id", hasItem("KT-01"));
  }
}

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
package de.gematik.liana.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.admin.AdminServer;
import de.gematik.liana.control.Fault;
import de.gematik.liana.control.LianaControl;
import de.gematik.liana.control.LianaControlException;
import de.gematik.liana.control.PinInput;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * LIANA-138, LIANA-149: every endpoint of the Admin API (docs/handbuch.md "Admin-API") via
 * liana-control-client against LIANA.
 */
@QuarkusTest
class LianaControlTest {

  @Inject AdminServer admin;

  LianaControl control;

  @BeforeEach
  void connect() {
    control = LianaControl.connect("http://localhost:" + admin.port() + "/");
  }

  @AfterEach
  void reset() {
    control.reset();
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> slot(Map<String, Object> terminal, int slot) {
    return ((List<Map<String, Object>>) terminal.get("slots"))
        .stream()
            .filter(s -> ((Number) s.get("slot")).intValue() == slot)
            .findFirst()
            .orElseThrow();
  }

  @Test
  @DisplayName("ready, info, terminals, terminal, ct-list, infomodel, tls, vendor, log")
  void lesen() {
    assertTrue(control.ready());
    assertTrue(control.awaitReady(java.time.Duration.ofSeconds(1)));
    assertNotNull(control.info().get("version"));
    assertTrue(control.terminals().stream().anyMatch(t -> "KT-01".equals(t.get("id"))));
    assertEquals("KT-02", control.terminal("KT-02").get("id"));
    assertNotNull(control.ctList());
    assertFalse(control.infomodel().isEmpty());
    assertFalse(control.tls().isEmpty());
    assertEquals("neutral", control.vendor().get("vendor"));
    assertNotNull(control.log(Instant.parse("2026-01-01T00:00:00Z"), Instant.now()));
    assertNotNull(control.log(null, null));
  }

  @Test
  @DisplayName(
      "LIANA-149: cards, images, subscriptions, sessions, pki, settings, deviations, Selbsttest, "
          + "ct-discovery, openapi.yaml")
  @SuppressWarnings("unchecked")
  void sichten() {
    assertTrue(
        control.cards().stream()
            .anyMatch(c -> "KT-01".equals(c.get("ctId")) && c.get("iccsn") != null));
    assertTrue(
        ((List<Map<String, Object>>) control.images().get("images"))
            .stream().anyMatch(i -> "egk-valid".equals(i.get("name"))));
    assertEquals(List.of(), control.subscriptions());
    assertEquals(List.of(), control.sessions().get("cardSessions"));
    assertNotNull(((Map<String, Object>) control.pki().get("tsl")).get("sequenceNumber"));
    assertEquals(120.0, control.settings().get("cardSessionTimeout"));
    assertEquals(
        45.0,
        control.setSettings(java.time.Duration.ofSeconds(45), null).get("cardSessionTimeout"));
    assertEquals(false, control.setSettings(null, false).get("luOnline"));
    assertEquals(
        400,
        assertThrows(
                LianaControlException.class,
                () -> control.setSettings(java.time.Duration.ofSeconds(181), null))
            .status());
    assertFalse(((List<?>) control.deviations().get("deviations")).isEmpty());
    assertEquals(true, control.cryptoSelfTest("brainpool-ecdsa").get("ok"));
    assertEquals(
        404,
        assertThrows(LianaControlException.class, () -> control.cryptoSelfTest("nix")).status());
    assertEquals(List.of(), control.ctDiscovery(null));
    assertEquals(
        404,
        assertThrows(LianaControlException.class, () -> control.ctDiscovery("KT-01")).status());
    assertTrue(control.openApi().startsWith("openapi: 3.0.3"));
  }

  @Test
  @DisplayName("Karte stecken und ziehen, Störung setzen und löschen, reset")
  void kartenUndStoerungen() {
    control.insertCard("KT-02", 1, "egk-valid");
    assertNotNull(slot(control.terminal("KT-02"), 1).get("image"));
    control.setFault("KT-02", 1, Fault.statusWord("6A82").commandPrefix("00B0").count(1));
    assertNotNull(slot(control.terminal("KT-02"), 1).get("fault"));
    control.clearFault("KT-02", 1);
    assertNull(slot(control.terminal("KT-02"), 1).get("fault"));
    control.setFault("KT-02", 1, Fault.response("9000"));
    control.setFault("KT-02", 1, Fault.ioError());
    control.setFault("KT-02", 1, Fault.delay(5));
    control.ejectCard("KT-02", 1);
    assertNull(slot(control.terminal("KT-02"), 1).get("image"));
    control.reset();
    assertNull(slot(control.terminal("KT-02"), 1).get("fault"));
  }

  @Test
  @DisplayName("PIN-Script anhängen und leeren")
  void pinScript() {
    control.appendPinScript(
        "KT-01",
        List.of(
            PinInput.wrong().slot(2),
            PinInput.cancel(),
            PinInput.digits("1234"),
            PinInput.correct(),
            PinInput.puk(),
            PinInput.transport(),
            PinInput.timeout(),
            PinInput.incomplete()));
    assertEquals(8, ((List<?>) control.terminal("KT-01").get("pinScript")).size());
    control.clearPinScript("KT-01");
    assertEquals(0, ((List<?>) control.terminal("KT-01").get("pinScript")).size());
  }

  @Test
  @DisplayName("Herstellerprofil und strict umschalten, .kon holen")
  void vendorUndKon() {
    control.setVendor("KOCO", true);
    assertEquals("KOCO", control.vendor().get("vendor"));
    assertEquals(true, control.vendor().get("strict"));
    control.setVendor(null, false);
    assertEquals("KOCO", control.vendor().get("vendor"));
    assertTrue(control.konConfig("CS1").contains("\"clientSystemId\""));
  }

  @Test
  @DisplayName("LIANA-138 AC 2: Fehler als LianaControlException mit Status und Meldung von LIANA")
  void fehler() {
    LianaControlException unknown =
        assertThrows(LianaControlException.class, () -> control.terminal("KT-99"));
    assertEquals(404, unknown.status());
    assertNotNull(unknown.error());
    assertTrue(
        unknown.getMessage().startsWith("GET /admin/terminals/KT-99: HTTP 404 "),
        unknown.getMessage());
    assertEquals(
        400,
        assertThrows(LianaControlException.class, () -> control.setVendor("NIX", null)).status());
    assertEquals(
        404,
        assertThrows(
                LianaControlException.class, () -> control.insertCard("KT-02", 1, "gibt-es-nicht"))
            .status());
    assertEquals(
        400,
        assertThrows(LianaControlException.class, () -> control.setVendor(null, null)).status());
    assertEquals(
        404, assertThrows(LianaControlException.class, () -> control.konConfig("CS-99")).status());
  }

  @Test
  @DisplayName("Pairing-Endpunkte: am Fake-KT abgelehnt, mit Meldung von LIANA")
  void pairing() {
    for (Runnable call :
        List.<Runnable>of(
            () -> control.pair("KT-01", null),
            () -> control.pair("KT-01", "AB"),
            () -> control.setSharedSecret("KT-01", "00".repeat(16)),
            () -> control.deleteSharedSecret("KT-01"))) {
      LianaControlException e = assertThrows(LianaControlException.class, call::run);
      assertTrue(e.status() / 100 == 4, e.getMessage());
      assertNotNull(e.error(), e.getMessage());
    }
  }
}

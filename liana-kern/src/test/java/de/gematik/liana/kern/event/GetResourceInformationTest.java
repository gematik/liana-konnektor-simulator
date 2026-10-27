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
package de.gematik.liana.kern.event;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.kern.access.Context;
import de.gematik.liana.kern.access.Infomodel;
import de.gematik.liana.kern.card.CardAccess;
import de.gematik.liana.kern.card.CardList;
import de.gematik.liana.kern.card.CardLocks;
import de.gematik.liana.kern.card.RecordedTerminal;
import de.gematik.liana.kern.error.ConnectorException;
import de.gematik.liana.kern.management.ManagementSettings;
import de.gematik.liana.kern.management.OperatingState;
import de.gematik.liana.kern.terminal.TerminalRegistry;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * GetResourceInformation (TIP1-A_4607) against KT-01 with egk-valid in slot 1 and KT-02 without
 * card, context M1/CS1/WP1.
 */
class GetResourceInformationTest {

  private static final Context CTX = new Context("M1", "CS1", "WP1", null);

  private final RecordedTerminal kt01 =
      new RecordedTerminal("KT-01", 3, RecordedTerminal.EGK_VALID);
  private final RecordedTerminal kt02 =
      new RecordedTerminal("KT-02", 2, RecordedTerminal.EGK_VALID);
  private final RecordedTerminal kt03 =
      new RecordedTerminal("KT-03", 1, RecordedTerminal.EGK_VALID);
  private final TerminalRegistry registry = new TerminalRegistry(List.of(kt01, kt02, kt03));
  private final CardList cards = new CardList(registry, Clock.systemUTC());
  private final Infomodel infomodel =
      new Infomodel(
          List.of("M1", "M2"),
          List.of("CS1", "CS2"),
          List.of(
              new Infomodel.Workplace(
                  "WP1", List.of("M1"), List.of("CS1"), List.of("KT-01", "KT-02")),
              new Infomodel.Workplace("WP3", List.of("M2"), List.of("CS2"), List.of("KT-03"))));
  private final SystemLog log = new SystemLog(Clock.systemUTC(), 100);
  private final ManagementSettings settings =
      new ManagementSettings(Duration.ofSeconds(120), Duration.ofSeconds(10), log);
  private final OperatingState state =
      new OperatingState(
          new OperatingState.Connections(true, false, true), settings, log, Clock.systemUTC());
  private final GetResourceInformation gri =
      new GetResourceInformation(
          infomodel,
          registry,
          cards,
          new CardAccess(infomodel, cards, new CardLocks()),
          new GetCardTerminals(infomodel, registry),
          state);

  @BeforeEach
  void stecken() {
    cards.start();
    kt01.insert(1);
    kt03.insert(1);
  }

  private GetResourceInformation.Result execute(
      String ctId, Integer slotId, String iccsn, String cardHandle) {
    return gri.execute(new GetResourceInformation.Request(CTX, ctId, slotId, iccsn, cardHandle));
  }

  private int code(Runnable call) {
    return assertThrows(ConnectorException.class, call::run).error().code();
  }

  private Map<String, Boolean> values() {
    return state.errorStates().stream()
        .collect(
            Collectors.toMap(
                OperatingState.ErrorState::condition, OperatingState.ErrorState::value));
  }

  @Test
  @DisplayName(
      "TUC_KON_254 Schritt 3: ohne Parameter der Konnektor mit VPN TI Online, VPN SIS Offline und der "
          + "Fehlerzustandsliste TAB_KON_503, alle Werte false")
  void konnektor() {
    var connector = execute(null, null, null, null).connector();
    assertTrue(connector.vpnTi().online());
    assertFalse(connector.vpnSis().online());
    assertTrue(connector.errorStates().size() > 20);
    assertEquals("EC_No_VPN_TI_Connection", connector.errorStates().getFirst().condition());
    assertFalse(values().containsValue(true));
  }

  @Test
  @DisplayName(
      "TUC_KON_254 Schritt 1: Karte über CardHandle, Iccsn oder CtId+SlotId; Schritt 2: KT über CtId")
  void ressourcen() {
    String handle = cards.card("KT-01", 1).orElseThrow().cardHandle();
    String iccsn = cards.card("KT-01", 1).orElseThrow().data().iccsn();
    assertEquals(handle, execute(null, null, null, handle).card().cardHandle());
    assertEquals(handle, execute(null, null, iccsn, null).card().cardHandle());
    assertEquals(handle, execute("KT-01", 1, null, null).card().cardHandle());
    var kt = execute("KT-02", null, null, null);
    assertEquals("KT-02", kt.terminal().info().ctId());
    assertEquals(List.of("WP1"), kt.terminal().workplaceIds());
    assertNull(kt.card());
    assertNull(kt.connector());
  }

  @Test
  @DisplayName(
      "TAB_KON_562 / TAB_KON_570: SlotId ohne CtId 4000, unbekanntes KT 4007, Slot außerhalb 4097, leerer Slot "
          + "4098, unbekannte Iccsn 4099, unbekanntes CardHandle 4101; KT oder Karte eines anderen Mandanten 4015")
  void fehler() {
    assertEquals(4000, code(() -> execute(null, 1, null, null)));
    assertEquals(4007, code(() -> execute("KT-99", null, null, null)));
    assertEquals(4007, code(() -> execute("KT-99", 1, null, null)));
    assertEquals(4097, code(() -> execute("KT-02", 3, null, null)));
    assertEquals(4098, code(() -> execute("KT-02", 1, null, null)));
    assertEquals(4099, code(() -> execute(null, null, "80276000000000000000", null)));
    assertEquals(4101, code(() -> execute(null, null, null, "unbekannt")));
    assertEquals(4015, code(() -> execute("KT-03", null, null, null)));
    assertEquals(4015, code(() -> execute("KT-03", 1, null, null)));
  }

  @Test
  @DisplayName(
      "A_17085 / A_17087 / TIP1-A_4512-06: VPN TI bzw. Transportnetz offline setzen EC_No_VPN_TI_Connection "
          + "bzw. EC_No_Online_Connection mit neuem ValidFrom und melden OPERATIONAL_STATE/$EC; bei MGM_LU_ONLINE "
          + "Disabled nie; reset stellt den Boot-Stand ohne Ereignis her")
  void betriebszustand() throws Exception {
    Instant before = state.vpnTi().timestamp();
    Thread.sleep(2);
    state.set(false, null, false);
    assertFalse(state.vpnTi().online());
    assertTrue(state.vpnTi().timestamp().isAfter(before));
    assertTrue(values().get("EC_No_VPN_TI_Connection"));
    assertTrue(values().get("EC_No_Online_Connection"));
    assertFalse(
        values().get("EC_No_VPN_SIS_Connection"),
        "A_17086: ANLW_INTERNET_MODUS=SIS kennt LIANA nicht");
    var events =
        log.entries(Instant.MIN, Instant.MAX).stream().map(SystemLog.Entry::topic).toList();
    assertTrue(events.contains("OPERATIONAL_STATE/EC_No_VPN_TI_Connection"), events.toString());
    assertTrue(events.contains("OPERATIONAL_STATE/EC_No_Online_Connection"), events.toString());
    var entry =
        log.entries(Instant.MIN, Instant.MAX).stream()
            .filter(e -> e.topic().equals("OPERATIONAL_STATE/EC_No_VPN_TI_Connection"))
            .findFirst()
            .orElseThrow();
    assertEquals("true", entry.parameters().get("Value"));
    assertEquals(SystemLog.Severity.ERR, entry.severity());

    settings.online(false);
    assertFalse(values().get("EC_No_VPN_TI_Connection"), "A_17085");
    assertFalse(values().get("EC_No_Online_Connection"), "A_17087");
    settings.online(true);
    assertTrue(values().get("EC_No_VPN_TI_Connection"));

    log.clear();
    state.reset();
    assertTrue(state.vpnTi().online());
    assertFalse(values().containsValue(true));
    assertTrue(log.entries(Instant.MIN, Instant.MAX).isEmpty());
  }
}

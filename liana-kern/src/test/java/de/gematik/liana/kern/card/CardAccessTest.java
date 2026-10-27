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
package de.gematik.liana.kern.card;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import de.gematik.liana.kern.access.Context;
import de.gematik.liana.kern.access.Infomodel;
import de.gematik.liana.kern.error.ConnectorError;
import de.gematik.liana.kern.error.ConnectorException;
import de.gematik.liana.kern.terminal.TerminalRegistry;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

/**
 * TUC_KON_000 with CardHandle: rules R7 (SM-B_Verwaltet) and R9 (HBAx with card session) from
 * TAB_KON_514-01.
 */
class CardAccessTest {

  /**
   * Context as in the Informationsmodell case of Konnektor-QES: M2 is assigned to WP1 and CS1 but
   * manages no SMC-B.
   */
  private static final Context M1 = new Context("M1", "CS1", "WP1", "bert");

  private static final Context M2 = new Context("M2", "CS1", "WP1", "bert");
  private static final List<Infomodel.Workplace> WORKPLACES =
      List.of(
          new Infomodel.Workplace("WP1", List.of("M1", "M2"), List.of("CS1"), List.of("KT-01")));

  private final RecordedCards kt01 = new RecordedCards("KT-01");
  private final CardList cards =
      new CardList(new TerminalRegistry(List.of(kt01)), Clock.systemUTC());
  private String smcb;
  private String iccsn;
  private String hba;

  @BeforeEach
  void stecken() {
    cards.start();
    kt01.insert(2, RecordedTerminal.SMCB_VALID).insert(3, RecordedTerminal.HBA_VALID);
    CardObject card = cards.card("KT-01", 2).orElseThrow();
    smcb = card.cardHandle();
    iccsn = card.data().iccsn();
    hba = cards.card("KT-01", 3).orElseThrow().cardHandle();
  }

  @Test
  @DisplayName("TUC_KON_000 R7 / 4013: die SMC-B ist SM-B_Verwaltet von M1, nicht von M2")
  void smbNichtImMandanten() {
    CardAccess access = access(Map.of(iccsn, List.of("M1")));
    assertEquals(smcb, access.card(M1, smcb).cardHandle());
    assertError(ConnectorError.SMB_NOT_IN_MANDANT, () -> access.card(M2, smcb, true));
    assertError(ConnectorError.SMB_NOT_IN_MANDANT, () -> access.card(M2, smcb));
  }

  @Test
  @DisplayName(
      "TUC_KON_000 R7 / 4009: die SMC-B ist keinem Mandanten als SM-B_Verwaltet zugeordnet")
  void smbUnbekannt() {
    CardAccess access = access(Map.of("80276000000000000000", List.of("M1")));
    assertError(ConnectorError.SMB_UNKNOWN, () -> access.card(M1, smcb, true));
  }

  @Test
  @DisplayName("Ohne SM-B_Verwaltet gilt jede SMC-B als SM-B_Verwaltet jedes Mandanten")
  void ohneSmbVerwaltet() {
    CardAccess access = access(Map.of());
    assertEquals(smcb, access.card(M2, smcb, true).cardHandle());
  }

  @Test
  @DisplayName(
      "TUC_KON_000 R9 / 4003: HBAx mit Kartensitzung ohne oder mit leerer UserId; ohne Kartensitzung (R8) "
          + "und mit UserId kein Fehler")
  void hbaOhneUserId() {
    CardAccess access = access(Map.of());
    assertError(
        ConnectorError.USER_ID_MISSING,
        () -> access.card(new Context("M1", "CS1", "WP1", ""), hba, true));
    assertError(
        ConnectorError.USER_ID_MISSING,
        () -> access.card(new Context("M1", "CS1", "WP1", null), hba, true));
    assertEquals(hba, access.card(new Context("M1", "CS1", "WP1", null), hba, false).cardHandle());
    assertEquals(hba, access.card(M1, hba, true).cardHandle());
    assertEquals(smcb, access.card(new Context("M1", "CS1", "WP1", null), smcb, true).cardHandle());
  }

  @Test
  @DisplayName(
      "TAB_KON_514-01 Hinweis 3: unbekannte Mandanten, Clientsysteme und Arbeitsplätze sind 4021 an der "
          + "Außenschnittstelle und 4004/4005/4006 im Protokoll")
  void protokollcodes() {
    CardAccess access = access(Map.of());
    assertProtocol(
        ConnectorError.INVALID_MANDANT,
        () -> access.card(new Context("M9", "CS1", "WP1", "u"), hba));
    assertProtocol(
        ConnectorError.INVALID_CLIENT_SYSTEM,
        () -> access.card(new Context("M1", "falscheCsId", "WP1", "u"), hba));
    assertProtocol(
        ConnectorError.INVALID_WORKPLACE,
        () -> access.card(new Context("M1", "CS1", "WP9", "u"), hba));
    ConnectorException e =
        assertThrows(
            ConnectorException.class, () -> access.card(new Context("M1", null, "WP1", "u"), hba));
    assertEquals(ConnectorError.CONTEXT_INCOMPLETE, e.protocolError());
  }

  private CardAccess access(Map<String, List<String>> smbVerwaltet) {
    return new CardAccess(
        new Infomodel(List.of("M1", "M2"), List.of("CS1"), WORKPLACES, smbVerwaltet),
        cards,
        new CardLocks());
  }

  private static void assertError(ConnectorError expected, Executable call) {
    assertEquals(expected, assertThrows(ConnectorException.class, call).error());
  }

  private static void assertProtocol(ConnectorError protocol, Executable call) {
    ConnectorException e = assertThrows(ConnectorException.class, call);
    assertEquals(ConnectorError.CONTEXT_INCOMPLETE, e.error());
    assertEquals(protocol, e.protocolError());
  }
}

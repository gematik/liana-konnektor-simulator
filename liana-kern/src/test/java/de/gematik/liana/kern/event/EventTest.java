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

import de.gematik.liana.kern.card.CardData;
import de.gematik.liana.kern.card.CardEvent;
import de.gematik.liana.kern.card.CardObject;
import de.gematik.liana.kern.card.CardType;
import de.gematik.liana.kern.card.CardVersion;
import de.gematik.liana.kern.card.PinEvent;
import de.gematik.liana.kern.card.PinVerification.PinResult;
import java.time.Instant;
import java.time.LocalDate;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class EventTest {

  private static final Instant T0 = Instant.parse("2026-10-10T08:15:30.123456Z");
  private static final CardVersion VERSION =
      new CardVersion(
          new CardVersion.Version(4, 4, 0),
          new CardVersion.Version(4, 7, 0),
          null,
          null,
          null,
          null);
  private static final CardData EGK =
      new CardData(
          CardType.EGK,
          "80276883110000168584",
          VERSION,
          "Erika MustermannTEST-ONLY",
          "X110630769",
          LocalDate.parse("2030-04-06"));

  @Test
  @DisplayName(
      "TUC_KON_001 Schritt 3: CARD/INSERTED (Operation, Info) mit CardHandle, CardType, CardVersion, ICCSN, "
          + "CtID, SlotID, InsertTime, CardHolderName, KVNR, CertExpirationDate in dieser Reihenfolge")
  void inserted() {
    Event event =
        Event.of(
            new CardEvent(CardEvent.Topic.INSERTED, new CardObject("CH-1", "KT-01", 1, T0, EGK)));
    assertEquals("CARD/INSERTED", event.topic());
    assertEquals(Event.Type.OPERATION, event.type());
    assertEquals(Event.Severity.INFO, event.severity());
    Map<String, String> expected = new LinkedHashMap<>();
    expected.put("CardHandle", "CH-1");
    expected.put("CardType", "EGK");
    expected.put("CardVersion", "COSVersion=4.4.0, ObjectSystemVersion=4.7.0");
    expected.put("ICCSN", "80276883110000168584");
    expected.put("CtID", "KT-01");
    expected.put("SlotID", "1");
    expected.put("InsertTime", "2026-10-10T08:15:30.123Z");
    expected.put("CardHolderName", "Erika MustermannTEST-ONLY");
    expected.put("KVNR", "X110630769");
    expected.put("CertExpirationDate", "2030-04-06");
    assertEquals(
        expected.entrySet().stream().toList(), event.parameters().entrySet().stream().toList());
  }

  @Test
  @DisplayName(
      "TIP1-A_4562: CARD/REMOVED mit Type statt CardType und ohne CertExpirationDate; fehlende Werte "
          + "(SMC-B ohne KVNR, UNKNOWN-Karte) entfallen")
  void removed() {
    CardData smcb =
        new CardData(CardType.SMC_B, "80276883110000168650", null, "Praxis", null, null);
    Event event =
        Event.of(
            new CardEvent(CardEvent.Topic.REMOVED, new CardObject("CH-2", "KT-01", 2, T0, smcb)));
    assertEquals("CARD/REMOVED", event.topic());
    assertEquals(
        java.util.List.of(
            "CardHandle", "Type", "ICCSN", "CtID", "SlotID", "InsertTime", "CardHolderName"),
        event.parameters().keySet().stream().toList());
    assertEquals("SMC-B", event.parameters().get("Type"));

    Event unknown =
        Event.of(
            new CardEvent(
                CardEvent.Topic.INSERTED,
                new CardObject("CH-3", "KT-01", 3, T0, CardData.UNKNOWN)));
    assertEquals(
        java.util.List.of("CardHandle", "CardType", "CtID", "SlotID", "InsertTime"),
        unknown.parameters().keySet().stream().toList());
    assertEquals("UNKNOWN", unknown.parameters().get("CardType"));
  }

  @Test
  @DisplayName(
      "TUC_KON_012 Schritte 7a und 7d: CARD/PIN/VERIFY_STARTED und VERIFY_FINISHED (Operation, Info) mit "
          + "CardHandle, CardType, ICCSN, CtID, SlotID, PinRef, PinInputCtID, bei FINISHED dazu Result")
  void pin() {
    CardObject smcb =
        new CardObject(
            "CH-2",
            "KT-01",
            2,
            T0,
            new CardData(CardType.SMC_B, "80276883110000168650", null, "Praxis", null, null));
    Event started =
        Event.of(new PinEvent(PinEvent.Topic.VERIFY_STARTED, smcb, "PIN.SMC", "KT-01", null));
    assertEquals("CARD/PIN/VERIFY_STARTED", started.topic());
    assertEquals(Event.Type.OPERATION, started.type());
    assertEquals(Event.Severity.INFO, started.severity());
    Map<String, String> expected = new LinkedHashMap<>();
    expected.put("CardHandle", "CH-2");
    expected.put("CardType", "SMC-B");
    expected.put("ICCSN", "80276883110000168650");
    expected.put("CtID", "KT-01");
    expected.put("SlotID", "2");
    expected.put("PinRef", "PIN.SMC");
    expected.put("PinInputCtID", "KT-01");
    assertEquals(
        expected.entrySet().stream().toList(), started.parameters().entrySet().stream().toList());

    Event finished =
        Event.of(
            new PinEvent(
                PinEvent.Topic.VERIFY_FINISHED, smcb, "PIN.SMC", "KT-01", PinResult.REJECTED));
    assertEquals("CARD/PIN/VERIFY_FINISHED", finished.topic());
    expected.put("Result", "REJECTED");
    assertEquals(
        expected.entrySet().stream().toList(), finished.parameters().entrySet().stream().toList());
  }

  @Test
  @DisplayName("TUC_KON_256 Schritt 5b: Parameter ctId ohne Groß-/Kleinschreibung")
  void parameter() {
    Event event =
        Event.of(
            new CardEvent(CardEvent.Topic.INSERTED, new CardObject("CH-1", "KT-01", 1, T0, EGK)));
    assertEquals(Optional.of("KT-01"), event.parameter("ctId"));
    assertEquals(Optional.empty(), event.parameter("SessionID"));
  }
}

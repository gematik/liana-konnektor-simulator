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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.kern.access.Context;
import de.gematik.liana.kern.access.Infomodel;
import de.gematik.liana.kern.error.ConnectorError;
import de.gematik.liana.kern.error.ConnectorException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

class SubscriptionsTest {

  private static final Context WP1 = new Context("M1", "CS1", "WP1", "bert");
  private static final Context WP2 = new Context("M1", "CS1", "WP2", null);
  private static final Context M2 = new Context("M2", "CS2", "WP3", null);
  private static final String PS = "cetp://192.168.197.2:7001";

  private final ManualClock clock = new ManualClock();
  private final Infomodel infomodel =
      new Infomodel(
          List.of("M1", "M2"),
          List.of("CS1", "CS2"),
          List.of(
              new Infomodel.Workplace("WP1", List.of("M1"), List.of("CS1"), List.of("KT-01")),
              new Infomodel.Workplace("WP2", List.of("M1"), List.of("CS1"), List.of("KT-02")),
              new Infomodel.Workplace("WP3", List.of("M2"), List.of("CS2"), List.of("KT-01"))));
  private final List<String> sent = new ArrayList<>();
  private final List<EventSink.Outcome> outcomes = new ArrayList<>();
  private final Subscriptions subscriptions =
      new Subscriptions(
          infomodel,
          clock,
          (event, subscription, outcome) -> {
            sent.add(event.topic() + " → " + subscription.eventTo() + " " + subscription.id());
            outcomes.add(outcome);
          },
          3);

  private static Event inserted(String ctId) {
    return new Event(
        "CARD/INSERTED",
        Event.Type.OPERATION,
        Event.Severity.INFO,
        Map.of("CardHandle", "h1", "CtID", ctId, "SlotID", "1"));
  }

  private static void assertError(ConnectorError error, Executable executable) {
    assertEquals(error, assertThrows(ConnectorException.class, executable).error());
  }

  @Test
  @DisplayName(
      "TIP1-A_4608 Subscribe: neue SubscriptionID, TerminationTime = Systemzeit + 25 h; dieselbe Anmeldung "
          + "noch einmal liefert dieselbe SubscriptionID mit neuer TerminationTime (TAB_KON_572 saveSubscription)")
  void subscribe() {
    Subscription first = subscriptions.subscribe(WP1, PS, "CARD/INSERTED", null);
    assertEquals(Instant.parse("2026-10-09T13:00:00Z"), first.terminationTime());

    clock.advance(Duration.ofHours(1));
    Subscription again = subscriptions.subscribe(WP1, PS, "CARD/INSERTED", null);
    assertEquals(first.id(), again.id());
    assertEquals(Instant.parse("2026-10-09T14:00:00Z"), again.terminationTime());

    assertNotEquals(first.id(), subscriptions.subscribe(WP1, PS, "CARD/REMOVED", null).id());
    assertNotEquals(
        first.id(), subscriptions.subscribe(WP1, PS, "CARD/INSERTED", "/Event[Topic='x']").id());
    assertNotEquals(first.id(), subscriptions.subscribe(WP2, PS, "CARD/INSERTED", null).id());
    assertEquals(4, subscriptions.all().size());
  }

  @Test
  @DisplayName(
      "TAB_KON_572 checkArguments → 4000 (EventTo nicht cetp://host:port, Topic leer), TUC_KON_000 → 4021 "
          + "(unbekannter Mandant); ohne Arbeitsplatz zulässig (allWorkplaces = true)")
  void subscribeFehler() {
    assertError(
        ConnectorError.SYNTAX, () -> subscriptions.subscribe(WP1, "http://ps:7001", "CARD", null));
    assertError(
        ConnectorError.SYNTAX, () -> subscriptions.subscribe(WP1, "cetp://ps", "CARD", null));
    assertError(
        ConnectorError.SYNTAX,
        () -> subscriptions.subscribe(WP1, "cetp://ps:7001/pfad", "CARD", null));
    assertError(
        ConnectorError.SYNTAX, () -> subscriptions.subscribe(WP1, "cetp:// kaputt", "CARD", null));
    assertError(ConnectorError.SYNTAX, () -> subscriptions.subscribe(WP1, PS, " ", null));
    assertError(
        ConnectorError.SYNTAX, () -> subscriptions.subscribe(WP1, PS, "CARD", "x".repeat(1025)));
    assertError(
        ConnectorError.CONTEXT_INCOMPLETE,
        () -> subscriptions.subscribe(new Context("M9", "CS1", "WP1", null), PS, "CARD", null));
    subscriptions.subscribe(
        new Context("M1", "CS1", null, null), "cetp://[::1]:7001", "CARD", null);
    assertEquals(List.of(), sent);
  }

  @Test
  @DisplayName(
      "TIP1-A_4609 Unsubscribe per SubscriptionID (unbekannt → 4102) oder EventTo (alle Anmeldungen der "
          + "Ereignissenke, auch die anderer Arbeitsplätze), wie PSSIM „löscht alle Abonnements“")
  void unsubscribe() {
    Subscription a = subscriptions.subscribe(WP1, PS, "CARD/INSERTED", null);
    Subscription b = subscriptions.subscribe(WP1, PS, "CARD/REMOVED", null);
    Subscription c = subscriptions.subscribe(WP2, PS, "CARD", null);
    Subscription other = subscriptions.subscribe(WP1, "cetp://127.0.0.1:7002", "CARD", null);

    subscriptions.unsubscribe(WP1, a.id(), null);
    assertError(
        ConnectorError.INVALID_SUBSCRIPTION, () -> subscriptions.unsubscribe(WP1, a.id(), null));
    assertEquals(List.of(b, c, other), subscriptions.all());

    subscriptions.unsubscribe(WP1, null, PS);
    assertEquals(List.of(other), subscriptions.all());
    subscriptions.unsubscribe(WP1, null, PS);

    assertError(ConnectorError.SYNTAX, () -> subscriptions.unsubscribe(WP1, null, null));
    assertError(ConnectorError.SYNTAX, () -> subscriptions.unsubscribe(WP1, other.id(), PS));
    assertError(
        ConnectorError.CONTEXT_INCOMPLETE,
        () -> subscriptions.unsubscribe(new Context("M1", "CS9", "WP1", null), other.id(), null));
  }

  @Test
  @DisplayName(
      "TIP1-A_5112 RenewSubscriptions: gültige um 25 h verlängert, ungültige im Ergebnis; keine gültige → "
          + "4102; abgelaufene Anmeldungen entfernt (TAB_KON_793)")
  void renew() {
    Subscription a = subscriptions.subscribe(WP1, PS, "CARD/INSERTED", null);
    clock.advance(Duration.ofHours(24));
    Subscription b = subscriptions.subscribe(WP1, PS, "CARD/REMOVED", null);

    clock.advance(Duration.ofHours(2));
    var renewal = subscriptions.renew(WP1, List.of(a.id(), b.id(), "unbekannt"));
    assertEquals(List.of(b.id()), renewal.renewed().stream().map(Subscription::id).toList());
    assertEquals(Instant.parse("2026-10-10T15:00:00Z"), renewal.renewed().get(0).terminationTime());
    assertEquals(List.of(a.id(), "unbekannt"), renewal.invalid());
    assertEquals(List.of(b.id()), subscriptions.all().stream().map(Subscription::id).toList());

    assertError(
        ConnectorError.INVALID_SUBSCRIPTION, () -> subscriptions.renew(WP1, List.of(a.id())));
    assertError(ConnectorError.SYNTAX, () -> subscriptions.renew(WP1, List.of()));
  }

  @Test
  @DisplayName(
      "TIP1-A_4610 GetSubscription: per SubscriptionID (unbekannt → 4102), sonst die Anmeldungen des "
          + "Kontexts; @mandant-wide auch die anderer Arbeitsplätze von Mandant und Clientsystem")
  void get() {
    Subscription a = subscriptions.subscribe(WP1, PS, "CARD/INSERTED", "/Event");
    Subscription b = subscriptions.subscribe(WP2, PS, "CARD/REMOVED", null);
    Subscription c = subscriptions.subscribe(M2, PS, "CARD", null);

    assertEquals(List.of(a), subscriptions.get(WP1, null, false));
    assertEquals(
        List.of(a, b), subscriptions.get(new Context("M1", "CS1", null, null), null, true));
    assertEquals(List.of(c), subscriptions.get(WP1, c.id(), false));
    assertError(
        ConnectorError.INVALID_SUBSCRIPTION, () -> subscriptions.get(WP1, "unbekannt", false));
    assertError(
        ConnectorError.CONTEXT_INCOMPLETE,
        () -> subscriptions.get(new Context("M1", "CS1", null, null), null, false));
    clock.advance(Duration.ofHours(25));
    assertEquals(List.of(), subscriptions.get(WP1, null, true), "abgelaufen");
  }

  @Test
  @DisplayName(
      "TUC_KON_256 Schritte 5a und 5b: an gültige Anmeldungen, deren Topic Präfix ist (ohne Groß-/"
          + "Kleinschreibung) und deren Arbeitsplatz das KT aus CtID erreicht")
  void publish() {
    Subscription inserted = subscriptions.subscribe(WP1, PS, "CARD/INSERTED", null);
    Subscription card = subscriptions.subscribe(WP1, "cetp://127.0.0.1:7002", "card", null);
    subscriptions.subscribe(WP1, PS, "CARD/REMOVED", null);
    subscriptions.subscribe(WP1, PS, "CARD/INSERTED/MEHR", null);
    subscriptions.subscribe(WP2, PS, "CARD", null);
    Subscription m2 = subscriptions.subscribe(M2, PS, "CARD", null);
    subscriptions.subscribe(new Context("M1", "CS1", null, null), PS, "CARD", null);

    subscriptions.publish(inserted("KT-01"));
    assertEquals(
        List.of(
            "CARD/INSERTED → " + PS + " " + inserted.id(),
            "CARD/INSERTED → cetp://127.0.0.1:7002 " + card.id(),
            "CARD/INSERTED → " + PS + " " + m2.id()),
        sent);

    sent.clear();
    subscriptions.publish(
        new Event("CT/DISCONNECTED", Event.Type.OPERATION, Event.Severity.INFO, Map.of()));
    assertEquals(List.of(), sent);

    clock.advance(Duration.ofHours(25));
    subscriptions.publish(inserted("KT-01"));
    assertEquals(List.of(), sent, "abgelaufen");
  }

  @Test
  @DisplayName(
      "TAB_KON_571 Auto-Unsubscribe: nach EVT_MAX_TRY fehlgeschlagenen Zustellungen in Folge entfernt LIANA "
          + "alle Anmeldungen der Ereignissenke; eine erfolgreiche Zustellung setzt den Zähler zurück")
  void autoUnsubscribe() {
    subscriptions.subscribe(WP1, PS, "CARD/INSERTED", null);
    subscriptions.subscribe(WP1, PS, "CARD/REMOVED", null);
    Subscription other = subscriptions.subscribe(WP1, "cetp://127.0.0.1:7002", "CARD", null);

    subscriptions.publish(inserted("KT-01"));
    EventSink.Outcome ps = outcomes.get(0);
    EventSink.Outcome toOther = outcomes.get(1);
    ps.failed("Verbindung abgelehnt");
    ps.failed("Verbindung abgelehnt");
    toOther.failed("Verbindung abgelehnt");
    ps.delivered();
    ps.failed("Verbindung abgelehnt");
    ps.failed("Verbindung abgelehnt");
    assertEquals(3, subscriptions.all().size(), "nach delivered wieder bei 2 von 3");
    ps.failed("Verbindung abgelehnt");
    assertEquals(List.of(other), subscriptions.all());
    assertThrows(
        IllegalArgumentException.class,
        () -> new Subscriptions(infomodel, clock, (e, s, o) -> {}, 0));
  }

  @Test
  @DisplayName(
      "TIP1-A_4594 / LIANA-149: letzter Zustellversuch je Anmeldung mit Zeit, Topic und Grund; Reset und "
          + "Auto-Unsubscribe vergessen ihn")
  void letzteZustellung() {
    Subscription subscription = subscriptions.subscribe(WP1, PS, "CARD", null);
    assertTrue(subscriptions.lastDelivery(subscription.id()).isEmpty(), "noch kein Versuch");
    subscriptions.publish(inserted("KT-01"));
    outcomes.getFirst().delivered();
    assertEquals(
        new Subscriptions.Delivery(clock.instant(), "CARD/INSERTED", true, null),
        subscriptions.lastDelivery(subscription.id()).orElseThrow());
    clock.advance(Duration.ofSeconds(5));
    outcomes.getFirst().failed("Verbindung abgelehnt");
    assertEquals(
        new Subscriptions.Delivery(clock.instant(), "CARD/INSERTED", false, "Verbindung abgelehnt"),
        subscriptions.lastDelivery(subscription.id()).orElseThrow());
    outcomes.getFirst().failed("Verbindung abgelehnt");
    outcomes.getFirst().failed("Verbindung abgelehnt");
    assertTrue(subscriptions.all().isEmpty(), "EVT_MAX_TRY");
    assertTrue(subscriptions.lastDelivery(subscription.id()).isEmpty());
    outcomes.getFirst().failed("spät");
    assertTrue(
        subscriptions.lastDelivery(subscription.id()).isEmpty(),
        "nach dem Entfernen kein Eintrag mehr");

    Subscription again = subscriptions.subscribe(WP1, PS, "CARD", null);
    subscriptions.publish(inserted("KT-01"));
    outcomes.getLast().delivered();
    subscriptions.clear();
    assertTrue(subscriptions.lastDelivery(again.id()).isEmpty());
  }

  @Test
  @DisplayName("TIP1-A_4613: clear() leert die Liste (Admin-Reset wie Bootup)")
  void clear() {
    subscriptions.subscribe(WP1, PS, "CARD", null);
    subscriptions.clear();
    assertTrue(subscriptions.all().isEmpty());
  }

  static final class ManualClock extends Clock {
    private Instant now = Instant.parse("2026-10-08T12:00:00Z");

    void advance(Duration duration) {
      now = now.plus(duration);
    }

    @Override
    public ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return now;
    }
  }

  @Test
  @DisplayName(
      "LIANA-151: jede Änderung der Anmeldungen und jeder Zustellversuch meldet eine Change mit Anlass; "
          + "Ablauf (TAB_KON_571), Auto-Unsubscribe und Reset ohne SubscriptionID")
  void aenderungen() {
    List<Subscriptions.Change> changes = new ArrayList<>();
    subscriptions.addListener(changes::add);
    String id = subscriptions.subscribe(WP1, PS, "CARD", null).id();
    subscriptions.renew(WP1, List.of(id));
    subscriptions.publish(inserted("KT-01"));
    outcomes.getLast().delivered();
    subscriptions.unsubscribe(WP1, id, null);
    subscriptions.subscribe(WP1, PS, "CARD", null);
    clock.advance(Duration.ofHours(26));
    subscriptions.all();
    String other = subscriptions.subscribe(WP1, PS, "CARD", null).id();
    for (int n = 0; n < 3; n++) {
      subscriptions.publish(inserted("KT-01"));
      outcomes.getLast().failed("Verbindung abgelehnt");
    }
    subscriptions.clear();
    assertEquals(
        List.of(
            new Subscriptions.Change("subscribe", id),
            new Subscriptions.Change("renew", id),
            new Subscriptions.Change("delivery", id),
            new Subscriptions.Change("unsubscribe", id),
            changes.get(4),
            new Subscriptions.Change("expired", null),
            new Subscriptions.Change("subscribe", other),
            new Subscriptions.Change("delivery", other),
            new Subscriptions.Change("delivery", other),
            new Subscriptions.Change("delivery", other),
            new Subscriptions.Change("auto-unsubscribe", null),
            new Subscriptions.Change("reset", null)),
        changes);
    assertEquals("subscribe", changes.get(4).cause());
  }
}

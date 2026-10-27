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
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.admin.AdminServer;
import de.gematik.liana.control.LianaControl;
import de.gematik.liana.konnektor.Card;
import de.gematik.liana.konnektor.Konnektor;
import de.gematik.liana.konnektor.KonnektorEvent;
import de.gematik.liana.konnektor.KonnektorFault;
import de.gematik.liana.konnektor.Operation;
import de.gematik.liana.konnektor.ws.conn.connectorcontext.v2_0.ContextType;
import de.gematik.liana.konnektor.ws.conn.eventservice.v7_2.GetCards;
import de.gematik.liana.konnektor.ws.conn.eventservice.v7_2.GetCardsResponse;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * LIANA-137 against LIANA: {@code awaitCard} via CETP (TIP1-A_4594/4596, CETP2 without TLS as in
 * the default), the card inserted via liana-control-client; a GERROR from LIANA as a typed
 * exception.
 */
@QuarkusTest
@TestProfile(KonnektorClientTest.Basic.class)
class KonnektorClientEventsTest {

  @Inject AdminServer admin;

  @AfterEach
  void reset() {
    LianaControl.connect("http://localhost:" + admin.port()).reset();
  }

  @SuppressWarnings("unchecked")
  @Test
  @DisplayName(
      "awaitCard EGK: alle eGKs gezogen, Karte über die Admin-API gesteckt, CARD/INSERTED per CETP")
  void awaitCard() throws Exception {
    LianaControl liana = LianaControl.connect("http://localhost:" + admin.port());
    for (Map<String, Object> terminal : liana.terminals()) {
      for (Map<String, Object> slot : (List<Map<String, Object>>) terminal.get("slots")) {
        if ("EGK".equals(slot.get("cardType"))) {
          liana.ejectCard((String) terminal.get("id"), ((Number) slot.get("slot")).intValue());
        }
      }
    }
    try (Konnektor kon =
        Konnektor.builder().kon(KonnektorClientTest.export(admin.port())).build()) {
      CompletableFuture<Void> insert =
          CompletableFuture.runAsync(
              () -> {
                try {
                  Thread.sleep(500);
                } catch (InterruptedException e) {
                  Thread.currentThread().interrupt();
                }
                liana.insertCard("KT-02", 1, "egk-valid");
              });
      Card card = kon.events().awaitCard("EGK", Duration.ofSeconds(10));
      insert.get();
      assertEquals("KT-02", card.ctId());
      assertEquals(1, card.slot());
      assertEquals("EGK", card.type());
      Optional<KonnektorEvent> event =
          kon.events().received().stream()
              .filter(e -> "CARD/INSERTED".equals(e.topic()))
              .findFirst();
      assertTrue(event.isPresent(), kon.events().received().toString());
      assertEquals(card.handle(), event.get().parameters().get("CardHandle"));
    }
  }

  @Test
  @DisplayName(
      "GetCards mit unbekanntem Mandanten: GERROR von LIANA als KonnektorFault mit Code 4021 (KUC_1603_008)")
  void fehlerTrace() throws Exception {
    try (Konnektor kon =
        Konnektor.builder().kon(KonnektorClientTest.export(admin.port())).build()) {
      ContextType context = new ContextType();
      context.setMandantId("UNBEKANNT");
      context.setClientSystemId(kon.context().clientSystemId());
      context.setWorkplaceId(kon.context().workplaceId());
      GetCards request = new GetCards();
      request.setContext(context);
      KonnektorFault fault =
          assertThrows(
              KonnektorFault.class,
              () -> kon.invoke(Operation.GET_CARDS, request, GetCardsResponse.class));
      assertEquals(Optional.of(4021), fault.code());
      assertInstanceOf(KonnektorFault.class, fault);
      assertTrue(fault.gematikError().errorText().isPresent());
      assertEquals("Konnektor", fault.gematikError().traces().get(0).compType());
    }
  }
}

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

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.TestPorts;
import de.gematik.liana.admin.AdminServer;
import de.gematik.liana.konnektor.Credentials;
import de.gematik.liana.konnektor.KonConfig;
import de.gematik.liana.konnektor.Konnektor;
import de.gematik.liana.konnektor.Operation;
import de.gematik.liana.konnektor.ws.conn.connectorcontext.v2_0.ContextType;
import de.gematik.liana.konnektor.ws.conn.eventservice.v7_2.GetCards;
import de.gematik.liana.konnektor.ws.conn.eventservice.v7_2.GetCardsResponse;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * LIANA-133 AC 1: the Konnektor client reads the {@code .kon} export of LIANA ({@code basic}) and
 * calls GetCards via the rewritten endpoints.
 */
@QuarkusTest
@TestProfile(KonnektorClientTest.Basic.class)
class KonnektorClientTest {

  public static class Basic implements QuarkusTestProfile {
    @Override
    public Map<String, String> getConfigOverrides() {
      return TestPorts.config("liana.kon-export.url", "http://localhost:" + TestPorts.HTTP + "/");
    }
  }

  @Inject AdminServer admin;

  static GetCardsResponse getCards(Konnektor kon) {
    ContextType context = new ContextType();
    context.setMandantId(kon.context().mandantId());
    context.setClientSystemId(kon.context().clientSystemId());
    context.setWorkplaceId(kon.context().workplaceId());
    GetCards request = new GetCards();
    request.setContext(context);
    return kon.invoke(Operation.GET_CARDS, request, GetCardsResponse.class);
  }

  static KonConfig export(int adminPort) {
    String raw =
        given()
            .port(adminPort)
            .get("/admin/clients/CS1/config.kon")
            .then()
            .statusCode(200)
            .extract()
            .asString();
    return KonConfig.parse(raw, name -> null);
  }

  @Test
  @DisplayName(
      "LIANA-133: config.kon (basic, rewriteServiceEndpoints) → connector.sds → GetCards mit Karten")
  void basic() throws Exception {
    KonConfig kon = export(admin.port());
    assertTrue(kon.credentials() instanceof Credentials.Basic, kon.toString());
    try (Konnektor konnektor = Konnektor.builder().kon(kon).build()) {
      assertEquals("LIANA", konnektor.serviceDirectory().product().vendorId());
      GetCardsResponse cards = getCards(konnektor);
      assertEquals("OK", cards.getStatus().getResult());
      assertFalse(cards.getCards().getCard().isEmpty());
    }
  }
}

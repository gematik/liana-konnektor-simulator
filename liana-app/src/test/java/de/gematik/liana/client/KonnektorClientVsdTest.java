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

import de.gematik.liana.admin.AdminServer;
import de.gematik.liana.konnektor.Card;
import de.gematik.liana.konnektor.Konnektor;
import de.gematik.liana.konnektor.Vsd;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import java.time.LocalDateTime;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * LIANA-105 AC 6: ReadVSD via the domain API of the Konnektor client against LIANA (LIANA-119),
 * egk-valid in KT-01/1 and smcb-valid in KT-01/2 from the YAML state.
 */
@QuarkusTest
@TestProfile(KonnektorClientTest.Basic.class)
class KonnektorClientVsdTest {

  @Inject AdminServer admin;

  @AfterEach
  void reset() {
    given().port(admin.port()).post("/admin/reset").then().statusCode(200);
  }

  @Test
  @DisplayName(
      "VSDM-A_2567: ReadVSD nach VerifyPin PIN.SMC liefert PD und VD entpackt im Zeichensatz der eGK, "
          + "ohne GVD, und den VSD_Status")
  void readVsd() throws Exception {
    try (Konnektor kon =
        Konnektor.builder().kon(KonnektorClientTest.export(admin.port())).build()) {
      Card egk =
          kon.cards().ofType("EGK").stream()
              .filter(c -> c.ctId().equals("KT-01") && c.slot() == 1)
              .findFirst()
              .orElseThrow();
      Card smcb =
          kon.cards().ofType("SM-B").stream()
              .filter(c -> c.ctId().equals("KT-01") && c.slot() == 2)
              .findFirst()
              .orElseThrow();
      assertTrue(kon.card(smcb).pin("PIN.SMC").verify().ok());

      Vsd vsd = kon.card(egk).readVsd(smcb.handle());
      String pd = vsd.pdXml();
      assertTrue(pd.contains("<Versicherten_ID>X110630769</Versicherten_ID>"), pd);
      assertTrue(pd.contains("<Vorname>Dörthe Abigail</Vorname>"), pd);
      assertTrue(pd.contains("<Nachname>Dåmmer-Ørsted</Nachname>"), pd);
      assertTrue(
          vsd.vdXml().contains("<Kostentraegerkennung>109500969</Kostentraegerkennung>"),
          vsd.vdXml());
      assertFalse(vsd.gvd().isPresent());
      assertEquals("Dörthe Abigail", vsd.pdValue("Vorname").orElseThrow());
      assertEquals("Dåmmer-Ørsted", vsd.pdValue("Nachname").orElseThrow());
      assertEquals("109500969", vsd.vdValue("Kostentraegerkennung").orElseThrow());
      assertEquals(
          new Vsd.Status(false, LocalDateTime.parse("2025-04-07T10:01:58"), "5.2.0"), vsd.status());
    }
  }
}

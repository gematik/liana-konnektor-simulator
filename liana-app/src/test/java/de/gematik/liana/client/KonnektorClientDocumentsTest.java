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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.admin.AdminServer;
import de.gematik.liana.konnektor.Card;
import de.gematik.liana.konnektor.Document;
import de.gematik.liana.konnektor.KonConfig;
import de.gematik.liana.konnektor.Konnektor;
import de.gematik.liana.konnektor.KonnektorFault;
import de.gematik.liana.konnektor.ProductUnsupportedException;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * LIANA-136 AC 2 against LIANA: signing, encryption and verification run up to the access check
 * (TUC_KON_000, LIANA-60); after that the client reports the decision-12 fault as {@link
 * ProductUnsupportedException}, and aborts operations without implementation without a call.
 */
@QuarkusTest
@TestProfile(KonnektorClientTest.Basic.class)
class KonnektorClientDocumentsTest {

  @Inject AdminServer admin;

  @Test
  @DisplayName(
      "GetJobNumber vollständig; SignDocument ohne PIN.SMC → KonnektorFault 4085 (LIANA-112.02); "
          + "VerifyDocument XML ohne Signatur → KonnektorFault 4253 (LIANA-112.09); EncryptDocument, DecryptDocument nach "
          + "der Zugriffsprüfung als ProductUnsupportedException")
  void zugriffspruefungUndLuecken() throws Exception {
    try (Konnektor kon =
        Konnektor.builder().kon(KonnektorClientTest.export(admin.port())).build()) {
      assertTrue(kon.signatures().jobNumber().matches("[A-Z]{3}-\\d+"));
      Card smcb = kon.cards().ofType("SM-B").get(0);
      Document text = Document.of("Befund".getBytes(), "text/plain");
      KonnektorFault sign =
          assertThrows(
              KonnektorFault.class, () -> kon.card(smcb).sign(text).cades().detached().sign());
      assertEquals(Optional.of(4085), sign.code(), sign.getMessage());
      KonnektorFault verify =
          assertThrows(
              KonnektorFault.class, () -> kon.verify().signature(Document.xml("<a/>".getBytes())));
      assertEquals(Optional.of(4253), verify.code(), verify.getMessage());
      assertThrows(
          ProductUnsupportedException.class, () -> kon.encrypt(text).toCard(smcb.handle()));
      assertThrows(
          ProductUnsupportedException.class, () -> kon.card(smcb).decrypt(new byte[] {0x30, 0x00}));
    }
  }

  @Test
  @DisplayName(
      "Zugriffsprüfung: unbekannter Mandant → KonnektorFault 4021, nicht ProductUnsupportedException")
  void zugriffVerweigert() throws Exception {
    KonConfig kon = KonnektorClientTest.export(admin.port());
    try (Konnektor good = Konnektor.builder().kon(kon).build();
        Konnektor wrong =
            Konnektor.builder()
                .kon(kon)
                .context(
                    "UNBEKANNT", kon.context().clientSystemId(), kon.context().workplaceId(), null)
                .build()) {
      Card smcb = good.cards().ofType("SM-B").get(0);
      KonnektorFault fault =
          assertThrows(
              KonnektorFault.class,
              () -> wrong.card(smcb).sign(Document.of("x".getBytes(), "text/plain")).sign("ABC-1"));
      assertEquals(Optional.of(4021), fault.code());
    }
  }

  @Test
  @DisplayName(
      "VerifyCertificate: von LIANA nicht umgesetzt, Abbruch ohne Aufruf; StopSignature ohne laufenden "
          + "Auftrag → KonnektorFault 4243 (LIANA-112.05); Komfortsignatur mit der SM-B → 4274 bzw. 4269 "
          + "(LIANA-112.06)")
  void nichtUmgesetzt() throws Exception {
    try (Konnektor kon =
        Konnektor.builder().kon(KonnektorClientTest.export(admin.port())).build()) {
      Card smcb = kon.cards().ofType("SM-B").get(0);
      assertThrows(
          UnsupportedOperationException.class,
          () -> kon.verify().certificate(kon.card(smcb).certificate("C.AUT").read()));
      KonnektorFault stop =
          assertThrows(KonnektorFault.class, () -> kon.signatures().stop("ABC-123"));
      assertEquals(Optional.of(4243), stop.code(), stop.getMessage());
      KonnektorFault activate =
          assertThrows(KonnektorFault.class, () -> kon.card(smcb).comfort().activate());
      assertEquals(Optional.of(4274), activate.code(), activate.getMessage());
      KonnektorFault status =
          assertThrows(KonnektorFault.class, () -> kon.card(smcb).comfort().status());
      assertEquals(Optional.of(4269), status.code(), status.getMessage());
    }
  }
}

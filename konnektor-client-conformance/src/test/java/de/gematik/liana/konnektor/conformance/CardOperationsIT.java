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
package de.gematik.liana.konnektor.conformance;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import de.gematik.liana.control.LianaControl;
import de.gematik.liana.konnektor.Card;
import de.gematik.liana.konnektor.CardTerminal;
import de.gematik.liana.konnektor.Konnektor;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * Card operations through the domain API (LIANA-135), in a fixed order so that a recording ({@code
 * conformance.record}) can serve as a replay for the client tests. PIN entries only with {@code
 * conformance.interactive}; changing, unblocking, enabling and disabling a PIN additionally only
 * with {@code conformance.destructive}. Against LIANA ({@code conformance.liana-admin}), EjectCard
 * pulls the card via the Admin API, and at the end {@code POST /admin/reset} restores the state.
 */
@ExtendWith(ConformanceTarget.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class CardOperationsIT {

  static final String DESTRUCTIVE = "conformance.destructive";

  private static Konnektor kon() {
    return ConformanceTarget.konnektor();
  }

  private static Card smcb() {
    List<Card> cards = kon().cards().ofType("SM-B");
    assumeFalse(cards.isEmpty(), "keine SMC-B gesteckt");
    return cards.get(0);
  }

  private static Optional<LianaControl> liana() {
    String admin = ConformanceTarget.setting(ProductIT.ADMIN);
    return admin == null ? Optional.empty() : Optional.of(LianaControl.connect(admin));
  }

  @AfterAll
  static void reset() {
    liana().ifPresent(LianaControl::reset);
  }

  @Test
  @Order(1)
  @DisplayName("cards(): list, ofType, byIccsn, byHandle")
  void karten() {
    List<Card> all = kon().cards().list();
    assertFalse(all.isEmpty(), "keine Karte gesteckt");
    Card smcb = smcb();
    assertEquals(smcb.handle(), kon().cards().byIccsn(smcb.iccsn()).orElseThrow().handle());
    assertEquals(smcb.iccsn(), kon().cards().byHandle(smcb.handle()).orElseThrow().iccsn());
  }

  @Test
  @Order(2)
  @DisplayName(
      "certificate(C.AUT): read, readAll, asPem, expiration; byTelematikId über die Admission")
  void zertifikat() {
    Card smcb = smcb();
    X509Certificate aut = kon().card(smcb).certificate("C.AUT").ecc().read();
    assertFalse(kon().card(smcb).certificate("C.AUT").readAll().isEmpty());
    assertTrue(
        kon().card(smcb).certificate("C.AUT").asPem().startsWith("-----BEGIN CERTIFICATE-----"));
    assertEquals(aut.getNotAfter().toInstant(), kon().card(smcb).certificate("C.AUT").expiration());
    String telematikId = de.gematik.liana.konnektor.Certificates.telematikId(aut).orElseThrow();
    assertTrue(
        kon().cards().byTelematikId(telematikId).stream()
            .anyMatch(c -> c.handle().equals(smcb.handle())));
  }

  @Test
  @Order(3)
  @DisplayName("terminals(): list; requestCard auf einen belegten Slot liefert die Karte sofort")
  void terminals() {
    List<CardTerminal> terminals = kon().terminals().list();
    assertFalse(terminals.isEmpty());
    Card smcb = smcb();
    Card requested =
        kon().terminals().requestCard(smcb.ctId(), smcb.slot(), Duration.ofSeconds(5), null);
    assertEquals(smcb.iccsn(), requested.iccsn());
  }

  @Test
  @Order(4)
  @DisplayName("pin(PIN.SMC).status()")
  void pinStatus() {
    assertTrue(
        List.of("VERIFIED", "VERIFIABLE", "TRANSPORT_PIN", "EMPTY_PIN", "BLOCKED", "DISABLED")
            .contains(kon().card(smcb()).pin("PIN.SMC").status().status()));
  }

  @Test
  @Order(5)
  @DisplayName("interaktiv: pin(PIN.SMC).verify(), dann authenticate(hash).ecdsa() und jws(claims)")
  void verifyUndAuthenticate() throws Exception {
    assumeTrue(ConformanceTarget.interactive(), ConformanceTarget.INTERACTIVE + " nicht gesetzt");
    Card smcb = smcb();
    assertEquals("OK", kon().card(smcb).pin("PIN.SMC").verify().result());
    byte[] hash = MessageDigest.getInstance("SHA-256").digest("LIANA-135".getBytes());
    assertTrue(kon().card(smcb).authenticate(hash).ecdsa().length > 60);
    String jws = kon().card(smcb).jws(claims()).header("typ", "JWT").sign();
    assertEquals(3, jws.split("\\.").length);
    assertTrue(new String(Base64.getUrlDecoder().decode(jws.split("\\.")[0])).contains("\"x5c\""));
  }

  @Test
  @Order(6)
  @DisplayName(
      "interaktiv, verändernd: eGK disable/enable MRPIN.GDD, SMC-B change und unblock PIN.SMC")
  void pinVerwaltung() {
    assumeTrue(
        ConformanceTarget.interactive()
            && Boolean.parseBoolean(ConformanceTarget.setting(DESTRUCTIVE)),
        DESTRUCTIVE + " nicht gesetzt");
    List<Card> egks = kon().cards().ofType("EGK");
    assumeFalse(egks.isEmpty(), "keine eGK gesteckt");
    Card egk = egks.get(0);
    assertEquals("OK", kon().card(egk).pin("MRPIN.GDD").disable().result());
    assertEquals("DISABLED", kon().card(egk).pin("MRPIN.GDD").status().status());
    assertEquals("OK", kon().card(egk).pin("MRPIN.GDD").enable().result());
    Card smcb = smcb();
    assertEquals("OK", kon().card(smcb).pin("PIN.SMC").change().result());
    assertEquals("OK", kon().card(smcb).pin("PIN.SMC").unblock().result());
  }

  @Test
  @Order(7)
  @DisplayName("nur gegen LIANA: ejectCard wartet, bis die Admin-API die Karte zieht")
  void ejectCard() throws Exception {
    Optional<LianaControl> liana = liana();
    assumeTrue(liana.isPresent(), ProductIT.ADMIN + " nicht gesetzt");
    Card smcb = smcb();
    CompletableFuture<Void> eject =
        CompletableFuture.runAsync(
            () ->
                kon()
                    .terminals()
                    .ejectCard(smcb.handle(), Duration.ofSeconds(10), "Bitte Karte ziehen"));
    Thread.sleep(500);
    liana.get().ejectCard(smcb.ctId(), smcb.slot());
    assertDoesNotThrow(
        () -> eject.get(15, TimeUnit.SECONDS), "ejectCard kehrt nach dem Ziehen zurück");
  }

  /** Fixed order: Map.of iterates differently per JVM, the recording needs the same payload. */
  static Map<String, Object> claims() {
    Map<String, Object> claims = new java.util.LinkedHashMap<>();
    claims.put("sub", "LIANA-135");
    claims.put("iat", 1760443200);
    return claims;
  }
}

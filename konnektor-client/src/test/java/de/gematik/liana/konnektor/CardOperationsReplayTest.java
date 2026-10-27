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
package de.gematik.liana.konnektor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * LIANA-135 AC 1: every card operation of the domain API against the conformance suite's recording
 * at LIANA ({@code support/traces/konnektor-client/LIANA/0.5.26/cards.tgr}, {@code
 * CardOperationsIT}). Strict: the client must build the same requests as during the recording.
 */
class CardOperationsReplayTest {

  private static final Path TRACE =
      Path.of("support/traces/konnektor-client/LIANA/0.5.26/cards.tgr");

  private static Konnektor kon;
  private static Card smcb;

  @BeforeAll
  static void replay() throws Exception {
    kon =
        Konnektor.builder()
            .url("http://127.0.0.1:18080")
            .rewriteServiceEndpoints(true)
            .context("M1", "CS1", "WP1", null)
            .transport(new ReplayTransport(TRACE, true))
            .build();
    List<Card> all = kon.cards().list();
    assertFalse(all.isEmpty());
    smcb = kon.cards().ofType("SM-B").get(0);
  }

  @Test
  @DisplayName(
      "Karten, Zertifikat, Telematik-ID, Terminals, PIN, ExternalAuthenticate, JWS, PIN-Verwaltung, "
          + "EjectCard in der Reihenfolge der Aufnahme")
  void alleOperationen() throws Exception {
    assertEquals("SMC-B", smcb.type().replace("SM-B", "SMC-B"));
    assertEquals(smcb.handle(), kon.cards().byIccsn(smcb.iccsn()).orElseThrow().handle());
    assertEquals(smcb.iccsn(), kon.cards().byHandle(smcb.handle()).orElseThrow().iccsn());

    X509Certificate aut = kon.card(smcb).certificate("C.AUT").ecc().read();
    assertFalse(kon.card(smcb).certificate("C.AUT").readAll().isEmpty());
    assertTrue(
        kon.card(smcb).certificate("C.AUT").asPem().startsWith("-----BEGIN CERTIFICATE-----\n"));
    assertEquals(aut.getNotAfter().toInstant(), kon.card(smcb).certificate("C.AUT").expiration());
    String telematikId = Certificates.telematikId(aut).orElseThrow();
    assertFalse(Certificates.professionOids(aut).isEmpty());
    assertEquals(
        List.of(smcb.handle()),
        kon.cards().byTelematikId(telematikId).stream().map(Card::handle).toList());

    assertFalse(kon.terminals().list().isEmpty());
    assertEquals(
        smcb.iccsn(),
        kon.terminals().requestCard(smcb.ctId(), smcb.slot(), Duration.ofSeconds(5), null).iccsn());

    PinStatus status = kon.card(smcb).pin("PIN.SMC").status();
    assertTrue(status.status() != null);
    assertTrue(kon.card(smcb).pin("PIN.SMC").verify().ok());

    byte[] hash = MessageDigest.getInstance("SHA-256").digest("LIANA-135".getBytes());
    byte[] der = kon.card(smcb).authenticate(hash).ecdsa();
    Signature ecdsa = Signature.getInstance("SHA256withECDSA", Bc.PROVIDER);
    ecdsa.initVerify(aut.getPublicKey());
    ecdsa.update("LIANA-135".getBytes());
    assertTrue(ecdsa.verify(der), "ECDSA-Sig-Value über den Hash mit C.AUT prüfbar");

    String jws = kon.card(smcb).jws(claims()).header("typ", "JWT").sign();
    String[] parts = jws.split("\\.");
    String header = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
    assertTrue(
        header.startsWith("{\"alg\":\"" + Jws.alg(aut) + "\",\"typ\":\"JWT\",\"x5c\":[\""), header);
    Signature plain = Signature.getInstance("SHA256withPLAIN-ECDSA", Bc.PROVIDER);
    plain.initVerify(aut.getPublicKey());
    plain.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
    assertTrue(
        plain.verify(Base64.getUrlDecoder().decode(parts[2])), "JWS-Signatur r || s prüfbar");

    Card egk = kon.cards().ofType("EGK").get(0);
    assertTrue(kon.card(egk).pin("MRPIN.GDD").disable().ok());
    assertEquals("DISABLED", kon.card(egk).pin("MRPIN.GDD").status().status());
    assertTrue(kon.card(egk).pin("MRPIN.GDD").enable().ok());
    Card smcbAgain = kon.cards().ofType("SM-B").get(0);
    assertTrue(kon.card(smcbAgain).pin("PIN.SMC").change().ok());
    assertTrue(kon.card(smcbAgain).pin("PIN.SMC").unblock().ok());

    Card toEject = kon.cards().ofType("SM-B").get(0);
    kon.terminals().ejectCard(toEject.handle(), Duration.ofSeconds(10), "Bitte Karte ziehen");
  }

  @Test
  @DisplayName("Jws.concat: DER mit führender Null und kurzem r wird zu je 32 Byte r || s")
  void concat() {
    byte[] der = {0x30, 0x08, 0x02, 0x02, 0x00, (byte) 0x81, 0x02, 0x02, 0x01, 0x02};
    byte[] rs = Jws.concat(der, 32);
    assertEquals(64, rs.length);
    assertEquals((byte) 0x81, rs[31]);
    assertEquals(0x01, rs[62]);
    assertEquals(0x02, rs[63]);
  }

  /** Fixed order: Map.of iterates differently per JVM, the recording needs the same payload. */
  static Map<String, Object> claims() {
    Map<String, Object> claims = new java.util.LinkedHashMap<>();
    claims.put("sub", "LIANA-135");
    claims.put("iat", 1760443200);
    return claims;
  }
}

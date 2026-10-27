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
package de.gematik.liana.crypto;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * TUC_KON_037 offline for C.CH.AUT (TUC_KON_018 step 6a) against the RU TSL from {@code
 * support/pki/tsl/}: C.CH.AUT.E256 of egk-valid (GEM.EGK-CA57, valid 2025-04-07 to 2030-04-06), as
 * kartos delivers it.
 */
class EgkCertificateCheckTest {

  private static final TrustSpace TSL = TrustSpace.load(ScenarioSignerCheckTest.TSL, List.of());
  private static byte[] egkValidAut;

  @BeforeAll
  static void aut() throws Exception {
    if (Security.getProvider(CryptoProviders.BC) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
    String response =
        Files.readAllLines(Path.of("liana-kern/src/test/resources/apdu/egk-valid-vsd.txt")).stream()
            .filter(l -> l.startsWith("00B08400000000 "))
            .findFirst()
            .orElseThrow()
            .split(" ")[1];
    egkValidAut = HexFormat.of().parseHex(response.substring(0, response.length() - 4));
  }

  private static Clock at(String instant) {
    return Clock.fixed(Instant.parse(instant), ZoneOffset.UTC);
  }

  @Test
  @DisplayName("TUC_KON_037 / TUC_PKI_002–004: C.CH.AUT der egk-valid ist offline gültig")
  void gueltig() {
    assertNull(
        new EgkCertificateCheck(TSL, at("2026-10-15T00:00:00Z")).offlineInvalid(egkValidAut));
  }

  @Test
  @DisplayName("VSDM-A_2569 / TUC_PKI_002: nach Ablauf (2030-04-06) zeitlich ungültig")
  void abgelaufen() {
    String reason =
        new EgkCertificateCheck(TSL, at("2030-04-07T00:00:00Z")).offlineInvalid(egkValidAut);
    assertTrue(reason != null && reason.contains("zeitlich nicht gültig"), reason);
  }

  @Test
  @DisplayName(
      "TUC_PKI_003: Aussteller weder in der TSL noch importiert (popp-signer der Replay-CA)")
  void ausstellerUnbekannt() throws Exception {
    String pem = Files.readString(Path.of("support/pki/replay/popp-signer.pem"));
    byte[] der = Base64.getMimeDecoder().decode(pem.replaceAll("-----[A-Z ]+-----", ""));
    String reason = new EgkCertificateCheck(TSL, at("2026-10-15T00:00:00Z")).offlineInvalid(der);
    assertTrue(reason != null && reason.contains("weder in TSL noch importiert"), reason);
  }

  @Test
  @DisplayName("TUC_PKI_004: verfälschte Signatur (letztes Oktett) → ungültig")
  void signatur() {
    byte[] der = egkValidAut.clone();
    der[der.length - 1] ^= 0x01;
    String reason = new EgkCertificateCheck(TSL, at("2026-10-15T00:00:00Z")).offlineInvalid(der);
    assertTrue(reason != null && reason.contains("Signatur ungültig"), reason);
  }
}

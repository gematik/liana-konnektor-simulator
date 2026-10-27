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
package de.gematik.liana.sm;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Identity of LIANA as terminal (hop B, LIANA-28) from the gSMC-KT, chain to the roots of the card.
 */
class TerminalIdentityTest {

  private static final HexFormat HEX = HexFormat.of().withUpperCase();
  private static final Path TSL = Path.of("support/pki/tsl/ECC-RSA_TSL-ref.xml");
  private static final Path EGK = Path.of("support/images/egk-valid.xml");
  private static final Path GSMC_KT_ROOT6 = Path.of("support/images/gsmc-kt/gsmckt-root6.xml");
  private static final Path GSMC_KT_VALID = Path.of("support/images/gsmckt-valid.xml");

  @Test
  @DisplayName(
      "gemSpec_PKI Tab_PKI_937: die TSL liefert die Cross-CV-Zertifikate zwischen den CVC-Roots, ohne die "
          + "selbst signierten")
  void links() {
    List<Cvc> links = TerminalIdentity.links(TSL);
    assertTrue(links.stream().noneMatch(cvc -> java.util.Arrays.equals(cvc.car(), cvc.chr())));
    assertTrue(
        links.stream()
            .anyMatch(
                cvc ->
                    HEX.formatHex(cvc.car()).equals("4445475858870222")
                        && HEX.formatHex(cvc.chr()).equals("4445475858860220")),
        "Cross-CVC 860220 unter 870222");
  }

  @Test
  @DisplayName("gSMC-KT unter derselben Root wie die eGK: CA- und Rollen-CVC, kein Cross-CVC")
  void sameRoot() {
    TerminalIdentity identity = TerminalIdentity.of(GSMC_KT_ROOT6, TerminalIdentity.links(TSL));
    List<Cvc> chain = identity.chainFor(ImageObjects.load(EGK).verificationKeys()).orElseThrow();
    assertEquals(
        List.of("4445475858120223", "000A80276883110000152716"),
        chain.stream().map(cvc -> HEX.formatHex(cvc.chr())).toList());
    assertArrayEquals(identity.key().point(), identity.endEntity().publicKey());
  }

  @Test
  @DisplayName(
      "gSMC-KT unter einer anderen Root (860220) als die eGK (870222): zuerst das Cross-CVC aus der TSL")
  void crossRoot() {
    TerminalIdentity identity = TerminalIdentity.of(GSMC_KT_VALID, TerminalIdentity.links(TSL));
    List<Cvc> chain = identity.chainFor(ImageObjects.load(EGK).verificationKeys()).orElseThrow();
    assertEquals(
        List.of(
            "4445475858870222 → 4445475858860220",
            "4445475858860220 → 4445475858120220",
            "4445475858120220 → 000A80276883110000148887"),
        chain.stream()
            .map(cvc -> HEX.formatHex(cvc.car()) + " → " + HEX.formatHex(cvc.chr()))
            .toList());
    assertTrue(
        TerminalIdentity.of(GSMC_KT_VALID, List.of())
            .chainFor(ImageObjects.load(EGK).verificationKeys())
            .isEmpty(),
        "ohne TSL kein Weg");
  }

  @Test
  @DisplayName(
      "TIP1-A_4572 TUC_KON_005 Variante (9): ohne die Roots der Zielkarte zuerst CA- und Rollen-CVC, dann je "
          + "eine Kette über die Cross-CVCs der TSL ab jeder weiteren Root, kürzeste zuerst")
  void chains() {
    TerminalIdentity identity = TerminalIdentity.of(GSMC_KT_VALID, TerminalIdentity.links(TSL));
    List<List<Cvc>> chains = identity.chains();
    assertEquals(
        List.of(
            "4445475858860220 → 4445475858120220", "4445475858120220 → 000A80276883110000148887"),
        chains.getFirst().stream()
            .map(cvc -> HEX.formatHex(cvc.car()) + " → " + HEX.formatHex(cvc.chr()))
            .toList());
    assertTrue(
        chains.stream()
            .anyMatch(
                chain ->
                    chain.size() == 3
                        && HEX.formatHex(chain.getFirst().car()).equals("4445475858870222")),
        "über 870222");
    for (int i = 1; i < chains.size(); i++) {
      assertTrue(chains.get(i - 1).size() <= chains.get(i).size(), "kürzeste zuerst");
    }
    assertEquals(
        1,
        TerminalIdentity.of(GSMC_KT_VALID, List.of()).chains().size(),
        "ohne TSL nur die eigene Root");
  }

  @Test
  @DisplayName("Ein Image ohne die Objekte der gSMC-KT ist keine Identität als Terminal")
  void notAGsmcKt() {
    IllegalArgumentException e =
        assertThrows(IllegalArgumentException.class, () -> TerminalIdentity.of(EGK, List.of()));
    assertEquals(EGK + ": EF.C.CA_SMC.CS.E256 fehlt", e.getMessage());
  }

  @Test
  @DisplayName(
      "Zwilling: PrK.eGK.AUT_CVC.E256 (Schlüsselreferenz 09) kann elcSessionkey4SM, passt zum CVC der eGK")
  void twin() {
    ImageObjects egk = ImageObjects.load(EGK);
    ElcSessionkey4Sm.KeyPair key = egk.privateKey(0x09, "elcSessionkey4SM").orElseThrow();
    assertArrayEquals(egk.cvc("EF.C.eGK.AUT_CVC.E256").publicKey(), key.point());
    assertTrue(egk.privateKey(0x09, "elcSessionkey4TC").isEmpty());
    assertEquals(
        List.of("4445475858870222", "0000000000000013"),
        egk.verificationKeys().stream().map(HEX::formatHex).toList());
  }

  @Test
  @DisplayName(
      "A_16554: Karte und Terminal kommen mit vertauschten Rollen auf dieselben Sitzungsschlüssel, SSC 0")
  void sessionkeys() {
    ElcSessionkey4Sm.KeyPair cardStatic = ElcSessionkey4Sm.ephemeral();
    ElcSessionkey4Sm.KeyPair cardEphemeral = ElcSessionkey4Sm.ephemeral();
    ElcSessionkey4Sm.KeyPair terminalStatic = ElcSessionkey4Sm.ephemeral();
    ElcSessionkey4Sm.KeyPair terminalEphemeral = ElcSessionkey4Sm.ephemeral();
    SecureMessaging.Session card =
        ElcSessionkey4Sm.asCard(
            cardStatic, cardEphemeral, terminalStatic.point(), terminalEphemeral.point());
    SecureMessaging.Session terminal =
        ElcSessionkey4Sm.asTerminal(
            terminalStatic, terminalEphemeral, cardStatic.point(), cardEphemeral.point());
    assertArrayEquals(card.kEnc(), terminal.kEnc());
    assertArrayEquals(card.kMac(), terminal.kMac());
    assertArrayEquals(new byte[16], card.ssc());
    assertThrows(
        IllegalArgumentException.class,
        () ->
            ElcSessionkey4Sm.asCard(
                cardStatic,
                cardEphemeral,
                terminalStatic.point(),
                HEX.parseHex("04" + "00".repeat(64))));
  }
}

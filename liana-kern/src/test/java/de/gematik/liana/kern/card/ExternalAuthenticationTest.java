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
package de.gematik.liana.kern.card;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import de.gematik.liana.kern.access.Context;
import de.gematik.liana.kern.access.Infomodel;
import de.gematik.liana.kern.error.ConnectorError;
import de.gematik.liana.kern.error.ConnectorException;
import de.gematik.liana.kern.terminal.TerminalRegistry;
import java.math.BigInteger;
import java.nio.file.Files;
import java.time.Clock;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

/**
 * ExternalAuthenticate (TIP1-A_5439-02) against the recorded smcb-valid (ECDSA with
 * PrK.HCI.AUT.E256) and hba-valid (PrK.HP.AUT.E256).
 */
class ExternalAuthenticationTest {

  private static final Context CTX = new Context("M1", "CS1", "WP1", null);
  private static final HexFormat HEX = HexFormat.of().withUpperCase();

  /** The hash the popp-client has signed in the TU trace (request 12). */
  private static final byte[] HASH =
      HEX.parseHex("F13A9BEAA8AC0B4D19B58447C85229559C1BE459C8055A83E1A63812354717FE");

  private final RecordedCards kt01 = new RecordedCards("KT-01");
  private final TerminalRegistry registry = new TerminalRegistry(List.of(kt01));
  private final CardList cards = new CardList(registry, Clock.systemUTC());
  private final Infomodel infomodel =
      new Infomodel(
          List.of("M1"),
          List.of("CS1", "CS2"),
          List.of(
              new Infomodel.Workplace(
                  "WP1", List.of("M1"), List.of("CS1", "CS2"), List.of("KT-01"))));
  private final AuthState authState = new AuthState();
  private final CardAccess access = new CardAccess(infomodel, cards, new CardLocks());
  private final PinVerification pins = new PinVerification(access, registry, authState);
  private final ExternalAuthentication external =
      new ExternalAuthentication(access, registry, authState);
  private String egk;
  private String smcb;
  private String hba;

  @BeforeEach
  void stecken() {
    cards.start();
    kt01.insert(1, RecordedTerminal.EGK_VALID)
        .insert(2, RecordedTerminal.SMCB_VALID)
        .also(2, RecordedTerminal.SMCB_VALID_SIGN)
        .insert(3, RecordedTerminal.HBA_VALID)
        .also(3, RecordedTerminal.HBA_VALID_OPS);
    egk = cards.card("KT-01", 1).orElseThrow().cardHandle();
    smcb = cards.card("KT-01", 2).orElseThrow().cardHandle();
    hba = cards.card("KT-01", 3).orElseThrow().cardHandle();
  }

  @Test
  @DisplayName(
      "TIP1-A_5439-02 / TAB_KON_784 HBAx: nach VerifyPin PIN.CH signiert PrK.HP.AUT.E256 in DF.ESIGN "
          + "(keyIdentifier 06, MSE SET DST 86/signECDSA); ohne PIN.CH oder nur mit PIN.SMC-Versuch → 4085")
  void hba() throws Exception {
    assertError(ConnectorError.ACCESS_CONDITIONS, () -> external.sign(CTX, hba, HASH));
    pins.verify(CTX, hba, "PIN.CH");
    kt01.sent.get(3).clear();

    byte[] signature = external.sign(CTX, hba, HASH);

    assertEquals(
        List.of(
            "00A4040C0AA000000167455349474E",
            "002241B606840186800100",
            "002A9E9A20" + HEX.formatHex(HASH) + "00"),
        kt01.sent.get(3));
    assertEquals(cardSignature(RecordedTerminal.HBA_VALID_OPS), plain(signature));
  }

  @Test
  @DisplayName(
      "TIP1-A_5439-02 / TUC_KON_218: nach VerifyPin signiert PrK.HCI.AUT.E256 den Hash (MSE SET DST 86/signECDSA, "
          + "PSO CDS); (r, s) der Karte als ECDSA-Sig-Value. Die Prüfung mit C.HCI.AUT (brainpoolP256r1) braucht BC: "
          + "AuthSignatureServiceTest")
  void signatur() throws Exception {
    pins.verify(CTX, smcb, "PIN.SMC");
    kt01.sent.get(2).clear();

    byte[] signature = external.sign(CTX, smcb, HASH);

    assertEquals(
        List.of(
            "00A4040C0AA000000167455349474E",
            "002241B606840186800100",
            "002A9E9A20" + HEX.formatHex(HASH) + "00"),
        kt01.sent.get(2));
    assertEquals(cardSignature(RecordedTerminal.SMCB_VALID_SIGN), plain(signature));
  }

  @Test
  @DisplayName(
      "TUC_KON_218 Schritt 3 → 4085: ohne VerifyPin in der Kartensitzung, auch wenn ein anderes Clientsystem verifiziert hat")
  void ohnePin() {
    assertError(ConnectorError.ACCESS_CONDITIONS, () -> external.sign(CTX, smcb, HASH));
    pins.verify(new Context("M1", "CS2", "WP1", null), smcb, "PIN.SMC");
    assertError(ConnectorError.ACCESS_CONDITIONS, () -> external.sign(CTX, smcb, HASH));
  }

  @Test
  @DisplayName(
      "TAB_KON_783: eGK → 4058; BinaryString kein SHA-256-Hash → 4000; Karte antwortet 6982 → 4085")
  void fehler() {
    assertError(ConnectorError.CALL_NOT_ALLOWED, () -> external.sign(CTX, egk, HASH));
    assertError(ConnectorError.SYNTAX, () -> external.sign(CTX, smcb, new byte[20]));
    pins.verify(CTX, smcb, "PIN.SMC");
    kt01.answer(2, "002A9E9A20" + HEX.formatHex(HASH) + "00", "6982");
    assertError(ConnectorError.ACCESS_CONDITIONS, () -> external.sign(CTX, smcb, HASH));
  }

  @Test
  @DisplayName(
      "BSI TR-03111 5.2.2: (r, s) mit gesetztem Vorzeichenbit wird als positive INTEGER kodiert")
  void derKodierung() {
    byte[] plain = new byte[64];
    plain[0] = (byte) 0x80;
    plain[32] = 0x01;
    byte[] der = CardSignature.ecdsaSigValue(plain);
    assertEquals("30450221008000", HEX.formatHex(der, 0, 7));
    assertEquals(0x47, der.length);
  }

  /** (r, s) from the recorded response to PSO COMPUTE DIGITAL SIGNATURE. */
  private static String cardSignature(java.nio.file.Path recording) throws Exception {
    String response =
        Files.readAllLines(recording).stream()
            .filter(l -> l.startsWith("002A9E9A"))
            .findFirst()
            .orElseThrow()
            .split(" ")[1];
    return response.substring(0, response.length() - 4);
  }

  /** ECDSA-Sig-Value back to (r, s), 32 bytes each. */
  private static String plain(byte[] der) {
    int rLength = der[3];
    var r = new BigInteger(1, Arrays.copyOfRange(der, 4, 4 + rLength));
    var s = new BigInteger(1, Arrays.copyOfRange(der, 6 + rLength, der.length));
    return String.format("%064X%064X", r, s);
  }

  private static void assertError(ConnectorError expected, Executable call) {
    assertEquals(expected, assertThrows(ConnectorException.class, call).error());
  }
}

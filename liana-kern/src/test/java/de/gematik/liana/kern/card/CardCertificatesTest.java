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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import de.gematik.liana.kern.access.Context;
import de.gematik.liana.kern.access.Infomodel;
import de.gematik.liana.kern.error.ConnectorError;
import de.gematik.liana.kern.error.ConnectorException;
import de.gematik.liana.kern.terminal.TerminalRegistry;
import java.nio.file.Files;
import java.time.Clock;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

/**
 * ReadCardCertificate (TIP1-A_4700-03) against the recorded egk-valid (slot 1), smcb-valid (slot 2)
 * and hba-valid (slot 3).
 */
class CardCertificatesTest {

  private static final Context CTX = new Context("M1", "CS1", "WP1", null);
  private static final HexFormat HEX = HexFormat.of().withUpperCase();
  private static final String ESIGN = "00A4040C0AA000000167455349474E";
  private static final String QES = "00A4040C06D27600006601";

  private final RecordedCards kt01 = new RecordedCards("KT-01");
  private final CardList cards =
      new CardList(new TerminalRegistry(List.of(kt01)), Clock.systemUTC());
  private final Infomodel infomodel =
      new Infomodel(
          List.of("M1"),
          List.of("CS1"),
          List.of(new Infomodel.Workplace("WP1", List.of("M1"), List.of("CS1"), List.of("KT-01"))));
  private final CardCertificates certificates =
      new CardCertificates(
          new CardAccess(infomodel, cards, new CardLocks()), new TerminalRegistry(List.of(kt01)));
  private String egk;
  private String smcb;
  private String hba;

  @BeforeEach
  void stecken() {
    cards.start();
    kt01.insert(1, RecordedTerminal.EGK_VALID)
        .insert(2, RecordedTerminal.SMCB_VALID)
        .insert(3, RecordedTerminal.HBA_VALID)
        .also(3, RecordedTerminal.HBA_VALID_OPS);
    egk = cards.card("KT-01", 1).orElseThrow().cardHandle();
    smcb = cards.card("KT-01", 2).orElseThrow().cardHandle();
    hba = cards.card("KT-01", 3).orElseThrow().cardHandle();
    kt01.sent.get(2).clear();
    kt01.sent.get(3).clear();
  }

  /**
   * The file kartos returns in hba-valid after SELECT {@code df} on READ BINARY {@code read},
   * without SW.
   */
  private static String hbaFile(String df, String read) throws Exception {
    String selected = "";
    for (String line : Files.readAllLines(RecordedTerminal.HBA_VALID_OPS)) {
      String[] apdu = line.split(" ");
      if (line.startsWith("00A4040C")) {
        selected = apdu[0];
      } else if (selected.equals(df) && apdu[0].equals(read)) {
        return apdu[1].substring(0, apdu[1].length() - 4);
      }
    }
    throw new AssertionError(read + " nach " + df + " nicht aufgezeichnet");
  }

  /** EF.C.HCI.AUT.E256 of smcb-valid, as kartos returns it on READ BINARY SFI 06. */
  private static String autE256() throws Exception {
    String response =
        Files.readAllLines(RecordedTerminal.SMCB_VALID).stream()
            .filter(l -> l.startsWith("00B08600000000 "))
            .findFirst()
            .orElseThrow()
            .split(" ")[1];
    return response.substring(0, response.length() - 4);
  }

  @Test
  @DisplayName(
      "TIP1-A_4700-03 / TUC_KON_216: C.AUT der SMC-B ohne Crypt → ECC, EF.C.HCI.AUT.E256 aus DF.ESIGN (SFI 06)")
  void cAutEcc() throws Exception {
    var result = certificates.read(CTX, smcb, List.of("C.AUT"), null);

    assertEquals(1, result.size());
    assertEquals("C.AUT", result.getFirst().certRef());
    assertEquals(autE256(), HEX.formatHex(result.getFirst().der()));
    assertEquals(List.of("00A4040C0AA000000167455349474E", "00B08600000000"), kt01.sent.get(2));
  }

  @Test
  @DisplayName(
      "TAB_KON_858: Crypt RSA liest EF.C.HCI.AUT.R2048 (SFI 01); C.ENC/C.SIG über SFI 05/07")
  void dateiJeCrypt() {
    kt01.answer(2, "00B08100000000", "30039000");
    kt01.answer(2, "00B08500000000", "30049000");
    kt01.answer(2, "00B08700000000", "30059000");
    assertEquals(
        "3003",
        HEX.formatHex(certificates.read(CTX, smcb, List.of("C.AUT"), "RSA").getFirst().der()));
    var ecc = certificates.read(CTX, smcb, List.of("C.ENC", "C.SIG"), "ECC");
    assertEquals("3004", HEX.formatHex(ecc.get(0).der()));
    assertEquals("3005", HEX.formatHex(ecc.get(1).der()));
  }

  @Test
  @DisplayName(
      "TIP1-A_4700-03 / TAB_KON_858 HBA, Crypt ECC: C.AUT und C.ENC aus DF.ESIGN (EF.C.HP.AUT.E256 SFI 06, "
          + "EF.C.HP.ENC.E256 SFI 05), C.QES aus DF.QES (EF.C.HP.QES.E256, ebenfalls SFI 06)")
  void hbaEcc() throws Exception {
    var result = certificates.read(CTX, hba, List.of("C.AUT", "C.ENC", "C.QES"), null);

    assertEquals(
        List.of("C.AUT", "C.ENC", "C.QES"), result.stream().map(c -> c.certRef()).toList());
    assertEquals(hbaFile(ESIGN, "00B08600000000"), HEX.formatHex(result.get(0).der()));
    assertEquals(hbaFile(ESIGN, "00B08500000000"), HEX.formatHex(result.get(1).der()));
    assertEquals(hbaFile(QES, "00B08600000000"), HEX.formatHex(result.get(2).der()));
    assertNotEquals(HEX.formatHex(result.get(0).der()), HEX.formatHex(result.get(2).der()));
    assertEquals(
        List.of(ESIGN, "00B08600000000", ESIGN, "00B08500000000", QES, "00B08600000000"),
        kt01.sent.get(3));
  }

  @Test
  @DisplayName(
      "TAB_KON_858 HBA, Crypt RSA: EF.C.HP.AUT.R2048 (SFI 01), EF.C.HP.ENC.R2048 (SFI 02), EF.C.HP.QES.R2048 "
          + "(DF.QES, SFI 10); C.SIG gibt es für den HBA nicht → 4149")
  void hbaRsa() throws Exception {
    var result = certificates.read(CTX, hba, List.of("C.AUT", "C.ENC", "C.QES"), "RSA");

    assertEquals(hbaFile(ESIGN, "00B08100000000"), HEX.formatHex(result.get(0).der()));
    assertEquals(hbaFile(ESIGN, "00B08200000000"), HEX.formatHex(result.get(1).der()));
    assertEquals(hbaFile(QES, "00B09000000000"), HEX.formatHex(result.get(2).der()));
    assertError(
        ConnectorError.INVALID_CERT_REF, () -> certificates.read(CTX, hba, List.of("C.SIG"), null));
  }

  @Test
  @DisplayName("TAB_KON_604 4090: eGK-Zertifikate sind für Clientsysteme nicht lesbar")
  void egk() {
    assertError(
        ConnectorError.EGK_ACCESS_DENIED,
        () -> certificates.read(CTX, egk, List.of("C.AUT"), null));
  }

  @Test
  @DisplayName("TAB_KON_604 4149: CertRef ohne Objekt auf der SM-B (C.QES)")
  void ungueltigeReferenz() {
    assertError(
        ConnectorError.INVALID_CERT_REF,
        () -> certificates.read(CTX, smcb, List.of("C.QES"), null));
  }

  @Test
  @DisplayName(
      "TAB_KON_604 4258 (TUC_KON_216 4256): Zertifikatsdatei fehlt → „ECCZertifikat nicht vorhanden auf Karte: <Handle>“")
  void fehlendesZertifikat() {
    kt01.answer(2, "00B08600000000", "6A82");
    var e =
        assertThrows(
            ConnectorException.class, () -> certificates.read(CTX, smcb, List.of("C.AUT"), null));
    assertEquals(ConnectorError.CERT_NOT_ON_CARD, e.error());
    assertEquals("ECCZertifikat nicht vorhanden auf Karte: " + smcb, e.text());
  }

  @Test
  @DisplayName(
      "checkArguments 4000: CertRefList leer, Crypt unbekannt, CardHandle fehlt; TUC_KON_000: unbekanntes Handle → 4008")
  void argumente() {
    assertError(ConnectorError.SYNTAX, () -> certificates.read(CTX, smcb, List.of(), null));
    assertError(ConnectorError.SYNTAX, () -> certificates.read(CTX, smcb, List.of("C.AUT"), "DSA"));
    assertError(ConnectorError.SYNTAX, () -> certificates.read(CTX, null, List.of("C.AUT"), null));
    assertError(
        ConnectorError.CARD_NOT_INSERTED,
        () -> certificates.read(CTX, "SMC-B-99", List.of("C.AUT"), null));
  }

  private static void assertError(ConnectorError expected, Executable call) {
    assertEquals(expected, assertThrows(ConnectorException.class, call).error());
  }
}

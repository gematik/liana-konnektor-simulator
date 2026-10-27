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
package de.gematik.liana.adapter.fake;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.gematik.liana.kern.card.CardData;
import de.gematik.liana.kern.card.CardReader;
import de.gematik.liana.kern.card.CardType;
import de.gematik.liana.kern.terminal.CardTerminal;
import de.gematik.liana.kern.terminal.PinDialog;
import java.io.IOException;
import java.time.LocalDate;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Fake terminal with kartos as card engine ({@link KartosBinary}). */
class FakeTerminalIT {

  private static final HexFormat HEX = HexFormat.of().withUpperCase();

  @Test
  @DisplayName(
      "transmit auf egk-valid (KT-01/1) mit SELECT D2760001448000 liefert 9000 über kartos")
  void selectOnEgkValid() throws IOException {
    FakeTerminals terminals =
        new FakeTerminals(
            List.of(new FakeTerminals.Spec("KT-01", 3, Map.of(1, "egk-valid"))),
            FakeTerminalsTest.SEARCH_PATH,
            new KartosEngine(KartosBinary.path()));
    try {
      CardTerminal kt01 = terminals.terminals().getFirst();
      assertEquals("3B909681B1FE451F0391", HEX.formatHex(kt01.reset(1)));
      assertEquals(
          "9000", HEX.formatHex(kt01.transmit(1, HEX.parseHex("00A4040C07D2760001448000"))));
    } finally {
      terminals.close();
    }
  }

  @Test
  @DisplayName(
      "TIP1-A_4565-03 TUC_KON_001: CardReader liest smcb-valid über kartos als SMC-B mit Daten aus C.HCI.AUT.E256")
  void cardReaderOnSmcbValid() {
    FakeTerminals terminals =
        new FakeTerminals(
            List.of(new FakeTerminals.Spec("KT-01", 3, Map.of(2, "smcb-valid"))),
            FakeTerminalsTest.SEARCH_PATH,
            new KartosEngine(KartosBinary.path()));
    try {
      CardData data = CardReader.read(terminals.terminals().getFirst(), 2);
      assertEquals(CardType.SMC_B, data.type());
      assertEquals("80276883110000168650", data.iccsn());
      assertEquals("Praxis Münchhausen-HohenfelsTEST-ONLY", data.cardHolderName());
      assertEquals(LocalDate.of(2030, 4, 6), data.certExpirationDate());
    } finally {
      terminals.close();
    }
  }

  @Test
  @DisplayName(
      "TUC_KON_012 7b: das simulierte PIN-Pad gibt PIN.SMC ein – 123456 → 9000 über kartos, falsche PIN → 63C2")
  void pinPadOnSmcbValid() throws IOException {
    FakeTerminals richtig =
        new FakeTerminals(
            List.of(new FakeTerminals.Spec("KT-01", 3, Map.of(2, "smcb-valid"))),
            FakeTerminalsTest.SEARCH_PATH,
            new KartosEngine(KartosBinary.path()));
    FakeTerminals falsch =
        new FakeTerminals(
            List.of(new FakeTerminals.Spec("KT-01", 3, Map.of(2, "smcb-valid"), "111111")),
            FakeTerminalsTest.SEARCH_PATH,
            new KartosEngine(KartosBinary.path()));
    try {
      assertEquals(
          "9000",
          HEX.formatHex(richtig.terminals().getFirst().verifyPin(2, 0x01, PinDialog.pinSmc(2))));
      assertEquals(
          "63C2",
          HEX.formatHex(falsch.terminals().getFirst().verifyPin(2, 0x01, PinDialog.pinSmc(2))));
    } finally {
      richtig.close();
      falsch.close();
    }
  }

  @Test
  @DisplayName(
      "LIANA-61 TUC_KON_012 7b: das simulierte PIN-Pad gibt PIN.CH des HBA ein (hba-valid, VERIFY P2 01) – "
          + "123456 → 9000 über kartos, falsche PIN → 63C2")
  void pinPadOnHbaValid() throws IOException {
    FakeTerminals richtig =
        new FakeTerminals(
            List.of(new FakeTerminals.Spec("KT-01", 3, Map.of(3, "hba-valid"))),
            FakeTerminalsTest.SEARCH_PATH,
            new KartosEngine(KartosBinary.path()));
    FakeTerminals falsch =
        new FakeTerminals(
            List.of(new FakeTerminals.Spec("KT-01", 3, Map.of(3, "hba-valid"), "111111")),
            FakeTerminalsTest.SEARCH_PATH,
            new KartosEngine(KartosBinary.path()));
    try {
      assertEquals(
          "9000",
          HEX.formatHex(richtig.terminals().getFirst().verifyPin(3, 0x01, PinDialog.pinCh())));
      assertEquals(
          "63C2",
          HEX.formatHex(falsch.terminals().getFirst().verifyPin(3, 0x01, PinDialog.pinCh())));
    } finally {
      richtig.close();
      falsch.close();
    }
  }
}

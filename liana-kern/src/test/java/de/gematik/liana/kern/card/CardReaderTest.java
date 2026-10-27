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
import static org.junit.jupiter.api.Assertions.assertNull;

import de.gematik.liana.kern.terminal.CardTerminal;
import java.io.IOException;
import java.time.LocalDate;
import java.util.HexFormat;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class CardReaderTest {

  private static final HexFormat HEX = HexFormat.of().withUpperCase();

  @Test
  @DisplayName(
      "TUC_KON_001 2c: egk-valid liefert Typ, ICCSN, CardVersion und die Angaben aus C.CH.AUT.E256")
  void egkValid() {
    RecordedTerminal terminal = new RecordedTerminal("KT-01", 1, RecordedTerminal.EGK_VALID);
    terminal.insert(1);
    CardData data = CardReader.read(terminal, 1);

    assertEquals(CardType.EGK, data.type());
    assertEquals("80276883110000168584", data.iccsn());
    assertEquals("4.3.0", data.version().cos().toString());
    assertEquals("4.5.2", data.version().objectSystem().toString());
    assertEquals("1.0.0", data.version().logging().toString());
    assertEquals("2.0.0", data.version().atr().toString());
    assertEquals("1.0.0", data.version().gdo().toString());
    assertNull(data.version().keyInfo());
    assertEquals("Dörthe Abigail Freifrau Dåmmer-ØrstedTEST-ONLY", data.cardHolderName());
    assertEquals("X110630769", data.kvnr());
    assertEquals(LocalDate.of(2030, 4, 6), data.certExpirationDate());
    assertEquals(0, terminal.expected.size(), "alle aufgezeichneten Kommandos gesendet");
  }

  @Test
  @DisplayName(
      "TUC_KON_001 2c / VSDM-A_2568: eGK mit gesperrter Gesundheitsanwendung (SELECT DF.HCA → 6283) bleibt "
          + "eine eGK, damit TUC_KON_018 sie als gesperrt erkennt")
  void egkGesperrt() {
    RecordedTerminal gesperrt =
        new RecordedTerminal("KT-01", 1, RecordedTerminal.EGK_VALID) {
          @Override
          public byte[] transmit(int slot, byte[] commandApdu) {
            byte[] response = super.transmit(slot, commandApdu);
            return HEX.formatHex(commandApdu).equals("00A4040C06D27600000102")
                ? HEX.parseHex("6283")
                : response;
          }
        };
    gesperrt.insert(1);
    CardData data = CardReader.read(gesperrt, 1);

    assertEquals(CardType.EGK, data.type());
    assertEquals("X110630769", data.kvnr());
  }

  @Test
  @DisplayName(
      "TIP1-A_4565-03 TUC_KON_001 2c: smcb-valid ist eine SMC-B (MF D27600014606, kein DF.HCA, C.HCI.AUT.E256 "
          + "mit oid_smc_b_aut); Name und Ablauf aus C.HCI.AUT, keine KVNR")
  void smcbValid() {
    RecordedTerminal terminal = new RecordedTerminal("KT-01", 2, RecordedTerminal.SMCB_VALID);
    terminal.insert(2);
    CardData data = CardReader.read(terminal, 2);

    assertEquals(CardType.SMC_B, data.type());
    assertEquals("80276883110000168650", data.iccsn());
    assertEquals("4.8.0", data.version().objectSystem().toString());
    assertEquals("Praxis Münchhausen-HohenfelsTEST-ONLY", data.cardHolderName());
    assertNull(data.kvnr());
    assertEquals(LocalDate.of(2030, 4, 6), data.certExpirationDate());
    assertEquals(0, terminal.expected.size(), "alle aufgezeichneten Kommandos gesendet");
  }

  @Test
  @DisplayName(
      "TIP1-A_4565-03 TUC_KON_001 2c: hba-valid ist ein HBA (MF D27600014601, kein DF.HCA, C.HP.AUT.E256 "
          + "mit oid_hba_aut); Name aus dem mehrwertigen RDN und Ablauf aus C.HP.AUT, keine KVNR")
  void hbaValid() {
    RecordedTerminal terminal = new RecordedTerminal("KT-01", 3, RecordedTerminal.HBA_VALID);
    terminal.insert(3);
    CardData data = CardReader.read(terminal, 3);

    assertEquals(CardType.HBA, data.type());
    assertEquals("80276883119000000020", data.iccsn());
    assertEquals("4.8.0", data.version().objectSystem().toString());
    assertEquals("Maximilian PopówitschTEST-ONLY", data.cardHolderName());
    assertNull(data.kvnr());
    assertEquals(LocalDate.of(2031, 6, 3), data.certExpirationDate());
    assertEquals(0, terminal.expected.size(), "alle aufgezeichneten Kommandos gesendet");
  }

  @Test
  @DisplayName(
      "LIANA-188 TUC_KON_001 2c: gsmckt-root6 in einem Slot ist eine SMC-KT (MF D2760001448003, kein DF.HCA, "
          + "C.SMKT.AUT in DF.KT); Name und Ablauf aus C.SMKT.AUT wie beim secunet-Konnektor (CN = ICCSN)")
  void gsmcKt() {
    RecordedTerminal terminal = new RecordedTerminal("KT-01", 4, RecordedTerminal.GSMCKT_ROOT6);
    terminal.insert(4);
    CardData data = CardReader.read(terminal, 4);

    assertEquals(CardType.SMC_KT, data.type());
    assertEquals("80276883110000152716", data.iccsn());
    assertEquals("4.4.1", data.version().objectSystem().toString());
    assertEquals("80276883110000152716", data.cardHolderName());
    assertNull(data.kvnr());
    assertEquals(LocalDate.of(2028, 9, 19), data.certExpirationDate());
    assertEquals(0, terminal.expected.size(), "alle aufgezeichneten Kommandos gesendet");
  }

  @Test
  @DisplayName(
      "TUC_KON_001: Karte mit HBA-MF, deren AUT-Zertifikat nicht vom Typ oid_hba_aut ist → UNKNOWN")
  void keinHba() {
    RecordedTerminal fremd =
        new RecordedTerminal("KT-01", 3, RecordedTerminal.HBA_VALID) {
          @Override
          public byte[] transmit(int slot, byte[] commandApdu) {
            // the certificate's policies lose oid_hba_aut (…04 4B → …04 4E)
            byte[] response = super.transmit(slot, commandApdu);
            String hex =
                HEX.formatHex(response).replace("06072A8214004C044B", "06072A8214004C044E");
            return HEX.parseHex(hex);
          }
        };
    fremd.insert(3);
    assertEquals(
        CardReader.Reading.unknown("C.HP.AUT ohne Zertifikatstyp oid_hba_aut"),
        CardReader.open(fremd, 3));
  }

  @Test
  @DisplayName(
      "TUC_KON_001: G2-Karte ohne DF.HCA, deren AUT-Zertifikat nicht vom Typ oid_smc_b_aut ist → UNKNOWN")
  void keineSmcb() {
    RecordedTerminal fremd =
        new RecordedTerminal("KT-01", 2, RecordedTerminal.SMCB_VALID) {
          @Override
          public byte[] transmit(int slot, byte[] commandApdu) {
            // the certificate's policies lose oid_smc_b_aut (…04 4D → …04 4E)
            byte[] response = super.transmit(slot, commandApdu);
            String hex =
                HEX.formatHex(response).replace("06072A8214004C044D", "06072A8214004C044E");
            return HEX.parseHex(hex);
          }
        };
    fremd.insert(2);
    assertEquals(
        CardReader.Reading.unknown("C.HCI.AUT ohne Zertifikatstyp oid_smc_b_aut"),
        CardReader.open(fremd, 2));
  }

  @Test
  @DisplayName("TUC_KON_001 Fehlerfall: nicht lesbare Karte wird als UNKNOWN geführt")
  void nichtLesbar() {
    CardTerminal stumm =
        new RecordedTerminal("KT-01", 1, RecordedTerminal.EGK_VALID) {
          @Override
          public byte[] transmit(int slot, byte[] commandApdu) {
            return HEX.parseHex("6F00");
          }
        };
    assertEquals(
        CardReader.Reading.unknown("kein MF der eGK, SMC-B, des HBA oder der gSMC-KT wählbar"),
        CardReader.open(stumm, 1));
  }

  @Test
  @DisplayName(
      "LIANA-121 TUC_KON_001 Fehlerfall: startet die Card-Engine nicht, ist der Grund ihre Fehlermeldung")
  void engineStartetNicht() {
    CardTerminal kaputt =
        new CardTerminal() {
          @Override
          public String id() {
            return "KT-01";
          }

          @Override
          public int slots() {
            return 1;
          }

          @Override
          public void addSlotListener(de.gematik.liana.kern.terminal.SlotListener listener) {}

          @Override
          public boolean cardPresent(int slot) {
            return true;
          }

          @Override
          public byte[] reset(int slot) throws IOException {
            throw new IOException(
                "Cannot run program \"/opt/liana/bin/kartos\": error=2, No such file or directory");
          }

          @Override
          public byte[] transmit(int slot, byte[] commandApdu) throws IOException {
            throw new AssertionError("kein Reset, keine APDU");
          }
        };
    assertEquals(
        CardReader.Reading.unknown(
            "Cannot run program \"/opt/liana/bin/kartos\": error=2, No such file or directory"),
        CardReader.open(kaputt, 1));
  }

  @Test
  @DisplayName("TIP1-A_4988-03: EF.Version2 C1 = 3.x.y (keine G2/G3) → UNKNOWN")
  void falscheGeneration() {
    CardTerminal g1 =
        new RecordedTerminal("KT-01", 1, RecordedTerminal.EGK_VALID) {
          @Override
          public byte[] transmit(int slot, byte[] commandApdu) {
            return HEX.formatHex(commandApdu).equals("00B0910000")
                ? HEX.parseHex("EF05C1030300009000")
                : HEX.parseHex("9000");
          }
        };
    assertEquals(
        CardReader.Reading.unknown(
            "Objektsystem 3.0.0 ist weder Generation 2 noch 3 (TIP1-A_4988-03)"),
        CardReader.open(g1, 1));
  }

  @Test
  @DisplayName("Kartentyp-Filter: Einzeltypen und HBAx, SM-B aus TAB_KON_500")
  void kartentypFilter() {
    assertEquals(true, CardType.EGK.matches("EGK"));
    assertEquals(false, CardType.EGK.matches("SMC-B"));
    assertEquals(true, CardType.SMC_B.matches("SM-B"));
    assertEquals(true, CardType.HBA_Q_SIG.matches("HBAx"));
    assertEquals(true, CardType.HBA.matches("HBAx"));
    assertEquals(CardType.SMC_B, CardType.of("SMC-B").orElseThrow());
  }

  /**
   * A CT with a synchronous card: ATR {@code atr}, SELECT FILE of the AID {@code aid} with 9000,
   * otherwise 6A82.
   */
  private static CardTerminal synchronous(String atr, String aid) {
    return new CardTerminal() {
      @Override
      public String id() {
        return "KT-01";
      }

      @Override
      public int slots() {
        return 1;
      }

      @Override
      public void addSlotListener(de.gematik.liana.kern.terminal.SlotListener listener) {}

      @Override
      public boolean cardPresent(int slot) {
        return true;
      }

      @Override
      public byte[] reset(int slot) {
        return HEX.parseHex(atr);
      }

      @Override
      public byte[] transmit(int slot, byte[] apdu) {
        return HEX.parseHex(HEX.formatHex(apdu).equals("00A4040006" + aid) ? "9000" : "6A82");
      }
    };
  }

  @Test
  @DisplayName(
      "TUC_KON_001 Varianten / LIANA-113: synchroner ATR und KVK-Anwendung (neue oder alte AID) → KVK ohne "
          + "ICCSN, Version und Zertifikatsdaten; synchrone Karte ohne KVK-Anwendung → UNKNOWN")
  void kvk() {
    for (String aid : new String[] {"D27600000101", "D28000000101"}) {
      CardReader.Reading reading = CardReader.open(synchronous("A2131091", aid), 1);
      assertEquals(new CardData(CardType.KVK, null, null, null, null, null), reading.data(), aid);
      assertNull(reading.unknownReason());
    }
    CardReader.Reading other = CardReader.open(synchronous("A2131091", "D27600000102"), 1);
    assertEquals(CardType.UNKNOWN, other.data().type());
    assertEquals("synchrone Karte ohne KVK-Anwendung", other.unknownReason());
    assertEquals(
        CardType.UNKNOWN,
        CardReader.open(synchronous("3B00", "D27600000101"), 1).data().type(),
        "asynchroner ATR: keine KVK, auch wenn die AID antwortet");
  }
}

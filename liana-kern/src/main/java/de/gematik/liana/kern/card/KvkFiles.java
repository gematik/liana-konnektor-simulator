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

import de.gematik.liana.kern.error.ConnectorError;
import de.gematik.liana.kern.terminal.CardTerminal;
import de.gematik.liana.kern.terminal.TerminalRegistry;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.HexFormat;

/**
 * TUC_KON_202 „LeseDatei“ for the KVK (LIANA-113): the card terminal maps SELECT FILE and READ
 * BINARY to the memory card (gemSpec_Kon TUC_KON_202 variants, [SICCT] 5.5.8.1). Reading follows
 * KBV-Merkblatt KVK 4.2a: SELECT of the KVK application, then READ BINARY from offset 0000 with Le
 * 00 until the card reports the end of file with {@code 6282}.
 */
public final class KvkFiles {

  private static final HexFormat HEX = HexFormat.of().withUpperCase();

  /** KBV-Merkblatt KVK 4.1: new and old AID of the KVK application. */
  private static final String[] SELECT_KVK = {"00A4040006D27600000101", "00A4040006D28000000101"};

  /**
   * Le 00 reads up to 256 bytes, the VersichertenDatenTemplate has at most 215; more rounds are an
   * error.
   */
  private static final int MAX_READS = 4;

  private final TerminalRegistry terminals;

  public KvkFiles(TerminalRegistry terminals) {
    this.terminals = terminals;
  }

  /**
   * The data of the KVK application from offset 0000 to the end of file, unchecked. 3020 if the
   * application cannot be selected or the card answers READ BINARY with an error (gemILF_PS
   * Tab_ILF_PS_Fehlercodes_VSDM).
   */
  public byte[] read(CardObject kvk) {
    CardTerminal terminal =
        terminals
            .terminal(kvk.ctId())
            .orElseThrow(() -> ConnectorError.CT_ACCESS.exception(kvk.ctId()));
    try {
      boolean selected = false;
      for (String select : SELECT_KVK) {
        if (ok(terminal.transmit(kvk.slotNo(), HEX.parseHex(select)))) {
          selected = true;
          break;
        }
      }
      if (!selected) {
        throw ConnectorError.KVK_READ_FAILED.exception(
            kvk.cardHandle() + ": KVK-Anwendung nicht wählbar");
      }
      ByteArrayOutputStream data = new ByteArrayOutputStream();
      for (int i = 0; i < MAX_READS; i++) {
        byte[] response =
            terminal.transmit(
                kvk.slotNo(), HEX.parseHex("00B0" + HEX.toHexDigits((short) data.size()) + "00"));
        int n = response.length - 2;
        int sw = n < 0 ? -1 : (response[n] & 0xFF) << 8 | response[n + 1] & 0xFF;
        if (sw != 0x9000 && sw != 0x6282) {
          throw ConnectorError.KVK_READ_FAILED.exception(
              kvk.cardHandle()
                  + ": READ BINARY "
                  + (sw < 0 ? "ohne Statuswort" : HEX.toHexDigits((short) sw)));
        }
        data.write(response, 0, n);
        if (sw == 0x6282 || n == 0) {
          return data.toByteArray();
        }
      }
      throw ConnectorError.KVK_READ_FAILED.exception(
          kvk.cardHandle() + ": READ BINARY ohne Dateiende");
    } catch (IOException e) {
      throw TerminalErrors.of(kvk, "LeseDatei", e);
    }
  }

  private static boolean ok(byte[] response) {
    return Arrays.equals(response, new byte[] {(byte) 0x90, 0x00});
  }
}

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
package de.gematik.liana.adapter.sicct;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * TUC_KON_055 step 2/3: GET STATUS into the CT object, with the responses of kartos terminal (SICCT
 * 1.2.3 §5.15).
 */
class GetStatusTest {

  static final HexFormat HEX = HexFormat.of();

  /** kartos: 4 contact slots 0001–0004, all with a card (ICCS 15). */
  static final byte[] CTS = HEX.parseHex("6310810800010002000300048004151515159000");

  /**
   * kartos: CTM DO INGHC/0120/03000, DD DO VER 1.0.0, PT KT, PTV 1.2.0, MODN ORGA6100, FWV 3.0.0,
   * HWV 1.0.0.
   */
  static final byte[] CTM =
      HEX.parseHex(
          "467d494e47484330313230203033303030d76c2020312020302020304b5420203120"
              + "20322020304f52474136313030202033202030202030202031202030202030303030303130372e30382e323031352d2020"
              + "20202020202020202020202020202020202020202020202020202020203031343030303030303030353930209000");

  /** kartos: DSPLC DO 20×4 visible, 48 virtual characters, beeper. */
  static final byte[] DSPLC = HEX.parseHex("670f8001148101048201308301048401019000");

  @Test
  @DisplayName(
      "TUC_KON_055 Schritt 2: SLOTCOUNT, SLOTS_USED, PRODUCTINFORMATION, EHEALTH_INTERFACE_VERSION (DD DO VER) "
          + "und DISPLAY_CAPABILITIES (DSPLC DO) aus den kartos-Antworten")
  void kartos() throws IOException {
    GetStatus.Terminal status = GetStatus.parse(CTS, CTM, DSPLC);
    assertEquals(4, status.slotCount());
    assertEquals(List.of(1, 2, 3, 4), status.slotsUsed());
    assertEquals("1.0.0", status.ehealthInterfaceVersion());
    assertEquals(
        Map.of(
            "ProductVendorID",
            "INGHC",
            "ProductType",
            "0120",
            "SoftwareVersion",
            "03000",
            "ProductCode",
            "ORGA6100",
            "ProductTypeVersion",
            "1.2.0",
            "FWVersion",
            "3.0.0",
            "HWVersion",
            "1.0.0"),
        status.productInformation());
    assertEquals(new CtObject.DisplayCapabilities(20, 4, 48, 4, true), status.display());
  }

  @Test
  @DisplayName(
      "§5.5.10.17: ein KT ohne DSPLC DO (6A86) hat keine DISPLAY_CAPABILITIES; leere Slots zählen nicht als "
          + "belegt")
  void ohneDisplay() throws IOException {
    byte[] cts = HEX.parseHex("6310810800010002000300048004150000159000");
    GetStatus.Terminal status = GetStatus.parse(cts, CTM, HEX.parseHex("6a86"));
    assertNull(status.display());
    assertEquals(List.of(1, 4), status.slotsUsed());
  }

  @Test
  @DisplayName("Fehlerhafte Antworten: Statuswort ≠ 9000 oder fehlendes Datenobjekt")
  void fehler() {
    assertThrows(IOException.class, () -> GetStatus.parse(HEX.parseHex("6a86"), CTM, DSPLC));
    assertThrows(IOException.class, () -> GetStatus.parse(HEX.parseHex("80009000"), CTM, DSPLC));
    assertThrows(IOException.class, () -> GetStatus.parse(CTS, HEX.parseHex("6400"), DSPLC));
  }

  @Test
  @DisplayName(
      "TUC_KON_055 Schritt 3: Haupt- und Nebenversion gleich, dritte Stelle ≥ Eintrag aus "
          + "CTM_SUPPORTED_KT_VERSIONS")
  void versionspruefung() {
    assertTrue(GetStatus.supported("1.0.0", List.of("1.0.0")));
    assertTrue(GetStatus.supported("1.0.3", List.of("2.1.0", "1.0.2")));
    assertFalse(GetStatus.supported("1.0.1", List.of("1.0.2")));
    assertFalse(GetStatus.supported("1.1.0", List.of("1.0.0")));
    assertFalse(GetStatus.supported(null, List.of("1.0.0")));
    assertEquals("1.0.0", GetStatus.version("  1  0  0"));
    assertEquals("12.3.45", GetStatus.version(" 12  3 45"));
  }
}

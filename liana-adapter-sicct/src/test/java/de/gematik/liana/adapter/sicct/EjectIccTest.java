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

import java.util.HexFormat;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * Status word of SICCT EJECT ICC (SICCT 1.2.3 §5.14.6) for TUC_KON_057 "Karte auswerfen" (eject
 * card).
 */
class EjectIccTest {

  @ParameterizedTest(name = "{0} → {1}")
  @CsvSource({"9000, true", "9001, true", "6200, false", "6400, false", "6A80, false", "90, false"})
  @DisplayName(
      "TUC_KON_057, SICCT §5.14.6: 9000 (ohne Aussage zur Entnahme) und 9001 (entnommen) sind Erfolg, "
          + "62xx (nicht entnommen) und andere Statuswörter nicht")
  void statuswort(String sw, boolean ejected) {
    assertEquals(ejected, SicctTerminal.ejected(HexFormat.of().parseHex(sw)));
  }
}

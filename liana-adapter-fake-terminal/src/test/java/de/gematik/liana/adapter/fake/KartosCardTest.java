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

import java.io.IOException;
import java.nio.file.Path;
import java.util.HexFormat;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Runs without kartos; {@link KartosCardIT} checks the APDU path. */
class KartosCardTest {

  static final Path EGK_VALID = Path.of("support/images/egk-valid.xml");

  @Test
  @DisplayName("Card-G2-A_2345 ATR der eGK kommt aus coldAnswerToReset des Images")
  void coldAtrFromImage() throws IOException {
    assertEquals(
        "3B909681B1FE451F0391",
        HexFormat.of().withUpperCase().formatHex(KartosCard.coldAtr(EGK_VALID)));
  }
}

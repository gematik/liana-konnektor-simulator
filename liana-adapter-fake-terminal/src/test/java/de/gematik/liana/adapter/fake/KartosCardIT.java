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
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Card engine (LIANA-5) against a real kartos binary ({@link KartosBinary}). {@code ./mvnw verify
 * -DskipITs=false -Dit.test=KartosCardIT}
 */
class KartosCardIT {

  private static final HexFormat HEX = HexFormat.of().withUpperCase();
  private static final String SELECT_EGK_ROOT = "00A4040C07D2760001448000";

  private static KartosCard egkValid() throws IOException {
    return KartosCard.open(KartosBinary.path(), KartosCardTest.EGK_VALID);
  }

  @Test
  @DisplayName("egk-valid liefert ATR und beantwortet SELECT D2760001448000 mit 9000")
  void selectEgkRoot() throws IOException {
    try (KartosCard card = egkValid()) {
      assertEquals("3B909681B1FE451F0391", HEX.formatHex(card.atr()));
      assertEquals("9000", HEX.formatHex(card.transmit(HEX.parseHex(SELECT_EGK_ROOT))));
    }
  }

  @Test
  @DisplayName(
      "Trusted Channel Konnektor (Blueprint Sequenz 2): MSE, PSO VERIFY CERTIFICATE ×2, GENERAL AUTHENTICATE")
  void trustedChannel() throws IOException {
    JsonNode blueprint =
        new ObjectMapper()
            .readTree(Path.of("support/blueprints/poppApdusSequence2Connector.json").toFile());
    try (KartosCard card = egkValid()) {
      card.transmit(HEX.parseHex(SELECT_EGK_ROOT));
      for (JsonNode step : blueprint.get("steps")) {
        String command = step.get("commandApdu").asText();
        List<String> expected = new ArrayList<>();
        step.get("expectedStatusWords").forEach(sw -> expected.add(sw.asText().toUpperCase()));
        String response = HEX.formatHex(card.transmit(HEX.parseHex(command)));
        String sw = response.substring(response.length() - 4);
        assertTrue(expected.contains(sw), command + " -> " + sw + ", erwartet " + expected);
      }
    }
  }
}

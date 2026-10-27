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
package de.gematik.liana.wiring;

import de.gematik.liana.adapter.fake.Card;
import de.gematik.liana.adapter.fake.CardEngine;
import de.gematik.liana.config.LianaConfig;
import jakarta.enterprise.inject.Alternative;
import jakarta.inject.Singleton;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

/**
 * kartos as in operation, plus per image the APDUs as {@code <command> <response>} in hex
 * (LIANA-112.13: trusted channel in SE #2). Only active where a test profile enables it via {@code
 * getEnabledAlternatives}.
 */
@Alternative
@Singleton
public class ObservedKartos implements CardEngine {

  private static final HexFormat HEX = HexFormat.of().withUpperCase();

  private final CardEngine kartos;
  private final List<String[]> apdus = new ArrayList<>();

  ObservedKartos(LianaConfig config) {
    this.kartos = TerminalWiring.cardEngineOf(config, Path.of(""));
  }

  @Override
  public Card open(Path image) throws IOException {
    Card card = kartos.open(image);
    String name = image.getFileName().toString().replace(".xml", "");
    return new Card() {
      @Override
      public byte[] atr() {
        return card.atr();
      }

      @Override
      public byte[] transmit(byte[] commandApdu) throws IOException {
        byte[] response = card.transmit(commandApdu);
        synchronized (apdus) {
          apdus.add(new String[] {name, HEX.formatHex(commandApdu), HEX.formatHex(response)});
        }
        return response;
      }

      @Override
      public void close() {
        card.close();
      }
    };
  }

  /** The APDUs to {@code image} since the last call, each {@code {command, response}}. */
  public List<String[]> take(String image) {
    synchronized (apdus) {
      List<String[]> taken =
          apdus.stream()
              .filter(apdu -> apdu[0].equals(image))
              .map(apdu -> new String[] {apdu[1], apdu[2]})
              .toList();
      apdus.clear();
      return taken;
    }
  }
}

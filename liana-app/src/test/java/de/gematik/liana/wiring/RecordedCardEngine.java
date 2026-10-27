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
import io.quarkus.test.Mock;
import jakarta.inject.Singleton;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.eclipse.microprofile.config.ConfigProvider;

/**
 * Card engine of the Quarkus tests: each card replays the APDU sequence of its image recorded with
 * kartos ({@code liana-kern/src/test/resources/apdu/<image>*.txt}, egk-valid, smcb-valid, hba-valid
 * or gsmckt-root6), so the JVM tests run without kartos. The order is free; a command not in the
 * recording is answered with 6D00. A command that occurs in several DFs (READ BINARY via SFI) is
 * answered according to the most recently selected DF.
 *
 * <p>Tests that need the card state (retry counter, transport PIN) set {@value #KARTOS} {@code
 * =kartos} in their test profile: then the cards run in kartos as in operation ({@link
 * TerminalWiring#cardEngine}).
 */
@Mock
@Singleton
public class RecordedCardEngine implements CardEngine {

  /** Test configuration, outside of {@code liana.*}, which the startup check knows. */
  public static final String KARTOS = "liana-test.card-engine";

  private static final HexFormat HEX = HexFormat.of().withUpperCase();
  private static final String SELECT_AID = "00A4040C";
  private static final Path RECORDINGS = Path.of("liana-kern/src/test/resources/apdu");

  private final CardEngine kartos;

  RecordedCardEngine(LianaConfig config) {
    this.kartos =
        ConfigProvider.getConfig()
            .getOptionalValue(KARTOS, String.class)
            .filter("kartos"::equals)
            .map(engine -> TerminalWiring.cardEngineOf(config, Path.of("")))
            .orElse(null);
  }

  @Override
  public Card open(Path image) throws IOException {
    if (kartos != null) {
      return kartos.open(image);
    }
    String name = image.getFileName().toString().replace(".xml", "");
    Map<String, String> answers = new HashMap<>();
    List<String> recordings =
        switch (name) {
          case "smcb-valid" ->
              List.of("smcb-valid.txt", "smcb-valid-pin.txt", "smcb-valid-sign.txt");
          case "hba-valid" -> List.of("hba-valid.txt", "hba-valid-ops.txt");
          case "gsmckt-root6" -> List.of("gsmckt-root6.txt", "gsmckt-root6-certs.txt");
          default -> List.of("egk-valid.txt", "egk-valid-vsd.txt");
        };
    for (String recording : recordings) {
      String df = "";
      for (String[] line : load(RECORDINGS.resolve(recording))) {
        answers.putIfAbsent(line[0], line[1]);
        answers.putIfAbsent(df + ">" + line[0], line[1]);
        if (line[0].startsWith(SELECT_AID) && line[1].endsWith("9000")) {
          df = line[0];
        }
      }
    }
    return new Card() {
      private String selected = "";

      @Override
      public byte[] atr() {
        return HEX.parseHex("3B00");
      }

      @Override
      public byte[] transmit(byte[] commandApdu) {
        String command = HEX.formatHex(commandApdu);
        String response =
            answers.getOrDefault(selected + ">" + command, answers.getOrDefault(command, "6D00"));
        if (command.startsWith(SELECT_AID) && response.endsWith("9000")) {
          selected = command;
        }
        return HEX.parseHex(response);
      }

      @Override
      public void close() {}
    };
  }

  private static List<String[]> load(Path recording) {
    try {
      return Files.readAllLines(recording).stream()
          .filter(l -> !l.startsWith("#") && !l.isBlank())
          .map(l -> l.split(" "))
          .toList();
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }
}

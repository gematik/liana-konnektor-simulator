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

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

/**
 * A card from a gematik XML card image, run by kartos as a separate process (decision-7). Each card
 * is a {@code kartos pipe <image>}: a command APDU as hex line in, a response line (data + SW) out.
 *
 * <p>{@code kartos pipe} does not supply the ATR; it is in the image as attribute {@code
 * coldAnswerToReset}.
 */
public final class KartosCard implements Card {

  private static final HexFormat HEX = HexFormat.of().withUpperCase();
  private static final String COLD_ATR = "coldAnswerToReset";

  private final Process process;
  private final BufferedWriter commands;
  private final BufferedReader responses;
  private final byte[] atr;

  private KartosCard(Process process, byte[] atr) {
    this.process = process;
    this.commands =
        new BufferedWriter(
            new OutputStreamWriter(process.getOutputStream(), StandardCharsets.US_ASCII));
    this.responses =
        new BufferedReader(
            new InputStreamReader(process.getInputStream(), StandardCharsets.US_ASCII));
    this.atr = atr;
  }

  /** Starts {@code kartos pipe} on the image; kartos messages on stderr end up in the LIANA log. */
  public static KartosCard open(Path kartos, Path image) throws IOException {
    return open(kartos, image, Optional.empty());
  }

  /**
   * Like {@link #open(Path, Path)}; with {@code anchors} kartos registers the CV certificates
   * ({@code *.cvc}) of this directory as trust anchors ({@code --anchors}), e.g. the root of a test
   * PoPP service (LIANA-28).
   */
  public static KartosCard open(Path kartos, Path image, Optional<Path> anchors)
      throws IOException {
    byte[] atr = coldAtr(image);
    List<String> command = new ArrayList<>(List.of(kartos.toString(), "pipe"));
    anchors.ifPresent(dir -> command.addAll(List.of("--anchors", dir.toString())));
    command.add(image.toString());
    Process process =
        new ProcessBuilder(command).redirectError(ProcessBuilder.Redirect.INHERIT).start();
    return new KartosCard(process, atr);
  }

  @Override
  public byte[] atr() {
    return atr.clone();
  }

  @Override
  public synchronized byte[] transmit(byte[] commandApdu) throws IOException {
    // kartos answers invalid lines only on stderr; without this check readLine() would hang.
    if (commandApdu.length < 4) {
      throw new IllegalArgumentException(
          "APDU kürzer als der Header (4 Byte): " + HEX.formatHex(commandApdu));
    }
    commands.write(HEX.formatHex(commandApdu));
    commands.newLine();
    commands.flush();
    String line = responses.readLine();
    if (line == null) {
      throw new IOException("kartos beendet (Exit " + exitCode() + ")");
    }
    return HEX.parseHex(line.strip());
  }

  @Override
  public void close() {
    process.destroy();
  }

  private String exitCode() {
    return process.isAlive() ? "läuft noch" : String.valueOf(process.exitValue());
  }

  static byte[] coldAtr(Path image) throws IOException {
    try (InputStream in = Files.newInputStream(image)) {
      XMLStreamReader xml = XMLInputFactory.newDefaultFactory().createXMLStreamReader(in);
      try {
        while (xml.hasNext()) {
          if (xml.next() == XMLStreamReader.START_ELEMENT
              && "attribute".equals(xml.getLocalName())
              && COLD_ATR.equals(xml.getAttributeValue(null, "id"))) {
            return HEX.parseHex(xml.getElementText().strip());
          }
        }
      } finally {
        xml.close();
      }
    } catch (XMLStreamException e) {
      throw new IOException("Kartenimage nicht lesbar: " + image, e);
    }
    throw new IOException("Kartenimage ohne " + COLD_ATR + ": " + image);
  }
}

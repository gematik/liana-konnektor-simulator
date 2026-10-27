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
package de.gematik.liana.sm;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.adapter.fake.Card;
import de.gematik.liana.adapter.fake.FakeTerminal;
import de.gematik.liana.adapter.fake.KartosCard;
import de.gematik.liana.kern.terminal.CardTerminal;
import de.gematik.liana.sicct.KartosTerminal;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * LIANA-28: trusted channel with two sessions against a real kartos ({@code kartos pipe}, eGK
 * {@code egk-valid}). The test plays the PoPP service with the test PKI from {@code
 * support/pki/sm/} (root as kartos anchor); towards the card, LIANA is the terminal with the
 * gSMC-KT {@code gsmc-kt/gsmckt-root6} (CVC root DEGXX870222 like the eGK).
 */
class TrustedChannelKartosIT {

  private static final HexFormat HEX = HexFormat.of().withUpperCase();
  private static final Path EGK = Path.of("support/images/egk-valid.xml");
  private static final Path GSMC_KT = Path.of("support/images/gsmc-kt/gsmckt-root6.xml");
  private static final Path TSL = Path.of("support/pki/tsl/ECC-RSA_TSL-ref.xml");
  private static final Path PKI = Path.of("support/pki/sm");
  private static final String ROOT = "4445544553540001";

  /** MSE SET AT: PrK.eGK.AUT_CVC.E256 (key reference 09), elcSessionkey4SM (algorithm 54). */
  private static final String MSE_SET_AT = "002241A406840109800154";

  private static final String SELECT_ESIGN = "00A4040C0AA000000167455349474E";

  /** READ BINARY EF.C.CH.AUT.E256 via SFI 04, Ne extended (as in the PoPP run of the Testhub). */
  private static final String READ_C_CH_AUT = "00B08400000000";

  /** Card that records every APDU to kartos. */
  static final class RecordingCard implements Card {

    final Card card;
    final List<String> commands = new ArrayList<>();

    RecordingCard(Card card) {
      this.card = card;
    }

    @Override
    public byte[] atr() {
      return card.atr();
    }

    @Override
    public synchronized byte[] transmit(byte[] commandApdu) throws IOException {
      commands.add(HEX.formatHex(commandApdu));
      return card.transmit(commandApdu);
    }

    @Override
    public void close() {
      card.close();
    }
  }

  record Plaintext(String command, byte[] response) {}

  /** Fake KT with the eGK in slot 1, in front of it LIANA with a terminated trusted channel. */
  private static final class Setup implements AutoCloseable {

    final List<RecordingCard> cards = new ArrayList<>();
    final List<Plaintext> plaintext = new ArrayList<>();
    final FakeTerminal fake;
    final TrustedChannelTerminal terminal;

    Setup(boolean twin) {
      fake =
          new FakeTerminal(
              "KT-SM",
              1,
              image -> {
                RecordingCard card =
                    new RecordingCard(
                        KartosCard.open(
                            KartosTerminal.kartosBinary(),
                            image,
                            Optional.of(PKI.resolve("anchors"))));
                cards.add(card);
                return card;
              });
      fake.insert(1, EGK);
      TerminalIdentity identity = TerminalIdentity.of(GSMC_KT, TerminalIdentity.links(TSL));
      terminal =
          new TrustedChannelTerminal(
              fake,
              identity,
              (ctId, slot) -> twin ? Optional.of(ImageObjects.load(EGK)) : Optional.empty(),
              (kt, slot, command, sent, response, received) ->
                  plaintext.add(new Plaintext(HEX.formatHex(command), response)));
    }

    RecordingCard card() {
      return cards.getLast();
    }

    @Override
    public void close() {
      fake.close();
    }
  }

  /** PoPP side of the trusted channel: session according to elcSessionkey4SM and its own SSC. */
  private static final class PoppService {

    final SecureMessaging.Session keys;
    byte[] ssc = new byte[16];

    PoppService(SecureMessaging.Session keys) {
      this.keys = keys;
    }

    byte[] wrap(String plain, boolean encrypted) throws Exception {
      ssc = SecureMessaging.increment(ssc);
      return SecureMessaging.wrapCommand(
          new SecureMessaging.Plain(HEX.parseHex(plain), encrypted), keys, ssc);
    }

    byte[] unwrap(byte[] response) throws Exception {
      ssc = SecureMessaging.increment(ssc);
      return SecureMessaging.unwrapResponse(response, keys, ssc).apdu();
    }
  }

  @Test
  @DisplayName(
      "LIANA-28: PoPP-Service ↔ LIANA (Hop A, Zwilling) und LIANA ↔ eGK (Hop B, gSMC-KT); "
          + "SM-Kommandos kommen im Klartext an, die Karte bekommt sie mit den Schlüsseln von Hop B")
  void terminate() throws Exception {
    try (Setup setup = new Setup(true)) {
      PoppService popp = handshake(setup.terminal);
      List<String> card = setup.card().commands;
      TerminalIdentity identity = TerminalIdentity.of(GSMC_KT, List.of());
      assertTrue(
          card.contains("002281B60A8308" + "4445475858870222"), "MSE SET DST mit der Root der eGK");
      assertTrue(
          card.contains("002281B60A8308" + "4445475858120223"),
          "MSE SET DST mit der CA der gSMC-KT");
      assertTrue(
          card.stream()
              .anyMatch(
                  c ->
                      c.startsWith("002A00BE")
                          && c.endsWith(HEX.formatHex(identity.endEntity().content()))),
          "Rollen-CVC der gSMC-KT importiert");
      assertTrue(
          card.stream()
              .anyMatch(
                  c ->
                      c.startsWith("108600001")
                          && c.contains("C30C" + HEX.formatHex(identity.endEntity().chr()))),
          "Hop B nennt die CHR der gSMC-KT");

      int before = card.size();
      for (String[] step : new String[][] {{SELECT_ESIGN, "true"}, {READ_C_CH_AUT, "false"}}) {
        byte[] command = popp.wrap(step[0], Boolean.parseBoolean(step[1]));
        byte[] response = setup.terminal.transmit(1, command);
        byte[] plain = popp.unwrap(response);
        Plaintext seen = setup.plaintext.getLast();
        assertEquals(step[0], seen.command());
        assertArrayEquals(plain, seen.response());
        assertFalse(
            card.getLast().equals(HEX.formatHex(command)),
            "an die Karte mit den Schlüsseln von Hop B");
        assertEquals(
            "9000", HEX.formatHex(Arrays.copyOfRange(plain, plain.length - 2, plain.length)));
      }
      assertEquals(before + 2, card.size());
      byte[] certificate = setup.plaintext.getLast().response();
      assertEquals(0x30, certificate[0] & 0xFF, "X.509-Zertifikat C.CH.AUT im Klartext");
    }
  }

  @Test
  @DisplayName(
      "LIANA-28: ohne Zwilling läuft der Trusted Channel direkt zwischen PoPP-Service und Karte")
  void withoutTwin() throws Exception {
    try (Setup setup = new Setup(false)) {
      PoppService popp = handshake(setup.terminal);
      byte[] command = popp.wrap(SELECT_ESIGN, true);
      byte[] response = setup.terminal.transmit(1, command);
      assertEquals("9000", HEX.formatHex(popp.unwrap(response)));
      assertEquals(HEX.formatHex(command), setup.card().commands.getLast());
      assertTrue(setup.plaintext.isEmpty());
    }
  }

  @Test
  @DisplayName(
      "LIANA-28, A_15856: SM-Kommando mit falschem MAC beendet die Sitzung, die Karte bekommt das Original "
          + "und antwortet 6988")
  void manipulatedMac() throws Exception {
    try (Setup setup = new Setup(true)) {
      PoppService popp = handshake(setup.terminal);
      byte[] command = popp.wrap(SELECT_ESIGN, true);
      command[command.length - 2] ^= 0x01;
      assertEquals("6988", HEX.formatHex(setup.terminal.transmit(1, command)));
      assertEquals(HEX.formatHex(command), setup.card().commands.getLast());
      assertTrue(setup.plaintext.isEmpty());
    }
  }

  /**
   * The test PoPP service sets up the channel as in the Testhub: MSE SET DST and PSO VERIFY
   * CERTIFICATE with its CVC, MSE SET AT, GENERAL AUTHENTICATE with its CHR and with its ephemeral
   * key.
   */
  private static PoppService handshake(CardTerminal terminal) throws Exception {
    Cvc cvc = Cvc.parse(Files.readAllBytes(PKI.resolve("popp.cvc")));
    assertEquals(
        "9000", HEX.formatHex(terminal.transmit(1, HEX.parseHex("002281B60A8308" + ROOT))));
    byte[] content = cvc.content();
    assertEquals(
        "9000",
        HEX.formatHex(
            terminal.transmit(
                1,
                HEX.parseHex(
                    "002A00BE" + String.format("%02X", content.length) + HEX.formatHex(content)))));
    assertEquals("9000", HEX.formatHex(terminal.transmit(1, HEX.parseHex(MSE_SET_AT))));
    byte[] step1 =
        terminal.transmit(1, HEX.parseHex("10860000107C0EC30C" + HEX.formatHex(cvc.chr()) + "00"));
    assertEquals("9000", HEX.formatHex(Arrays.copyOfRange(step1, step1.length - 2, step1.length)));
    byte[] cardEphemeral = Arrays.copyOfRange(step1, 4, 4 + 65);
    ElcSessionkey4Sm.KeyPair ephemeral = ElcSessionkey4Sm.ephemeral();
    byte[] step2 =
        terminal.transmit(
            1, HEX.parseHex("00860000457C438541" + HEX.formatHex(ephemeral.point()) + "00"));
    assertEquals("9000", HEX.formatHex(step2));
    byte[] cardStatic =
        ImageObjects.load(EGK).privateKey(0x09, "elcSessionkey4SM").orElseThrow().point();
    return new PoppService(
        ElcSessionkey4Sm.asTerminal(poppKey(), ephemeral, cardStatic, cardEphemeral));
  }

  private static ElcSessionkey4Sm.KeyPair poppKey() throws IOException {
    String pem = Files.readString(PKI.resolve("popp-key.pem"));
    byte[] der = Base64.getMimeDecoder().decode(pem.replaceAll("-----[A-Z ]+-----", ""));
    ECPrivateKey key = ECPrivateKey.getInstance(PrivateKeyInfo.getInstance(der).parsePrivateKey());
    byte[] d = key.getKey().toByteArray();
    return ElcSessionkey4Sm.KeyPair.of(d);
  }
}

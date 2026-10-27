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

import static de.gematik.liana.sm.Apdus.OK;
import static de.gematik.liana.sm.Apdus.WRONG_DATA;
import static de.gematik.liana.sm.Apdus.concat;
import static de.gematik.liana.sm.Apdus.data;
import static de.gematik.liana.sm.Apdus.fields;
import static de.gematik.liana.sm.Apdus.isOk;
import static de.gematik.liana.sm.Apdus.tlv;

import de.gematik.liana.kern.terminal.CardTerminal;
import de.gematik.liana.kern.terminal.CardTerminalInfo;
import de.gematik.liana.kern.terminal.PinCommand;
import de.gematik.liana.kern.terminal.SlotListener;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Terminates the PoPP service's trusted channel in LIANA ({@code
 * liana.card.terminate-secure-messaging}, LIANA-28) with two separate sessions per elcSessionkey4SM
 * (gemSpec_COS 15.4):
 *
 * <ul>
 *   <li><b>Hop A</b>, PoPP service ↔ LIANA: LIANA answers GENERAL AUTHENTICATE as the card, with
 *       the private key of the virtual twin ({@link Twins}, card image for the ICCSN). LIANA picks
 *       up the PoPP service's static key from its PSO VERIFY CERTIFICATE, which, like MSE SET AT,
 *       goes to the card unchanged: whether the chain is valid is decided by the card.
 *   <li><b>Hop B</b>, LIANA ↔ card: LIANA is the terminal, with the gSMC-KT of the card terminal
 *       ({@link TerminalIdentity}); LIANA imports the chain itself (MSE SET DST, PSO VERIFY
 *       CERTIFICATE), then GENERAL AUTHENTICATE in two steps.
 * </ul>
 *
 * After that LIANA unwraps every protected APDU with the keys of hop A and rewraps it with those of
 * hop B, responses the other way round; the {@link Listener} gets the plain text. If anything is
 * missing for termination (twin, key, CVC of the PoPP service, path to a root of the card), the
 * channel runs directly between PoPP service and card as without termination. A command without
 * secure messaging or an SM error ends the session as on the card (A_15855, A_15856).
 */
public final class TrustedChannelTerminal implements CardTerminal {

  private static final System.Logger LOG = System.getLogger(TrustedChannelTerminal.class.getName());
  private static final HexFormat HEX = HexFormat.of().withUpperCase();
  private static final String ALGORITHM = "elcSessionkey4SM";

  /** algId elcSessionkey4SM in MSE SET AT (tag 80). */
  private static final int ALGORITHM_ID = 0x54;

  /** The virtual twin of the card in a slot: its image, found via the ICCSN. */
  @FunctionalInterface
  public interface Twins {
    Optional<ImageObjects> of(String ctId, int slot);
  }

  /** Receiver of the plain text of each terminated APDU. */
  @FunctionalInterface
  public interface Listener {
    void plaintext(
        String terminal, int slot, byte[] command, Instant sent, byte[] response, Instant received);
  }

  private final CardTerminal terminal;
  private final TerminalIdentity identity;
  private final Twins twins;
  private final Listener listener;
  private final Map<Integer, Slot> slots = new HashMap<>();

  public TrustedChannelTerminal(
      CardTerminal terminal, TerminalIdentity identity, Twins twins, Listener listener) {
    this.terminal = terminal;
    this.identity = identity;
    this.twins = twins;
    this.listener = listener;
    terminal.addSlotListener(
        new SlotListener() {
          @Override
          public void slotInUse(String ctId, int slot) {
            forget(slot);
          }

          @Override
          public void slotFree(String ctId, int slot) {
            forget(slot);
          }
        });
  }

  /** What LIANA knows per slot about the setup of the channel. */
  private static final class Slot {
    /** Public keys from the PoPP service's PSO VERIFY CERTIFICATE, per CHR. */
    final Map<String, byte[]> imported = new HashMap<>();

    /** The last successful MSE SET AT for elcSessionkey4SM, otherwise null. */
    byte[] setAt;

    int keyReference;
    Handshake handshake;
    Channel channel;
  }

  /** After step 1: LIANA as card towards the PoPP service, hop B is already established. */
  private record Handshake(
      ElcSessionkey4Sm.KeyPair cardStatic,
      ElcSessionkey4Sm.KeyPair cardEphemeral,
      byte[] terminalStatic,
      SecureMessaging.Session hopB) {}

  /** Both sessions with their SSCmac after the last response. */
  private static final class Channel {
    final SecureMessaging.Session hopA;
    final SecureMessaging.Session hopB;
    byte[] sscA = new byte[16];
    byte[] sscB = new byte[16];

    Channel(SecureMessaging.Session hopA, SecureMessaging.Session hopB) {
      this.hopA = hopA;
      this.hopB = hopB;
    }
  }

  /** Hop B failed: the card's status word goes to the PoPP service. */
  private static final class HopBFailed extends Exception {
    final byte[] status;

    HopBFailed(String message, byte[] status) {
      super(message);
      this.status = status;
    }
  }

  @Override
  public String id() {
    return terminal.id();
  }

  @Override
  public int slots() {
    return terminal.slots();
  }

  @Override
  public CardTerminalInfo info() {
    return terminal.info();
  }

  @Override
  public void addSlotListener(SlotListener listener) {
    terminal.addSlotListener(listener);
  }

  @Override
  public boolean cardPresent(int slot) {
    return terminal.cardPresent(slot);
  }

  @Override
  public byte[] reset(int slot) throws IOException {
    forget(slot);
    return terminal.reset(slot);
  }

  @Override
  public byte[] pinCommand(int slot, PinCommand command) throws IOException {
    return terminal.pinCommand(slot, command);
  }

  @Override
  public boolean securePinEntry() {
    return terminal.securePinEntry();
  }

  @Override
  public boolean requestCard(int slot, String displayMessage, Duration wait) throws IOException {
    return terminal.requestCard(slot, displayMessage, wait);
  }

  @Override
  public boolean ejectCard(int slot, String displayMessage, Duration wait) throws IOException {
    return terminal.ejectCard(slot, displayMessage, wait);
  }

  @Override
  public synchronized byte[] transmit(int slot, byte[] command) throws IOException {
    Slot state = slots.computeIfAbsent(slot, s -> new Slot());
    if (state.channel != null) {
      if (SecureMessaging.isSecured(command)) {
        return terminate(slot, state, command);
      }
      // G2_N031.600.a.1: a command without secure messaging deletes the session keys, likewise on
      // the card
      state.channel = null;
    }
    Handshake handshake = state.handshake;
    state.handshake = null;
    if (handshake != null && isGeneralAuthenticate(command, false)) {
      return step2(state, handshake, command);
    }
    if (state.setAt != null && isGeneralAuthenticate(command, true)) {
      Optional<byte[]> response = step1(slot, state, command);
      if (response.isPresent()) {
        return response.get();
      }
    }
    byte[] response = terminal.transmit(slot, command);
    observe(state, command, response);
    return response;
  }

  private synchronized void forget(int slot) {
    slots.remove(slot);
  }

  /** Remembers what the PoPP service has prepared for the channel and the card has accepted. */
  private static void observe(Slot state, byte[] command, byte[] response) {
    if (!isOk(response) || command.length < 5 || command[0] != 0) {
      return;
    }
    int ins = command[1] & 0xFF;
    int p1 = command[2] & 0xFF;
    int p2 = command[3] & 0xFF;
    byte[] data = data(command);
    if (ins == 0x2A && p1 == 0x00 && p2 == 0xBE) {
      try {
        Cvc cvc = Cvc.parse(data);
        state.imported.put(HEX.formatHex(cvc.chr()), cvc.publicKey());
      } catch (IllegalArgumentException e) {
        LOG.log(
            System.Logger.Level.DEBUG,
            "PSO VERIFY CERTIFICATE ohne lesbares CVC: {0}",
            e.getMessage());
      }
    } else if (ins == 0x22 && p1 == 0x41 && p2 == 0xA4) {
      Map<Integer, byte[]> fields = fields(data);
      byte[] algorithm = fields.get(0x80);
      byte[] key = fields.get(0x84);
      boolean sessionkey4Sm =
          algorithm != null
              && algorithm.length == 1
              && (algorithm[0] & 0xFF) == ALGORITHM_ID
              && key != null
              && key.length == 1;
      state.setAt = sessionkey4Sm ? command.clone() : null;
      state.keyReference = sessionkey4Sm ? key[0] & 0xFF : 0;
    }
  }

  /**
   * GENERAL AUTHENTICATE step 1 of the PoPP service ((N085.052)): first hop B to the card, then
   * LIANA answers as the card with its own ephemeral key. Empty if LIANA cannot terminate; the
   * command then goes to the card.
   */
  private Optional<byte[]> step1(int slot, Slot state, byte[] command) throws IOException {
    byte[] chr = fields(fields(data(command)).getOrDefault(0x7C, new byte[0])).get(0xC3);
    String why = null;
    byte[] terminalStatic = chr == null ? null : state.imported.get(HEX.formatHex(chr));
    Optional<ImageObjects> twin = twins.of(id(), slot);
    Optional<ElcSessionkey4Sm.KeyPair> cardStatic =
        twin.flatMap(t -> t.privateKey(state.keyReference, ALGORITHM));
    Optional<List<Cvc>> chain = twin.flatMap(t -> identity.chainFor(t.verificationKeys()));
    if (terminalStatic == null) {
      why =
          "CVC zur CHR "
              + (chr == null ? "?" : HEX.formatHex(chr))
              + " nicht per PSO VERIFY CERTIFICATE gesehen";
    } else if (twin.isEmpty()) {
      why = "kein Kartenimage zur Karte (card-images, ICCSN)";
    } else if (cardStatic.isEmpty()) {
      why =
          String.format(
              "%s: kein privater Schlüssel %02X für %s",
              twin.get().image().getFileName(), state.keyReference, ALGORITHM);
    } else if (chain.isEmpty()) {
      why = identity + ": keine CVC-Kette zu den Roots der Karte (TSL, Cross-CVCs)";
    }
    if (why != null) {
      LOG.log(
          System.Logger.Level.WARNING,
          "{0}/{1}: Trusted Channel nicht terminiert, {2}",
          id(),
          slot,
          why);
      return Optional.empty();
    }
    SecureMessaging.Session hopB;
    try {
      hopB = hopB(slot, state, cardStatic.get(), chain.get());
    } catch (HopBFailed e) {
      LOG.log(
          System.Logger.Level.WARNING,
          "{0}/{1}: Trusted Channel zur Karte (Hop B) gescheitert: {2}",
          id(),
          slot,
          e.getMessage());
      return Optional.of(e.status);
    }
    LOG.log(
        System.Logger.Level.INFO,
        "{0}/{1}: Trusted Channel terminiert, Hop A mit CHR {2} (Zwilling {3}), "
            + "Hop B mit CHR {4}",
        id(),
        slot,
        HEX.formatHex(chr),
        twin.get().image().getFileName(),
        HEX.formatHex(identity.endEntity().chr()));
    ElcSessionkey4Sm.KeyPair ephemeral = ElcSessionkey4Sm.ephemeral();
    state.handshake = new Handshake(cardStatic.get(), ephemeral, terminalStatic, hopB);
    // G2_N085.052.h: responseData = 7C-L-(85-L-ephemeralPK_self)
    return Optional.of(concat(tlv(0x7C, tlv(0x85, ephemeral.point())), OK));
  }

  /** Step 2 of the PoPP service ((N085.054)): derive the hop A session, empty response data. */
  private byte[] step2(Slot state, Handshake handshake, byte[] command) {
    byte[] terminalEphemeral =
        fields(fields(data(command)).getOrDefault(0x7C, new byte[0])).get(0x85);
    if (terminalEphemeral == null) {
      return WRONG_DATA;
    }
    try {
      SecureMessaging.Session hopA =
          ElcSessionkey4Sm.asCard(
              handshake.cardStatic(),
              handshake.cardEphemeral(),
              handshake.terminalStatic(),
              terminalEphemeral);
      state.channel = new Channel(hopA, handshake.hopB());
      return OK;
    } catch (IllegalArgumentException e) {
      return WRONG_DATA;
    }
  }

  /**
   * Hop B: import the chain, repeat the PoPP service's MSE SET AT, GENERAL AUTHENTICATE as
   * terminal.
   */
  private SecureMessaging.Session hopB(
      int slot, Slot state, ElcSessionkey4Sm.KeyPair cardStatic, List<Cvc> chain)
      throws IOException, HopBFailed {
    try {
      return SourceCard.authenticate(
          terminal, slot, identity, List.of(chain), state.setAt, cardStatic.point());
    } catch (SourceCard.Failed e) {
      throw new HopBFailed(e.getMessage(), e.status);
    }
  }

  /** A protected APDU: unwrap from hop A, wrap into hop B, the response the other way round. */
  private byte[] terminate(int slot, Slot state, byte[] command) throws IOException {
    Channel channel = state.channel;
    byte[] sscA = SecureMessaging.increment(channel.sscA);
    byte[] sscB = SecureMessaging.increment(channel.sscB);
    SecureMessaging.Plain plain;
    byte[] forward;
    try {
      plain = SecureMessaging.unwrapCommand(command, channel.hopA, sscA);
      forward = SecureMessaging.wrapCommand(plain, channel.hopB, sscB);
    } catch (SecureMessaging.SecureMessagingException e) {
      // G2_N031.700.a.2: an SM error deletes the session; the card sees the original and answers as
      // usual
      LOG.log(
          System.Logger.Level.WARNING,
          "{0}/{1}: SM-Kommando nicht auswickelbar ({2}), Sitzung beendet",
          id(),
          slot,
          e.getMessage());
      state.channel = null;
      return terminal.transmit(slot, command);
    }
    Instant sent = Instant.now();
    byte[] response = terminal.transmit(slot, forward);
    Instant received = Instant.now();
    sscA = SecureMessaging.increment(sscA);
    sscB = SecureMessaging.increment(sscB);
    SecureMessaging.Plain answer;
    byte[] back;
    try {
      answer = SecureMessaging.unwrapResponse(response, channel.hopB, sscB);
      back = SecureMessaging.wrapResponse(answer, channel.hopA, sscA);
    } catch (SecureMessaging.SecureMessagingException e) {
      LOG.log(
          System.Logger.Level.WARNING,
          "{0}/{1}: Antwort der Karte ohne gültiges Secure Messaging ({2}), " + "Sitzung beendet",
          id(),
          slot,
          e.getMessage());
      state.channel = null;
      listener.plaintext(id(), slot, plain.apdu(), sent, response, received);
      return response;
    }
    channel.sscA = sscA;
    channel.sscB = sscB;
    listener.plaintext(id(), slot, plain.apdu(), sent, answer.apdu(), received);
    return back;
  }

  private static boolean isGeneralAuthenticate(byte[] command, boolean chained) {
    return command.length >= 5
        && (command[1] & 0xFF) == 0x86
        && command[0] == (chained ? 0x10 : 0x00);
  }
}

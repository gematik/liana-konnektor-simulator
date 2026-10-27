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

import de.gematik.liana.kern.terminal.CardTerminal;
import de.gematik.liana.kern.terminal.CardTerminalInfo;
import de.gematik.liana.kern.terminal.NoCardException;
import de.gematik.liana.kern.terminal.PinCommand;
import de.gematik.liana.kern.terminal.PinDialog;
import de.gematik.liana.kern.terminal.SlotListener;
import de.gematik.liana.kern.vendor.Deviation;
import de.gematik.liana.kern.vendor.PeerDeviations;
import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Supplier;

/**
 * An eHealth card terminal configured via YAML behind the port {@link CardTerminal} (decision-3):
 * CT.CTID from the YAML, CT.SLOTCOUNT from the CT object once TUC_KON_055 has populated it. The
 * occupied slots (CT.SLOTS_USED) follow the working connection: TUC_KON_050 step 11 on connect,
 * then the slot events {@code 84}/{@code 85} (TIP1-A_4541-02, TIP1-A_4542-02); on disconnect all
 * become free (TIP1-A_4537).
 *
 * <p>Card access only via the working connection (state ClientWithPairing, gemSpec_KT
 * TIP1-A_3266-01): reset via SICCT RESET ICC with cold ATR (SICCT 1.2.3 §5.12, P2 {@code 01}),
 * command APDUs in the envelope to the slot FU {@code 00nn} (§6.2.4.3), plus REQUEST ICC (§5.13,
 * TUC_KON_056) and EJECT ICC (§5.14, TUC_KON_057). Without a connection access fails with {@link
 * IOException} (TUC_KON_200: 4044), without a response with {@link
 * de.gematik.liana.kern.terminal.CardTimeoutException} (4094), without a card with {@link
 * NoCardException}.
 */
public final class SicctTerminal implements CardTerminal {

  private final String id;
  private final Supplier<Optional<CtObject>> ct;
  private final List<SlotListener> listeners = new CopyOnWriteArrayList<>();
  private final java.util.Set<Integer> used = new java.util.concurrent.ConcurrentSkipListSet<>();
  private final Supplier<Optional<SicctConnection>> connection;
  private final java.time.Duration timeout;
  private final PeerDeviations deviations;

  /**
   * Status word "Wrong Lc" ([SICCT] §5.20.6); kartos 0.8.0 answers the spec-conformant command this
   * way.
   */
  private static final byte[] WRONG_LENGTH = {0x67, 0x00};

  SicctTerminal(String id, Supplier<Optional<CtObject>> ct) {
    this(
        id,
        ct,
        Optional::empty,
        java.time.Duration.ofSeconds(10),
        new PeerDeviations(
            false, new de.gematik.liana.kern.event.SystemLog(java.time.Clock.systemUTC(), 10)));
  }

  SicctTerminal(
      String id,
      Supplier<Optional<CtObject>> ct,
      Supplier<Optional<SicctConnection>> connection,
      java.time.Duration timeout,
      PeerDeviations deviations) {
    this.id = id;
    this.ct = ct;
    this.connection = connection;
    this.timeout = timeout;
    this.deviations = deviations;
  }

  @Override
  public String id() {
    return id;
  }

  /** CT.SLOTCOUNT; 0 as long as the CT object is missing or not populated. */
  @Override
  public int slots() {
    return ct.get().map(CtObject::slotCount).orElse(0);
  }

  /**
   * TAB_KON_563 from the CT object (TAB_KON_522), without querying the card terminal: name
   * CT.HOSTNAME, CT.MAC_ADRESS, CT.IP_ADRESS, CT.SLOTCOUNT, CT.CONNECTED, CT.PRODUCTINFORMATION; if
   * the CT object is missing, only CtId and not connected (IP {@link CardTerminalInfo#UNKNOWN_IP}).
   */
  @Override
  public CardTerminalInfo info() {
    return ct.get()
        .map(
            o ->
                new CardTerminalInfo(
                    id,
                    o.hostname() != null ? o.hostname() : id,
                    CardTerminalInfo.schemaMac(o.mac()),
                    o.ip() instanceof java.net.Inet4Address v4 ? v4.getHostAddress() : null,
                    o.slotCount(),
                    true,
                    o.connected(),
                    CardTerminalInfo.Product.of(
                        o.productInformation(), CardTerminalInfo.Product.FAKE)))
        .orElseGet(
            () ->
                new CardTerminalInfo(
                    id,
                    id,
                    CardTerminalInfo.fake(id, 0).macAddress(),
                    null,
                    0,
                    true,
                    false,
                    CardTerminalInfo.Product.FAKE));
  }

  @Override
  public void addSlotListener(SlotListener listener) {
    listeners.add(listener);
  }

  @Override
  public boolean cardPresent(int slot) {
    return used.contains(slot);
  }

  /** CT.SLOTS_USED */
  public List<Integer> slotsUsed() {
    return List.copyOf(used);
  }

  /** TIP1-A_4541-02: card inserted into {@code slot} → CT/SLOT_IN_USE. */
  void inserted(int slot) {
    if (used.add(slot)) {
      listeners.forEach(l -> l.slotInUse(id, slot));
    }
  }

  /** TIP1-A_4542-02: card removed from {@code slot} → CT/SLOT_FREE. */
  void removed(int slot) {
    if (used.remove(slot)) {
      listeners.forEach(l -> l.slotFree(id, slot));
    }
  }

  /** TIP1-A_4537: connection lost, all slots free. */
  void clear() {
    for (Integer slot : List.copyOf(used)) {
      removed(slot);
    }
  }

  /**
   * SICCT RESET ICC with cold ATR (§5.12, {@code 80 11 nn 01}); returns the ATR from the ATR DO
   * {@code 5F41}.
   */
  @Override
  public byte[] reset(int slot) throws IOException {
    requireCard(slot);
    byte[] response = terminalCommand(new byte[] {(byte) 0x80, 0x11, (byte) slot, 0x01, 0x00});
    return atr(slot, "RESET ICC", response);
  }

  /**
   * Command APDU in the envelope to the FU {@code 00nn} of the slot; returns the response APDU with
   * status word.
   */
  @Override
  public byte[] transmit(int slot, byte[] commandApdu) throws IOException {
    requireCard(slot);
    return working().transmit(slot, commandApdu, timeout);
  }

  /**
   * TUC_KON_056 "Karte anfordern" (request card) step 2: SICCT REQUEST ICC (§5.13) with display
   * (APPL DO) and waiting time (WT DO, whole seconds, rounded up). {@code 6201} (card was already
   * inserted and activated) and {@code 90xx} mean inserted, {@code 6200} timeout (§5.13.6); the
   * response may take up to the waiting time plus CARD_TIMEOUT_CARD.
   */
  @Override
  public boolean requestCard(int slot, String displayMessage, java.time.Duration wait)
      throws IOException {
    byte[] response =
        terminalCommand(iccCommand(0x12, slot, 0x01, displayMessage, wait, true), wait);
    return waited(slot, "REQUEST ICC", response);
  }

  /**
   * TUC_KON_057 "Karte auswerfen" (eject card) step 3: SICCT EJECT ICC (§5.14) with "Delivery:
   * Mechanical Throw out" ({@code P2 = 00}), display (APPL DO) and waiting time (WT DO). The
   * command is sent even without a reported card (TUC_KON_057 variants); the card terminal reports
   * the removal with {@code 85}. {@code 9000} and {@code 9001} mean removed (§5.14.6, see {@link
   * #ejected(byte[])}), {@code 6200} deactivated but not removed.
   */
  @Override
  public boolean ejectCard(int slot, String displayMessage, java.time.Duration wait)
      throws IOException {
    byte[] response =
        terminalCommand(iccCommand(0x15, slot, 0x00, displayMessage, wait, false), wait);
    if (ejected(response)) {
      return true;
    }
    if (sw(response).equals("6200")) {
      return false;
    }
    throw new IOException(id + "/" + slot + ": EJECT ICC " + sw(response));
  }

  /**
   * {@code 6200}: waiting time expired; {@code 90xx} and {@code 6201}: success; otherwise {@link
   * IOException}.
   */
  private boolean waited(int slot, String command, byte[] response) throws IOException {
    String sw = sw(response);
    if (sw.equals("6200")) {
      return false;
    }
    if (sw.startsWith("90") || sw.equals("6201")) {
      return true;
    }
    throw new IOException(id + "/" + slot + ": " + command + " " + sw);
  }

  /**
   * SICCT 1.2.3 §5.14.6: after EJECT ICC, SW1 {@code 90} means success; SW2 {@code 01} "Command
   * Successful, card removed", {@code 00} without indication whether the card was removed. {@code
   * 62xx} (card not removed) and everything else is an error.
   */
  static boolean ejected(byte[] response) {
    return response.length >= 2
        && (response[response.length - 2] & 0xFF) == 0x90
        && (response[response.length - 1] == 0x00 || response[response.length - 1] == 0x01);
  }

  /**
   * PIN entry on the PIN pad of the card terminal and VERIFY to the card (TUC_KON_012 7b): SICCT
   * PERFORM VERIFICATION (§5.19) for slot {@code slot} ({@code P1}, direct coding) to the standard
   * keypad with confirmation key ({@code P2 = D0}, §5.19.3; the PIN length is variable, 6–8 digits
   * per TAB_KON_090). The data field holds the displays as APPL DOs in the order of the standard
   * texts from §5.19.2 – request with PIN prompt (no. 4), success (no. 5), error (no. 6) –, which
   * the card terminal displays per gemSpec_KT TIP1-A_3083 (TIP1-A_3084: up to 48 characters
   * message, TIP1-A_3085: up to 10 characters prompt); then the Command-To-Perform DO ({@code 52},
   * §5.5.10.23): control byte {@code 02} (format-2 PIN block, gemSpec_KT TIP1-A_3013-01), insertion
   * position {@code 06}, VERIFY {@code 00 20 00 ref 08} with placeholder block. Without a WT DO the
   * card terminal waits 30 s for the first character (TIP1-A_3086). Returns the status word of the
   * card (9000, 63Cx, 6983 …) or of the card terminal (6400 timeout, 6401 cancel, §5.19.6); the PIN
   * does not leave the card terminal.
   *
   * <p>LIANA-109: every card command with a PIN block (VERIFY, ENABLE/DISABLE VERIFICATION
   * REQUIREMENT, RESET RETRY COUNTER P1 '01'). LIANA-127: new PIN with repetition via {@link
   * #modifyVerificationData} (§5.20, TUC_KON_019/021 7b), status words of the card terminal per
   * §5.20.6 (SICCT Errata 1.0, among others {@code 6402} mismatched repetition). If the card
   * terminal answers the spec-conformant command with {@code 6700}, this is the known deviation
   * {@link Deviation#KARTOS_MODIFY_VERIFICATION_DATA}: without {@code liana.strict} LIANA repeats
   * the command in kartos format ({@link #kartosModify}), with {@code strict} access fails (4044);
   * both are recorded in the Systemprotokoll ({@link PeerDeviations}).
   */
  @Override
  public byte[] pinCommand(int slot, PinCommand command) throws IOException {
    if (command.channel() != null) {
      // LIANA does not implement the remote PIN procedure with the gSMC-KT of the eHealth card
      // terminal
      // (securePinEntry, LIANA-112.13)
      throw new IOException(id + "/" + slot + ": PIN-Eingabe im Trusted Channel nicht unterstützt");
    }
    requireCard(slot);
    if (command.mode() == PinCommand.Mode.ONE) {
      return statusWord(
          slot, "PERFORM VERIFICATION", terminalCommand(performVerification(slot, command)));
    }
    byte[] sw =
        statusWord(
            slot,
            "MODIFY VERIFICATION DATA",
            terminalCommand(modifyVerificationData(slot, command)));
    if (!java.util.Arrays.equals(sw, WRONG_LENGTH)) {
      return sw;
    }
    if (!deviations.tolerate(
        Deviation.KARTOS_MODIFY_VERIFICATION_DATA,
        id,
        java.util.Map.of(
            "Slot", String.valueOf(slot), "Command", command.toString(), "StatusWord", "6700"))) {
      throw new IOException(
          id
              + "/"
              + slot
              + ": MODIFY VERIFICATION DATA 6700 ("
              + command
              + "), Abweichung "
              + Deviation.KARTOS_MODIFY_VERIFICATION_DATA
              + " nicht toleriert (liana.strict)");
    }
    return statusWord(
        slot, "MODIFY VERIFICATION DATA (kartos)", terminalCommand(kartosModify(slot, command)));
  }

  /** The last two bytes of the response, {@link IOException} without status word. */
  private byte[] statusWord(int slot, String what, byte[] response) throws IOException {
    if (response.length < 2) {
      throw new IOException(id + "/" + slot + ": " + what + " ohne Statuswort");
    }
    return java.util.Arrays.copyOfRange(response, response.length - 2, response.length);
  }

  /**
   * SICCT MODIFY VERIFICATION DATA (SICCT 1.2.3 §5.20.3) for {@link PinCommand.Mode#OLD_NEW} and
   * {@link PinCommand.Mode#NEW}: {@code 80 19}, P1 = slot (direct coding), P2 = {@code D0}
   * (standard keypad with confirmation key), no Le (gemSpec_KT A_25230). The data field holds the
   * displays per TAB_KON_090 as APPL DOs in the positions of the standard texts from §5.20.2: 1.
   * old PIN, transport PIN or PUK (no. 4), 2. success (no. 5), 3. error (no. 6), 4. new PIN (no.
   * 7), 5. repetition (no. 8), 6. mismatched repetition (no. 9); 7. and 8. (confirmation, cancel)
   * remain standard texts. Then the CMD DO {@code 52} (§5.5.10.23): control byte {@code 02}
   * (format-2 PIN block, variable length), insertion positions of the 1st and 2nd PIN, the card
   * command with placeholder blocks. Unblocking also goes via {@code 80 19}; the card APDU {@code
   * 00 2C} carries the operation (gemSpec_KT A_24111).
   *
   * <p>{@link PinCommand.Mode#NEW} (empty PIN, PIN.AMTS_REP: CHANGE REFERENCE DATA P1 '01', RESET
   * RETRY COUNTER P1 '02') is the null-PIN procedure from §5.20.2: 1st insertion position {@code
   * 00}, the 1st display as an empty APPL DO; the card terminal only asks for the new PIN with
   * repetition and inserts it at the 2nd insertion position.
   */
  static byte[] modifyVerificationData(int slot, PinCommand command) {
    boolean nullPin = command.mode() == PinCommand.Mode.NEW;
    java.util.List<String> prompts = command.prompts();
    java.util.List<String> texts =
        java.util.List.of(
            nullPin ? "" : prompts.getFirst(),
            command.success(),
            command.failure(),
            prompts.get(prompts.size() - 2),
            prompts.getLast(),
            command.mismatch());
    java.io.ByteArrayOutputStream data = new java.io.ByteArrayOutputStream();
    for (String text : texts) {
      data.writeBytes(new Tlv(0x50, display(text)).encode());
    }
    byte[] apdu = cardCommand(command);
    byte[] cmd = new byte[3 + apdu.length];
    cmd[0] = 0x02;
    cmd[1] = (byte) (nullPin ? 0x00 : 0x06);
    cmd[2] = (byte) (nullPin ? 0x06 : 0x0E);
    System.arraycopy(apdu, 0, cmd, 3, apdu.length);
    data.writeBytes(new Tlv(0x52, cmd).encode());
    return terminalApdu(0x19, slot, data.toByteArray());
  }

  /**
   * The command in the format of kartos terminal 0.8.0 ({@link
   * Deviation#KARTOS_MODIFY_VERIFICATION_DATA}): the displays as with PERFORM VERIFICATION (kartos
   * looks for {@code SLOT:n} in them), a PinFormat DO {@code 5F2F} (BCD/format 2, block 8 bytes,
   * length nibble 1, digits from nibble 2, 4–12 digits) and the card command without control byte
   * and insertion positions in the DO {@code 52}. Change as {@code 80 19}, unblock as {@code 80
   * 1A}; only the new PIN ({@link PinCommand.Mode#NEW}) is always taken by kartos as two blocks
   * there, hence as {@code 80 18} with a single entry, without repetition.
   */
  static byte[] kartosModify(int slot, PinCommand command) {
    java.io.ByteArrayOutputStream data = new java.io.ByteArrayOutputStream();
    for (String text :
        java.util.List.of(command.prompts().getFirst(), command.success(), command.failure())) {
      data.writeBytes(new Tlv(0x50, display(text)).encode());
    }
    data.writeBytes(new Tlv(0x5F2F, new byte[] {0x02, 0x08, 0x01, 0x02, 0x04, 0x0C}).encode());
    data.writeBytes(new Tlv(0x52, cardCommand(command)).encode());
    int ins =
        command.mode() == PinCommand.Mode.NEW ? 0x18 : command.header()[1] == 0x2C ? 0x1A : 0x19;
    return terminalApdu(ins, slot, data.toByteArray());
  }

  /** Card command with Lc and eight placeholder bytes {@code FF} per PIN block. */
  private static byte[] cardCommand(PinCommand command) {
    return java.util.HexFormat.of().parseHex(command.template());
  }

  /**
   * {@code 80 <ins> <slot> D0 Lc <data>}, no Le (gemSpec_KT A_22869-01, A_25230); for more than 255
   * bytes of data (all six displays from TAB_KON_090 with MODIFY VERIFICATION DATA) with extended
   * Lc {@code 00 HH LL} ([SICCT] §5.20.3).
   */
  private static byte[] terminalApdu(int ins, int slot, byte[] data) {
    java.io.ByteArrayOutputStream apdu = new java.io.ByteArrayOutputStream();
    apdu.writeBytes(new byte[] {(byte) 0x80, (byte) ins, (byte) slot, (byte) 0xD0});
    if (data.length > 0xFF) {
      apdu.writeBytes(new byte[] {0x00, (byte) (data.length >> 8), (byte) data.length});
    } else {
      apdu.write(data.length);
    }
    apdu.writeBytes(data);
    return apdu.toByteArray();
  }

  static byte[] performVerification(int slot, int pinReference, PinDialog dialog) {
    return performVerification(slot, PinCommand.verify(pinReference, dialog));
  }

  static byte[] performVerification(int slot, PinCommand command) {
    java.io.ByteArrayOutputStream data = new java.io.ByteArrayOutputStream();
    for (String text :
        java.util.List.of(command.prompts().getFirst(), command.success(), command.failure())) {
      data.writeBytes(new Tlv(0x50, display(text)).encode());
    }
    byte[] header = command.header();
    byte[] verify = {
      header[0],
      header[1],
      header[2],
      header[3],
      0x08,
      (byte) 0xFF,
      (byte) 0xFF,
      (byte) 0xFF,
      (byte) 0xFF,
      (byte) 0xFF,
      (byte) 0xFF,
      (byte) 0xFF,
      (byte) 0xFF
    };
    byte[] cmd = new byte[2 + verify.length];
    cmd[0] = 0x02;
    cmd[1] = 0x06;
    System.arraycopy(verify, 0, cmd, 2, verify.length);
    data.writeBytes(new Tlv(0x52, cmd).encode());
    return terminalApdu(0x18, slot, data.toByteArray());
  }

  /**
   * Display text in the character set ISO 646-DE / DIN 66003 (TAB_KON_090, notes): the umlauts, ß
   * and § in the positions of [ \\ ] { | } ~ @, otherwise ASCII.
   */
  static byte[] display(String text) {
    StringBuilder din = new StringBuilder(text.length());
    for (char c : text.toCharArray()) {
      din.append(
          switch (c) {
            case 'Ä' -> '[';
            case 'Ö' -> '\\';
            case 'Ü' -> ']';
            case 'ä' -> '{';
            case 'ö' -> '|';
            case 'ü' -> '}';
            case 'ß' -> '~';
            case '§' -> '@';
            default -> c;
          });
    }
    return din.toString().getBytes(java.nio.charset.StandardCharsets.US_ASCII);
  }

  static byte[] iccCommand(
      int ins, int slot, int p2, String text, java.time.Duration wait, boolean le) {
    byte[] appl = new Tlv(0x50, display(text)).encode();
    long seconds = (wait.toMillis() + 999) / 1000;
    byte[] wt = new Tlv(0x80, new byte[] {(byte) Math.min(255, Math.max(1, seconds))}).encode();
    java.io.ByteArrayOutputStream apdu = new java.io.ByteArrayOutputStream();
    apdu.writeBytes(
        new byte[] {
          (byte) 0x80, (byte) ins, (byte) slot, (byte) p2, (byte) (appl.length + wt.length)
        });
    apdu.writeBytes(appl);
    apdu.writeBytes(wt);
    if (le) {
      apdu.write(0x00);
    }
    return apdu.toByteArray();
  }

  private byte[] atr(int slot, String command, byte[] response) throws IOException {
    if (response.length >= 2
        && (response[response.length - 2] & 0xFF) == 0x62
        && response[response.length - 1] == 0x00) {
      throw new NoCardException(id, slot);
    }
    int sw1 = response.length >= 2 ? response[response.length - 2] & 0xFF : 0;
    if (sw1 != 0x90 && sw1 != 0x62) {
      throw new IOException(id + "/" + slot + ": " + command + " " + sw(response));
    }
    byte[] body = java.util.Arrays.copyOf(response, response.length - 2);
    return Tlv.find(Tlv.parse(body), 0x5F41).map(Tlv::value).orElse(new byte[0]);
  }

  private byte[] terminalCommand(byte[] apdu) throws IOException {
    return working().transmit(SicctEnvelope.FU_TERMINAL, apdu, timeout);
  }

  /**
   * Command whose response the card terminal may delay for up to {@code wait} while waiting for the
   * user.
   */
  private byte[] terminalCommand(byte[] apdu, java.time.Duration wait) throws IOException {
    return working().transmit(SicctEnvelope.FU_TERMINAL, apdu, wait.plus(timeout));
  }

  private SicctConnection working() throws IOException {
    return connection.get().orElseThrow(this::notConnected);
  }

  private void requireCard(int slot) {
    if (!used.contains(slot)) {
      throw new NoCardException(id, slot);
    }
  }

  private static String sw(byte[] response) {
    return response.length < 2
        ? ""
        : java.util.HexFormat.of()
            .withUpperCase()
            .formatHex(response, response.length - 2, response.length);
  }

  private IOException notConnected() {
    return new IOException(
        id + ": keine Arbeitsverbindung zum eHealth-KT (CT.CONNECTED = Nein, TIP1-A_3266-01)");
  }
}

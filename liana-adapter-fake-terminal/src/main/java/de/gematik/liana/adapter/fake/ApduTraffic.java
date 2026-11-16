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

import de.gematik.liana.kern.trace.Traffic;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Reports card APDUs to {@link Traffic} (LIANA-27): per APDU the command and the response, paired.
 *
 * <p>Rbel knows no bare APDUs, only SICCT. Therefore each APDU is put into a SICCT envelope (10
 * bytes, SICCT 6.1.4.2 according to {@code RbelSicctEnvelopeConverter}): type ({@link #C_COMMAND}
 * or {@link #R_RESPONSE}), slot address, sequence number, RFU, length. This way the trace of the
 * fake CT looks like the SICCT traffic of an eHealth CT.
 */
public final class ApduTraffic {

  static final byte C_COMMAND = 0x6B;
  static final byte R_RESPONSE = (byte) 0x83;

  private final Traffic traffic;
  private final AtomicInteger sequence = new AtomicInteger();

  public ApduTraffic(Traffic traffic) {
    this.traffic = traffic;
  }

  /** Command to the card in {@code terminal}/{@code slot} and its response: two messages. */
  public void apdu(
      String terminal, int slot, byte[] command, Instant sent, byte[] response, Instant received) {
    report(traffic.name(), address(terminal, slot), slot, command, sent, response, received);
  }

  /**
   * Plaintext of an SM APDU that LIANA has terminated (LIANA-28): own sender and receiver ({@code
   * <name>-sm-klartext}, {@code <name>-<KT>-sm-klartext:<Slot>}), so that the Tiger log separates
   * it from the ciphertext.
   */
  public void plaintext(
      String terminal, int slot, byte[] command, Instant sent, byte[] response, Instant received) {
    report(
        traffic.name() + "-sm-klartext",
        address(terminal + "-sm-klartext", slot),
        slot,
        command,
        sent,
        response,
        received);
  }

  private void report(
      String liana,
      String card,
      int slot,
      byte[] command,
      Instant sent,
      byte[] response,
      Instant received) {
    int seq = sequence.getAndIncrement() & 0xFFFF;
    String request =
        traffic.report(envelope(C_COMMAND, slot, seq, command), liana, card, sent, null);
    traffic.report(envelope(R_RESPONSE, slot, seq, response), card, liana, received, request);
  }

  /**
   * Receiver in the format of {@code RbelSocketAddress.fromString}: name of the connector and KT ID
   * as host, slot as port (LIANA-195.04). A fake CT has no wire and no IP; the name keeps the CTs
   * of several connectors in one proxy apart.
   */
  String address(String terminal, int slot) {
    return traffic.name() + "-" + terminal + ":" + slot;
  }

  /**
   * SICCT envelope: type, slot address (2 bytes), sequence number (2 bytes), RFU, length (4 bytes),
   * APDU.
   */
  static byte[] envelope(byte type, int slot, int seq, byte[] apdu) {
    return ByteBuffer.allocate(10 + apdu.length)
        .put(type)
        .putShort((short) slot)
        .putShort((short) seq)
        .put((byte) 0)
        .putInt(apdu.length)
        .put(apdu)
        .array();
  }
}

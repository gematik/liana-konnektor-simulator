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

import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Secure messaging with AES session keys per gemSpec_COS 13.2 (command, view {@code K_externeWelt})
 * and 13.3 (response, view {@code K_COS}), basic channel 0–3: unwrap and rewrap, commands as well
 * as responses. This is how LIANA reads in plain text what a PoPP service sends via the trusted
 * channel (elcSessionkey4SM, gemSpec_COS 15) ({@link TrustedChannelTerminal}).
 *
 * <p>Rewrapping follows the rules of the spec. Apart from the sender's choice whether data goes in
 * plain text (DO81) or encrypted (DO87), the result is unambiguous: IV from SSC, CMAC and case 4
 * encoding are deterministic. With unchanged plain text, exactly the incoming APDU is therefore
 * produced; if it differs, the original was not built according to the spec.
 */
public final class SecureMessaging {

  private static final int BLOCK = 16;
  private static final int MAC_LENGTH = 8;
  private static final byte DO_PLAIN = (byte) 0x81;
  private static final byte DO_ENCRYPTED = (byte) 0x87;
  private static final byte DO_LE = (byte) 0x97;
  private static final byte DO_TRAILER = (byte) 0x99;
  private static final byte DO_MAC = (byte) 0x8E;
  private static final HexFormat HEX = HexFormat.of().withUpperCase();

  private SecureMessaging() {}

  /**
   * Session of a card: {@code K_enc}, {@code K_mac} (16 bytes AES each) and SSCmac before the next
   * command.
   */
  public record Session(byte[] kEnc, byte[] kMac, byte[] ssc) {

    public Session {
      if (kEnc.length != BLOCK || kMac.length != BLOCK || ssc.length != BLOCK) {
        throw new IllegalArgumentException("K_enc, K_mac und SSC müssen je 16 Byte lang sein");
      }
      kEnc = kEnc.clone();
      kMac = kMac.clone();
      ssc = ssc.clone();
    }

    /** {@code K_enc K_mac SSC} in hex, as in the test vectors under {@code support/sm/}. */
    public static Session parse(String line) {
      String[] parts = line.strip().split("\\s+");
      if (parts.length != 3) {
        throw new IllegalArgumentException("erwartet K_enc K_mac SSC: " + line);
      }
      return new Session(HEX.parseHex(parts[0]), HEX.parseHex(parts[1]), HEX.parseHex(parts[2]));
    }

    /**
     * SSCmac for the next command (G2_N032.190), the response to it uses the value after that
     * (G2_N033.690).
     */
    public byte[] commandSsc() {
      return increment(ssc);
    }

    public byte[] responseSsc() {
      return increment(increment(ssc));
    }

    @Override
    public byte[] kEnc() {
      return kEnc.clone();
    }

    @Override
    public byte[] kMac() {
      return kMac.clone();
    }

    @Override
    public byte[] ssc() {
      return ssc.clone();
    }

    @Override
    public String toString() {
      return "Session[SSC " + HEX.formatHex(ssc) + "]";
    }
  }

  /**
   * Unprotected APDU and whether its data was transmitted encrypted (DO87) instead of in plain text
   * (DO81).
   */
  public record Plain(byte[] apdu, boolean encrypted) {

    public Plain {
      apdu = apdu.clone();
    }

    @Override
    public byte[] apdu() {
      return apdu.clone();
    }
  }

  /** The APDU is not a valid SM object for this session: encoding, MAC or padding wrong. */
  public static final class SecureMessagingException extends Exception {

    SecureMessagingException(String message) {
      super(message);
    }
  }

  /**
   * CLA with bits b4 and b3 set on channel 0–3 (G2_N032.500.a), interindustry ({@code 0C}) as well
   * as proprietary ({@code 8C}): command with secure messaging.
   */
  public static boolean isSecured(byte[] command) {
    return command.length >= 4 && (command[0] & 0x60) == 0 && (command[0] & 0x0C) == 0x0C;
  }

  /**
   * Unwraps a protected command APDU: check MAC over SSCmac, head and tmpData (G2_N032.800.b), data
   * from DO81 or DO87 (G2_N032.100, G2_N032.300), Le from DO97 (G2_N032.400), CLA without {@code
   * 0C}.
   */
  public static Plain unwrapCommand(byte[] wire, Session session, byte[] ssc)
      throws SecureMessagingException {
    if (!isSecured(wire)) {
      throw new SecureMessagingException("CLA ohne Secure Messaging");
    }
    Apdu apdu = Apdu.parse(wire);
    byte[] head = Arrays.copyOf(wire, 4);
    Objects objects = Objects.parse(apdu.data(), false);
    checkMac(session, ssc, head, objects);
    byte[] data = objects.data(session, ssc);
    byte[] le = objects.le == null ? null : objects.le.value();
    byte[] plainHead = {(byte) (wire[0] & ~0x0C), wire[1], wire[2], wire[3]};
    return new Plain(
        Apdu.encode(plainHead, data, le, data.length > 255 || le != null && le.length > 1),
        objects.encrypted());
  }

  /** Protects a command APDU per G2_N032.000 to G2_N033.400 (case 4 short or extended). */
  public static byte[] wrapCommand(Plain plain, Session session, byte[] ssc)
      throws SecureMessagingException {
    Apdu apdu = Apdu.parse(plain.apdu());
    byte[] head = {
      (byte) (plain.apdu()[0] | 0x0C), plain.apdu()[1], plain.apdu()[2], plain.apdu()[3]
    };
    ByteArrayOutputStream tmpData = new ByteArrayOutputStream();
    tmpData.writeBytes(protectedData(apdu.data(), plain.encrypted(), session, ssc));
    if (apdu.le() != null) {
      tmpData.writeBytes(tlv(DO_LE, apdu.le()));
    }
    byte[] mac = mac(session.kMac(), ssc, head, tmpData.toByteArray());
    tmpData.writeBytes(tlv(DO_MAC, mac));
    byte[] newD = tmpData.toByteArray();
    boolean extended = apdu.le() != null || newD.length > 255;
    return Apdu.encode(head, newD, extended ? new byte[] {0, 0} : new byte[] {0}, extended);
  }

  /**
   * Unwraps a protected response APDU (inverse of G2_N033.500 to G2_N034.300): MAC over SSCmac,
   * ProtectedData and TDO, data from DO81 or DO87, status word from DO99.
   */
  public static Plain unwrapResponse(byte[] wire, Session session, byte[] ssc)
      throws SecureMessagingException {
    if (wire.length < 2) {
      throw new SecureMessagingException("Antwort ohne Statuswort");
    }
    Objects objects = Objects.parse(Arrays.copyOf(wire, wire.length - 2), true);
    checkMac(session, ssc, new byte[0], objects);
    byte[] data = objects.data(session, ssc);
    byte[] trailer = objects.trailer.value();
    if (trailer.length != 2) {
      throw new SecureMessagingException("DO99 nicht 2 Byte lang");
    }
    byte[] plain = Arrays.copyOf(data, data.length + 2);
    System.arraycopy(trailer, 0, plain, data.length, 2);
    return new Plain(plain, objects.encrypted());
  }

  /**
   * Protects a response APDU per G2_N033.500 to G2_N034.300; the trailer stays the inner status
   * word.
   */
  public static byte[] wrapResponse(Plain plain, Session session, byte[] ssc)
      throws SecureMessagingException {
    byte[] apdu = plain.apdu();
    if (apdu.length < 2) {
      throw new SecureMessagingException("Antwort ohne Statuswort");
    }
    byte[] trailer = Arrays.copyOfRange(apdu, apdu.length - 2, apdu.length);
    ByteArrayOutputStream body = new ByteArrayOutputStream();
    body.writeBytes(
        protectedData(Arrays.copyOf(apdu, apdu.length - 2), plain.encrypted(), session, ssc));
    body.writeBytes(tlv(DO_TRAILER, trailer));
    byte[] mac = mac(session.kMac(), ssc, new byte[0], body.toByteArray());
    body.writeBytes(tlv(DO_MAC, mac));
    body.writeBytes(trailer);
    return body.toByteArray();
  }

  static byte[] increment(byte[] ssc) {
    byte[] next = ssc.clone();
    for (int i = next.length - 1; i >= 0; i--) {
      if (++next[i] != 0) {
        break;
      }
    }
    return next;
  }

  private static void checkMac(Session session, byte[] ssc, byte[] head, Objects objects)
      throws SecureMessagingException {
    byte[] expected = mac(session.kMac(), ssc, head, objects.withoutMac);
    if (!MessageDigest.isEqual(expected, objects.mac.value())) {
      throw new SecureMessagingException("MAC falsch (SSC " + HEX.formatHex(ssc) + ")");
    }
  }

  /**
   * ProtectedData: empty, DO81 with the plain text (G2_N032.100) or DO87 with {@code 01 || C}
   * (G2_N032.300).
   */
  private static byte[] protectedData(byte[] data, boolean encrypted, Session session, byte[] ssc)
      throws SecureMessagingException {
    if (data.length == 0) {
      return data;
    }
    if (!encrypted) {
      return tlv(DO_PLAIN, data);
    }
    byte[] cipher =
        aes(Cipher.ENCRYPT_MODE, "AES/CBC/NoPadding", session.kEnc(), iv(session, ssc), pad(data));
    byte[] value = new byte[cipher.length + 1];
    value[0] = 0x01;
    System.arraycopy(cipher, 0, value, 1, cipher.length);
    return tlv(DO_ENCRYPTED, value);
  }

  /** IVenc = AES_ENC(Kenc, SSCmac), G2_N032.300.a. */
  private static byte[] iv(Session session, byte[] ssc) throws SecureMessagingException {
    return aes(Cipher.ENCRYPT_MODE, "AES/ECB/NoPadding", session.kEnc(), null, ssc);
  }

  /**
   * CalculateCMAC_IsoPadding(Kmac, MACin), the first 8 bytes: MACin = SSCmac || head || tmpData
   * with padded head, unless tmpData is empty (G2_N032.800.b); for responses without head SSCmac ||
   * ProtectedData || TDO (G2_N034.100.b).
   */
  private static byte[] mac(byte[] kMac, byte[] ssc, byte[] head, byte[] data)
      throws SecureMessagingException {
    ByteArrayOutputStream in = new ByteArrayOutputStream();
    in.writeBytes(ssc);
    in.writeBytes(data.length == 0 || head.length == 0 ? head : pad(head));
    in.writeBytes(data);
    return Arrays.copyOf(cmac(kMac, pad(in.toByteArray())), MAC_LENGTH);
  }

  /** AES-CMAC per RFC 4493 (NIST SP 800-38B); here the input is always padded to full blocks. */
  static byte[] cmac(byte[] key, byte[] message) throws SecureMessagingException {
    byte[] k1 = shift(aes(Cipher.ENCRYPT_MODE, "AES/ECB/NoPadding", key, null, new byte[BLOCK]));
    byte[] last;
    int blocks = Math.max(1, (message.length + BLOCK - 1) / BLOCK);
    if (message.length > 0 && message.length % BLOCK == 0) {
      last = xor(Arrays.copyOfRange(message, (blocks - 1) * BLOCK, blocks * BLOCK), k1);
    } else {
      byte[] padded =
          Arrays.copyOf(Arrays.copyOfRange(message, (blocks - 1) * BLOCK, message.length), BLOCK);
      padded[message.length - (blocks - 1) * BLOCK] = (byte) 0x80;
      last = xor(padded, shift(k1));
    }
    byte[] input = Arrays.copyOf(message, blocks * BLOCK);
    System.arraycopy(last, 0, input, (blocks - 1) * BLOCK, BLOCK);
    byte[] cbc = aes(Cipher.ENCRYPT_MODE, "AES/CBC/NoPadding", key, new byte[BLOCK], input);
    return Arrays.copyOfRange(cbc, cbc.length - BLOCK, cbc.length);
  }

  private static byte[] shift(byte[] block) {
    byte[] out = new byte[BLOCK];
    for (int i = 0; i < BLOCK; i++) {
      out[i] = (byte) (block[i] << 1 | (i + 1 < BLOCK ? (block[i + 1] & 0xFF) >>> 7 : 0));
    }
    if ((block[0] & 0x80) != 0) {
      out[BLOCK - 1] ^= (byte) 0x87;
    }
    return out;
  }

  private static byte[] xor(byte[] a, byte[] b) {
    byte[] out = new byte[a.length];
    for (int i = 0; i < a.length; i++) {
      out[i] = (byte) (a[i] ^ b[i]);
    }
    return out;
  }

  /**
   * PaddingIso(x, 16): {@code 80}, then zeros up to the block boundary, always at least one byte.
   */
  static byte[] pad(byte[] data) {
    byte[] out = Arrays.copyOf(data, (data.length / BLOCK + 1) * BLOCK);
    out[data.length] = (byte) 0x80;
    return out;
  }

  private static byte[] unpad(byte[] data) throws SecureMessagingException {
    for (int i = data.length - 1; i >= 0; i--) {
      if (data[i] == (byte) 0x80) {
        return Arrays.copyOf(data, i);
      }
      if (data[i] != 0) {
        break;
      }
    }
    throw new SecureMessagingException("Padding falsch");
  }

  private static byte[] aes(int mode, String transformation, byte[] key, byte[] iv, byte[] input)
      throws SecureMessagingException {
    try {
      Cipher cipher = Cipher.getInstance(transformation);
      SecretKeySpec spec = new SecretKeySpec(key, "AES");
      if (iv == null) {
        cipher.init(mode, spec);
      } else {
        cipher.init(mode, spec, new IvParameterSpec(iv));
      }
      return cipher.doFinal(input);
    } catch (GeneralSecurityException e) {
      throw new SecureMessagingException("AES: " + e.getMessage());
    }
  }

  /** BER-TLV with length in 1, 2 ({@code 81}) or 3 bytes ({@code 82}), G2_N032.100.a. */
  private static byte[] tlv(byte tag, byte[] value) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.write(tag);
    if (value.length < 0x80) {
      out.write(value.length);
    } else if (value.length <= 0xFF) {
      out.write(0x81);
      out.write(value.length);
    } else {
      out.write(0x82);
      out.write(value.length >> 8);
      out.write(value.length);
    }
    out.writeBytes(value);
    return out.toByteArray();
  }

  private record Tlv(byte tag, byte[] value) {}

  /**
   * The SM data objects of a data field, in the order of the spec: DO81/DO87, DO97 or DO99, DO8E.
   */
  private record Objects(Tlv data, Tlv le, Tlv trailer, Tlv mac, byte[] withoutMac) {

    static Objects parse(byte[] field, boolean response) throws SecureMessagingException {
      Tlv data = null;
      Tlv le = null;
      Tlv trailer = null;
      int offset = 0;
      while (offset < field.length) {
        int start = offset;
        byte tag = field[offset++];
        if (offset >= field.length) {
          throw new SecureMessagingException("TLV abgeschnitten");
        }
        int length = field[offset++] & 0xFF;
        if (length == 0x81 || length == 0x82) {
          int bytes = length & 0x0F;
          if (offset + bytes > field.length) {
            throw new SecureMessagingException("TLV-Länge abgeschnitten");
          }
          length = 0;
          for (int i = 0; i < bytes; i++) {
            length = length << 8 | field[offset++] & 0xFF;
          }
        } else if (length > 0x7F) {
          throw new SecureMessagingException("TLV-Länge ungültig");
        }
        if (offset + length > field.length) {
          throw new SecureMessagingException("TLV abgeschnitten");
        }
        Tlv tlv = new Tlv(tag, Arrays.copyOfRange(field, offset, offset + length));
        offset += length;
        if (tag == DO_MAC) {
          if (offset != field.length || length != MAC_LENGTH) {
            throw new SecureMessagingException("DO8E nicht am Ende oder nicht 8 Byte lang");
          }
          if (response && trailer == null) {
            throw new SecureMessagingException("Antwort ohne DO99");
          }
          return new Objects(data, le, trailer, tlv, Arrays.copyOf(field, start));
        }
        if ((tag == DO_PLAIN || tag == DO_ENCRYPTED)
            && data == null
            && le == null
            && trailer == null) {
          data = tlv;
        } else if (!response && tag == DO_LE && le == null) {
          le = tlv;
        } else if (response && tag == DO_TRAILER && trailer == null) {
          trailer = tlv;
        } else {
          throw new SecureMessagingException(String.format("unerwartetes Datenobjekt %02X", tag));
        }
      }
      throw new SecureMessagingException("DO8E fehlt");
    }

    boolean encrypted() {
      return data != null && data.tag() == DO_ENCRYPTED;
    }

    byte[] data(Session session, byte[] ssc) throws SecureMessagingException {
      if (data == null) {
        return new byte[0];
      }
      if (data.tag() == DO_PLAIN) {
        return data.value();
      }
      byte[] value = data.value();
      if (value.length < 1 + BLOCK || value[0] != 0x01 || (value.length - 1) % BLOCK != 0) {
        throw new SecureMessagingException("DO87 ohne Padding-Indikator 01 oder nicht blockweise");
      }
      return unpad(
          aes(
              Cipher.DECRYPT_MODE,
              "AES/CBC/NoPadding",
              session.kEnc(),
              iv(session, ssc),
              Arrays.copyOfRange(value, 1, value.length)));
    }
  }

  /**
   * Command APDU per ISO/IEC 7816-4 (gemSpec_COS 11.5): header, data, Ne field without leading zero
   * byte.
   */
  private record Apdu(byte[] data, byte[] le) {

    static Apdu parse(byte[] apdu) throws SecureMessagingException {
      int length = apdu.length;
      if (length < 4) {
        throw new SecureMessagingException("APDU kürzer als der Header");
      }
      if (length == 4) {
        return new Apdu(new byte[0], null);
      }
      if (length == 5) {
        return new Apdu(new byte[0], new byte[] {apdu[4]});
      }
      if (apdu[4] != 0) {
        int lc = apdu[4] & 0xFF;
        if (length == 5 + lc) {
          return new Apdu(Arrays.copyOfRange(apdu, 5, 5 + lc), null);
        }
        if (length == 6 + lc) {
          return new Apdu(Arrays.copyOfRange(apdu, 5, 5 + lc), new byte[] {apdu[5 + lc]});
        }
        throw new SecureMessagingException("Lc passt nicht zur Länge der APDU");
      }
      if (length == 7) {
        return new Apdu(new byte[0], Arrays.copyOfRange(apdu, 5, 7));
      }
      int lc = (apdu[5] & 0xFF) << 8 | apdu[6] & 0xFF;
      if (lc > 0 && length == 7 + lc) {
        return new Apdu(Arrays.copyOfRange(apdu, 7, 7 + lc), null);
      }
      if (lc > 0 && length == 9 + lc) {
        return new Apdu(
            Arrays.copyOfRange(apdu, 7, 7 + lc), Arrays.copyOfRange(apdu, 7 + lc, 9 + lc));
      }
      throw new SecureMessagingException("Lc passt nicht zur Länge der APDU");
    }

    static byte[] encode(byte[] head, byte[] data, byte[] le, boolean extended) {
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      out.writeBytes(head);
      if (data.length > 0) {
        if (extended) {
          out.write(0);
          out.write(data.length >> 8);
        }
        out.write(data.length);
        out.writeBytes(data);
      }
      if (le != null) {
        if (extended && data.length == 0) {
          out.write(0);
        }
        out.writeBytes(le);
      }
      return out.toByteArray();
    }
  }
}

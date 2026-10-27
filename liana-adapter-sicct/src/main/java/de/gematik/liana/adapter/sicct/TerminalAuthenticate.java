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

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * EHEALTH TERMINAL AUTHENTICATE (gemSpec_KT 3.7.2, CMD_KT_0001: {@code CLA 81 INS AA P1 00}), the
 * Konnektor side of pairing: CREATE ({@code P2=01}, SEQ_KT_0001-01) with shared secret DO ({@code
 * D4}, 16 bytes, DO_KT_0003) and display message in the APPL DO ({@code 50}, SICCT §5.5.10.19);
 * VALIDATE ({@code P2=02}, SEQ_KT_0002) with shared secret challenge DO ({@code D5}, 16–127 bytes,
 * DO_KT_0004), response {@code SHA-256(Challenge ‖ Shared Secret)}.
 */
public final class TerminalAuthenticate {

  /** DO_KT_0003: the shared secret has exactly 16 bytes. */
  public static final int SHARED_SECRET_LENGTH = 16;

  /** TUC_KON_050 step 6a: challenge with at least 16 bytes. */
  static final int CHALLENGE_LENGTH = 16;

  private static final int SS_DO = 0xD4;
  private static final int SSC_DO = 0xD5;
  private static final int APPL_DO = 0x50;

  private TerminalAuthenticate() {}

  /**
   * New shared secret ShS.KT.AUT (TUC_KON_053 step 4a, gemSpec_Krypt 2.2: random from the DRBG).
   */
  public static byte[] newSharedSecret() {
    byte[] secret = new byte[SHARED_SECRET_LENGTH];
    // No static SecureRandom: the native image rejects a seed in the image heap (LIANA-81)
    new SecureRandom().nextBytes(secret);
    return secret;
  }

  /** Challenge for VALIDATE (TUC_KON_050 step 6a). */
  static byte[] newChallenge() {
    byte[] challenge = new byte[CHALLENGE_LENGTH];
    new SecureRandom().nextBytes(challenge);
    return challenge;
  }

  /**
   * Display message of the CREATE variant (TUC_KON_053 step 5): {@code KT:<MAC> MIT KON:<Hostname>
   * PAIREN OK?}, MAC as {@code AABBCC:DDEEFF}.
   */
  public static String displayMessage(String mac, String konnektorHostname) {
    String hex = mac.replace(":", "").replace("-", "").toUpperCase(java.util.Locale.ROOT);
    return "KT:"
        + hex.substring(0, 6)
        + ":"
        + hex.substring(6)
        + " MIT KON:"
        + konnektorHostname
        + " PAIREN OK?";
  }

  /**
   * CREATE with {@code sharedSecret} and {@code display}; Le {@code 00} (the signature,
   * SEQ_KT_0001-01 step 8).
   */
  static byte[] create(byte[] sharedSecret, String display) {
    if (sharedSecret.length != SHARED_SECRET_LENGTH) {
      throw new IllegalArgumentException(
          "Shared Secret mit " + sharedSecret.length + " statt 16 Byte");
    }
    byte[] text = display.getBytes(StandardCharsets.US_ASCII);
    if (text.length > 0x7F) {
      throw new IllegalArgumentException("Display-Nachricht länger als 127 Zeichen");
    }
    return command(
        0x01, concat(new Tlv(SS_DO, sharedSecret).encode(), new Tlv(APPL_DO, text).encode()), 0x00);
  }

  /** VALIDATE with {@code challenge}; Le {@code 20} (the SHA-256 value). */
  static byte[] validate(byte[] challenge) {
    if (challenge.length < 16 || challenge.length > 0x7F) {
      throw new IllegalArgumentException(
          "Challenge mit " + challenge.length + " statt 16..127 Byte");
    }
    return command(0x02, new Tlv(SSC_DO, challenge).encode(), 0x20);
  }

  /**
   * What the terminal must answer to VALIDATE: SHA-256 over challenge and appended shared secret
   * (SEQ_KT_0002).
   */
  static byte[] expectedValidation(byte[] challenge, byte[] sharedSecret) {
    try {
      MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
      sha256.update(challenge);
      sha256.update(sharedSecret);
      return sha256.digest();
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 fehlt", e);
    }
  }

  /** abCmd of a response without status word; {@code null} if the status word is not 9000. */
  static byte[] body(byte[] response) {
    return InitCtSession.ok(response) ? Arrays.copyOf(response, response.length - 2) : null;
  }

  private static byte[] command(int p2, byte[] data, int le) {
    ByteArrayOutputStream apdu = new ByteArrayOutputStream();
    apdu.writeBytes(new byte[] {(byte) 0x81, (byte) 0xAA, 0x00, (byte) p2, (byte) data.length});
    apdu.writeBytes(data);
    apdu.write(le);
    return apdu.toByteArray();
  }

  private static byte[] concat(byte[] a, byte[] b) {
    byte[] all = Arrays.copyOf(a, a.length + b.length);
    System.arraycopy(b, 0, all, a.length, b.length);
    return all;
  }
}

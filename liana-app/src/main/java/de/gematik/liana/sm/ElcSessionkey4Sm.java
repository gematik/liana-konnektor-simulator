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

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Key agreement elcSessionkey4SM on brainpoolP256r1 (gemSpec_COS 15.4, (N085.052), (N085.054)), for
 * both roles: LIANA as card towards the PoPP service (hop A) and as terminal towards the card (hop
 * B).
 *
 * <p>From the card's view K1 = ECKA(PrK.d, ephemeralPK_oponent), K2 = ECKA(ephemeralSK_self,
 * PuK_oponent), KD = K1 || K2 (G2_N085.054.c, KD.e = 0); the terminal computes the same values with
 * swapped roles. Kenc and Kmac are derived by {@code KeyDerivation_AES128} (A_13599: SHA-1 over KD
 * || counter, the first 16 bytes), SSCmac starts at 0.
 */
public final class ElcSessionkey4Sm {

  private static final X9ECParameters CURVE = TeleTrusTNamedCurves.getByName("brainpoolP256r1");
  private static final int SIZE = 32;

  private ElcSessionkey4Sm() {}

  /** A key pair on brainpoolP256r1: private scalar and uncompressed point. */
  public record KeyPair(BigInteger d, byte[] point) {

    public KeyPair {
      point = point.clone();
    }

    /** The pair for the private scalar {@code d} (big endian). */
    public static KeyPair of(byte[] d) {
      BigInteger scalar = new BigInteger(1, d);
      return new KeyPair(scalar, encode(CURVE.getG().multiply(scalar)));
    }

    @Override
    public byte[] point() {
      return point.clone();
    }

    @Override
    public String toString() {
      return "KeyPair[brainpoolP256r1]";
    }
  }

  /** Ephemeral key pair for a step 1 ((N085.052)f). */
  public static KeyPair ephemeral() {
    BigInteger n = CURVE.getN();
    // No static SecureRandom: the native image rejects a seed in the image heap (LIANA-81)
    SecureRandom random = new SecureRandom();
    BigInteger d;
    do {
      d = new BigInteger(n.bitLength(), random);
    } while (d.signum() == 0 || d.compareTo(n) >= 0);
    return new KeyPair(d, encode(CURVE.getG().multiply(d)));
  }

  /** LIANA as card (hop A): own static and ephemeral key, the terminal's public ones. */
  public static SecureMessaging.Session asCard(
      KeyPair cardStatic, KeyPair cardEphemeral, byte[] terminalStatic, byte[] terminalEphemeral) {
    return session(
        ecka(cardStatic.d(), terminalEphemeral), ecka(cardEphemeral.d(), terminalStatic));
  }

  /** LIANA as terminal (hop B): own static and ephemeral key, the card's public ones. */
  public static SecureMessaging.Session asTerminal(
      KeyPair terminalStatic, KeyPair terminalEphemeral, byte[] cardStatic, byte[] cardEphemeral) {
    return session(
        ecka(terminalEphemeral.d(), cardStatic), ecka(terminalStatic.d(), cardEphemeral));
  }

  /** ECKAvalue per BSI TR-03111: x coordinate of d·P, 32 bytes. */
  static byte[] ecka(BigInteger d, byte[] point) {
    ECPoint other = CURVE.getCurve().decodePoint(point);
    if (!other.isValid()) {
      throw new IllegalArgumentException("Punkt liegt nicht auf brainpoolP256r1");
    }
    return fixed(other.multiply(d).normalize().getAffineXCoord().toBigInteger());
  }

  private static SecureMessaging.Session session(byte[] k1, byte[] k2) {
    byte[] kd = Arrays.copyOf(k1, k1.length + k2.length);
    System.arraycopy(k2, 0, kd, k1.length, k2.length);
    return new SecureMessaging.Session(kdf(kd, 1), kdf(kd, 2), new byte[16]);
  }

  @SuppressWarnings("java:S4790") // KDF with SHA-1 as specified for the session keys (gemSpec_COS)
  private static byte[] kdf(byte[] kd, int counter) {
    try {
      MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
      sha1.update(kd);
      sha1.update(new byte[] {0, 0, 0, (byte) counter});
      return Arrays.copyOf(sha1.digest(), 16);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  private static byte[] encode(ECPoint point) {
    return point.normalize().getEncoded(false);
  }

  private static byte[] fixed(BigInteger value) {
    byte[] raw = value.toByteArray();
    byte[] out = new byte[SIZE];
    int copy = Math.min(SIZE, raw.length);
    System.arraycopy(raw, raw.length - copy, out, SIZE - copy, copy);
    return out;
  }
}

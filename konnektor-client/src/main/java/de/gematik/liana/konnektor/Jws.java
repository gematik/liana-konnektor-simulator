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
package de.gematik.liana.konnektor;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

/**
 * JWS in compact serialization (RFC 7515), signed via ExternalAuthenticate with the card's C.AUT
 * (LIANA-135): {@code alg} {@code BP256R1} for brainpoolP256r1 (G2.1 cards), {@code ES256} for
 * P-256, {@code x5c} with the C.AUT. The Konnektor's ECDSA signature (DER) is converted to {@code r
 * || s} (RFC 7518 3.4).
 */
public final class Jws {

  private static final ASN1ObjectIdentifier BRAINPOOL_P256 =
      new ASN1ObjectIdentifier("1.3.36.3.3.2.8.1.1.7");
  private static final ASN1ObjectIdentifier P256 = new ASN1ObjectIdentifier("1.2.840.10045.3.1.7");

  private final Konnektor kon;
  private final CardScope card;
  private final Map<String, Object> claims;
  private final Map<String, Object> header = new LinkedHashMap<>();

  Jws(Konnektor kon, CardScope card, Map<String, Object> claims) {
    this.kon = kon;
    this.card = card;
    this.claims = new LinkedHashMap<>(claims);
  }

  /** Additional header fields, such as {@code typ}; the client sets {@code alg} and {@code x5c}. */
  public Jws header(String name, Object value) {
    header.put(name, value);
    return this;
  }

  /** Reads the C.AUT (ECC), signs and returns {@code header.payload.signature}. */
  public String sign() {
    X509Certificate certificate = card.certificate("C.AUT").ecc().read();
    Map<String, Object> protectedHeader = new LinkedHashMap<>();
    protectedHeader.put("alg", alg(certificate));
    protectedHeader.putAll(header);
    try {
      protectedHeader.put(
          "x5c", List.of(Base64.getEncoder().encodeToString(certificate.getEncoded())));
    } catch (CertificateEncodingException e) {
      throw new KonnektorException("C.AUT nicht kodierbar", e);
    }
    String input = base64Url(Json.write(protectedHeader)) + "." + base64Url(Json.write(claims));
    byte[] der = card.authenticate(sha256(input)).ecdsa();
    return input + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(concat(der, 32));
  }

  static String alg(X509Certificate certificate) {
    SubjectPublicKeyInfo info =
        SubjectPublicKeyInfo.getInstance(certificate.getPublicKey().getEncoded());
    Object curve = info.getAlgorithm().getParameters();
    if (BRAINPOOL_P256.equals(curve)) {
      return "BP256R1";
    }
    if (P256.equals(curve)) {
      return "ES256";
    }
    throw new KonnektorException(
        "C.AUT: Kurve " + curve + " nicht für JWS unterstützt (BP256R1, ES256)");
  }

  /** ECDSA-Sig-Value (DER) → r || s with {@code size} bytes each. */
  static byte[] concat(byte[] der, int size) {
    ASN1Sequence sequence = ASN1Sequence.getInstance(der);
    byte[] out = new byte[2 * size];
    copy(ASN1Integer.getInstance(sequence.getObjectAt(0)).getPositiveValue(), out, 0, size);
    copy(ASN1Integer.getInstance(sequence.getObjectAt(1)).getPositiveValue(), out, size, size);
    return out;
  }

  private static void copy(BigInteger value, byte[] out, int offset, int size) {
    byte[] bytes = value.toByteArray();
    if (bytes.length > size) {
      bytes = Arrays.copyOfRange(bytes, bytes.length - size, bytes.length);
    }
    System.arraycopy(bytes, 0, out, offset + size - bytes.length, bytes.length);
  }

  private static String base64Url(String json) {
    return Base64.getUrlEncoder()
        .withoutPadding()
        .encodeToString(json.getBytes(StandardCharsets.UTF_8));
  }

  private static byte[] sha256(String input) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(input.getBytes(StandardCharsets.US_ASCII));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }
}

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
package de.gematik.liana.crypto;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * Compact JWS with ES256 (ECDSA P-256/SHA-256, signature as R||S per RFC 7518 §3.4) and x5c chain
 * (RFC 7515 §4.1.6), as used by the PoPP service for signed scenarios and tokens ({@code
 * support/api-popp}).
 *
 * <p>The chain check covers signatures and validity periods up to the given trust anchor.
 * Revocation status (OCSP, {@code stpl}) and TSL connection are not part of it.
 */
public final class EcJws {

  private static final String ALG = "ES256";
  private static final String JCA_ALG = "SHA256withPLAIN-ECDSA";

  /** Group order of P-256; distinguishes the curve from brainpoolP256r1 of the same field size. */
  private static final BigInteger P256_ORDER =
      new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);

  private static final ObjectMapper JSON = new ObjectMapper();
  private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
  private static final Base64.Decoder B64URL_DEC = Base64.getUrlDecoder();

  private EcJws() {}

  /** Signs {@code payload}; {@code x5c} starts with the certificate for {@code key}. */
  public static String sign(byte[] payload, PrivateKey key, List<X509Certificate> x5c)
      throws GeneralSecurityException {
    return sign(payload, key, x5c, Map.of());
  }

  /**
   * Like {@link #sign(byte[], PrivateKey, List)}, {@code headers} add or replace {@code typ} and
   * others.
   */
  public static String sign(
      byte[] payload, PrivateKey key, List<X509Certificate> x5c, Map<String, String> headers)
      throws GeneralSecurityException {
    ObjectNode header = JSON.createObjectNode().put("typ", "JWT").put("alg", ALG);
    headers.forEach(header::put);
    var chain = header.putArray("x5c");
    for (X509Certificate cert : x5c) {
      chain.add(Base64.getEncoder().encodeToString(cert.getEncoded()));
    }
    String signingInput =
        B64URL.encodeToString(toBytes(header)) + "." + B64URL.encodeToString(payload);
    Signature signature = Signature.getInstance(JCA_ALG, CryptoProviders.BC);
    signature.initSign(key);
    signature.update(signingInput.getBytes(StandardCharsets.US_ASCII));
    return signingInput + "." + B64URL.encodeToString(signature.sign());
  }

  /**
   * Verifies signature and x5c chain against {@code trustAnchor} and returns the payload.
   *
   * @throws GeneralSecurityException if format, algorithm, chain or signature are wrong
   */
  public static byte[] verify(String compact, X509Certificate trustAnchor)
      throws GeneralSecurityException {
    return verify(compact, chain -> verifyChain(chain, trustAnchor)).payload();
  }

  /**
   * Header, payload and signer certificate {@code x5c[0]} of a JWS whose signature is
   * mathematically valid.
   */
  public record Verified(JsonNode header, byte[] payload, X509Certificate signer) {}

  /**
   * Verifies only the signature with the key from {@code x5c[0]}. The caller checks the signer
   * certificate itself (SecureSendAPDU: TUC_KON_037).
   */
  public static Verified verifySignature(String compact) throws GeneralSecurityException {
    return verify(compact, chain -> {});
  }

  private interface ChainCheck {
    void check(List<X509Certificate> chain) throws GeneralSecurityException;
  }

  private static Verified verify(String compact, ChainCheck chainCheck)
      throws GeneralSecurityException {
    String[] parts = compact.split("\\.", -1);
    if (parts.length != 3) {
      throw new SignatureException("JWS hat " + parts.length + " statt 3 Teile");
    }
    JsonNode header = parseHeader(parts[0]);
    if (!ALG.equals(header.path("alg").asText())) {
      throw new SignatureException("alg " + header.path("alg") + " statt " + ALG);
    }
    List<X509Certificate> chain = parseX5c(header.path("x5c"));
    chainCheck.check(chain);

    X509Certificate signer = chain.getFirst();
    if (!(signer.getPublicKey() instanceof ECPublicKey ecKey)
        || !P256_ORDER.equals(ecKey.getParams().getOrder())) {
      throw new SignatureException("ES256 verlangt einen P-256-Schlüssel im Signerzertifikat");
    }
    Signature signature = Signature.getInstance(JCA_ALG, CryptoProviders.BC);
    signature.initVerify(signer.getPublicKey());
    signature.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
    if (!signature.verify(decode(parts[2]))) {
      throw new SignatureException("JWS-Signatur ungültig");
    }
    return new Verified(header, decode(parts[1]), signer);
  }

  private static void verifyChain(List<X509Certificate> chain, X509Certificate trustAnchor)
      throws GeneralSecurityException {
    for (int i = 0; i < chain.size(); i++) {
      X509Certificate cert = chain.get(i);
      X509Certificate issuer = i + 1 < chain.size() ? chain.get(i + 1) : trustAnchor;
      cert.checkValidity();
      if (!cert.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
        throw new SignatureException(
            "x5c["
                + i
                + "]: Aussteller "
                + cert.getIssuerX500Principal()
                + " passt nicht zu "
                + issuer.getSubjectX500Principal());
      }
      if (i > 0 && cert.getBasicConstraints() < 0) {
        throw new SignatureException("x5c[" + i + "] ist kein CA-Zertifikat");
      }
      cert.verify(issuer.getPublicKey(), CryptoProviders.BC);
    }
    trustAnchor.checkValidity();
  }

  private static JsonNode parseHeader(String encoded) throws SignatureException {
    try {
      return JSON.readTree(decode(encoded));
    } catch (IOException e) {
      throw new SignatureException("JWS-Header ist kein JSON", e);
    }
  }

  private static List<X509Certificate> parseX5c(JsonNode x5c) throws GeneralSecurityException {
    if (!x5c.isArray() || x5c.isEmpty()) {
      throw new SignatureException("x5c fehlt oder ist leer");
    }
    CertificateFactory factory = CertificateFactory.getInstance("X.509", CryptoProviders.BC);
    List<X509Certificate> chain = new ArrayList<>();
    for (JsonNode entry : x5c) {
      byte[] der = Base64.getDecoder().decode(entry.asText());
      chain.add((X509Certificate) factory.generateCertificate(new ByteArrayInputStream(der)));
    }
    return chain;
  }

  private static byte[] toBytes(ObjectNode node) throws SignatureException {
    try {
      return JSON.writeValueAsBytes(node);
    } catch (IOException e) {
      throw new SignatureException("JWS-Header nicht serialisierbar", e);
    }
  }

  private static byte[] decode(String part) throws SignatureException {
    try {
      return B64URL_DEC.decode(part);
    } catch (IllegalArgumentException e) {
      throw new SignatureException("kein Base64url", e);
    }
  }
}

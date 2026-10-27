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
package de.gematik.liana.trace;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Re-signs a JWS (ES256) from the trace after its payload received replacements: the trace's header
 * with the test signer from {@code support/pki/replay/} as x5c, the remaining fields ({@code typ},
 * {@code stpl}) stay, signature as R||S. LIANA verifies the signature against x5c[0]
 * (SecureSendAPDU, TAB_KON_271 step 2), the trace original would be invalid; LIANA accepts the
 * signer via the imported replay CA ({@link PoppKonTuGegenLiana}).
 */
final class JwsResigner {

  private static final Path DIR = Path.of("support/pki/replay");
  private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
  private static final Pattern X5C = Pattern.compile("\"x5c\"\\s*:\\s*\\[[^\\]]*\\]");

  private JwsResigner() {}

  /** {@code traceHeader}: the header of the trace JWS, base64url. */
  static String sign(String traceHeader, String payload) {
    var original =
        X5C.matcher(new String(Base64.getUrlDecoder().decode(traceHeader), StandardCharsets.UTF_8));
    if (!original.find()) {
      throw new IllegalStateException("JWS-Header des Traces ohne x5c");
    }
    String header =
        original.replaceFirst(
            Matcher.quoteReplacement(
                "\"x5c\":[\""
                    + Base64.getEncoder().encodeToString(pem("popp-signer.pem"))
                    + "\"]"));
    String input =
        B64URL.encodeToString(header.getBytes(StandardCharsets.UTF_8))
            + "."
            + B64URL.encodeToString(payload.getBytes(StandardCharsets.UTF_8));
    try {
      PrivateKey key =
          KeyFactory.getInstance("EC")
              .generatePrivate(new PKCS8EncodedKeySpec(pem("popp-signer.key.pem")));
      Signature signature = Signature.getInstance("SHA256withECDSAinP1363Format");
      signature.initSign(key);
      signature.update(input.getBytes(StandardCharsets.US_ASCII));
      return input + "." + B64URL.encodeToString(signature.sign());
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("Test-Signer aus " + DIR + " unbrauchbar", e);
    }
  }

  private static byte[] pem(String file) {
    try {
      return Base64.getDecoder()
          .decode(Files.readString(DIR.resolve(file)).replaceAll("-----[A-Z ]+-----|\\s", ""));
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }
}

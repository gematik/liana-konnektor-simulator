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

import java.security.Provider;
import java.security.Security;
import java.util.Objects;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

/**
 * JCA providers for TI cryptography. Brainpool in ECDSA and TLS 1.2 is only available via
 * BouncyCastle, never via the JDK defaults.
 */
public final class CryptoProviders {

  /** Registered by Quarkus via {@code quarkus.security.security-providers=BC,BCJSSE}. */
  public static final String BC = "BC";

  private static volatile Provider tls;

  /** BC property: Miller-Rabin rounds of the check that an RSA modulus is composite. */
  static final String RSA_MR_TESTS = "org.bouncycastle.rsa.max_mr_tests";

  private CryptoProviders() {}

  /**
   * Before startup (LIANA-178): BC checks every RSA key it parses with Miller-Rabin to ensure that
   * the modulus is not prime. The native image lacks the JIT intrinsics for BigInteger, there the
   * check costs about 9 ms per key; the 383 CAs of the BNetzA-VL and the 123 of the TSL made
   * startup 3.5 s slower. LIANA disables it: a plausibility check of no value for a simulator whose
   * trust anchors come from baked-in lists. An explicitly set value ({@code
   * -Dorg.bouncycastle.rsa.max_mr_tests=…}) is kept.
   */
  public static void configure() {
    if (System.getProperty(RSA_MR_TESTS) == null) {
      System.setProperty(RSA_MR_TESTS, "0");
    }
  }

  /**
   * BCJSSE whose TLS crypto is bound to BC. The globally registered BCJSSE obtains ECDH and EC
   * parameters via the JCA order, ends up at SunEC and silently disables brainpoolP256r1 ("contains
   * disabled NamedGroup"). TLS contexts in LIANA therefore always come from here.
   */
  public static Provider tls() {
    Provider provider = tls;
    if (provider == null) {
      synchronized (CryptoProviders.class) {
        provider = tls;
        if (provider == null) {
          provider =
              new BouncyCastleJsseProvider(
                  Objects.requireNonNull(
                      Security.getProvider(BC),
                      "Provider BC nicht registriert (quarkus.security.security-providers)"));
          tls = provider;
        }
      }
    }
    return provider;
  }
}

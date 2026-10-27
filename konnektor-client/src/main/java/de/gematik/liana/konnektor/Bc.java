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

import java.security.Provider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

/**
 * The client's own, unregistered BouncyCastle instances (LIANA-133): the client does not change the
 * security providers of the Primärsystem. BCJSSE is bound to this BC instance; otherwise it obtains
 * ECDH and EC parameters via the JCA provider order, ends up at SunEC and loses brainpoolP256r1
 * (like LIANA's {@code CryptoProviders.tls()}).
 */
final class Bc {

  static final Provider PROVIDER = new BouncyCastleProvider();
  static final Provider JSSE = new BouncyCastleJsseProvider(PROVIDER);

  private Bc() {}
}

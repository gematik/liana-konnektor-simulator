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
package de.gematik.liana.konnektor.examples;

import de.gematik.liana.konnektor.*;
import java.nio.file.Path;

/**
 * Decrypt a CMS document with the SMC-B (DecryptDocument). Usage: {@code java ... Decrypt
 * praxis.kon}.
 */
public final class Decrypt {

  private Decrypt() {}

  public static void main(String[] args) throws Exception {
    try (Konnektor kon = Konnektor.fromKon(Path.of(args[0]))) {
      System.out.println(run(kon));
    }
  }

  /** Decrypt a CMS document with the SMC-B (DecryptDocument). */
  public static Object run(Konnektor kon) throws Exception {
    Card smcb = kon.cards().ofType("SM-B").get(0);
    byte[] encrypted =
        kon.encrypt(Document.of("Befund".getBytes(), "text/plain")).toCard(smcb.handle());
    return new String(kon.card(smcb).decrypt(encrypted));
  }
}

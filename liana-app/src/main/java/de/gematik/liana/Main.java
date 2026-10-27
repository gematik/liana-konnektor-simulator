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
package de.gematik.liana;

import de.gematik.liana.crypto.CryptoProviders;
import io.quarkus.runtime.Quarkus;
import io.quarkus.runtime.annotations.QuarkusMain;

/**
 * Starts LIANA. With the argument {@code health [port]} it does not start but, as the image health
 * check, checks the readiness of a running instance ({@link HealthProbe}, LIANA-107).
 */
@QuarkusMain
public final class Main {

  private Main() {}

  public static void main(String... args) {
    if (args.length > 0 && "health".equals(args[0])) {
      System.exit(HealthProbe.run(args));
    }
    CryptoProviders.configure();
    Quarkus.run(args);
  }
}

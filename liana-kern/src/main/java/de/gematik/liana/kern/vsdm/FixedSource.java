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
package de.gematik.liana.kern.vsdm;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Optional;

/**
 * Stage {@value #CONFIG_NAME} of the Onlineprüfung (LIANA-141): „keine Aktualisierung erforderlich“
 * (result 2) without any Fachdienst. A deliberate deviation from the spec that no real connector
 * makes; with {@code liana.strict} it drops out of the chain. The Prüfziffer has the format of the
 * Testhub mock ({@code ChecksumService} of the vsdm-server-simservice): the first 48 bytes of
 * SHA-512 over the KVNR, without key. The mock transmits it Base64url-encoded; in the
 * Prüfungsnachweis it is xs:base64Binary; the bytes are the same.
 */
public final class FixedSource implements OnlineCheck.Source {

  public static final String CONFIG_NAME = "fixed";
  private static final int LENGTH = 48;

  @Override
  public String name() {
    return CONFIG_NAME;
  }

  @Override
  public boolean deviatesFromSpec() {
    return true;
  }

  @Override
  public Optional<OnlineCheck.Answer> ask(OnlineCheck.Request request, OnlineCheck.Notes notes) {
    if (request.kvnr() == null) {
      notes.add(CONFIG_NAME, "KVNR der eGK nicht lesbar (C.CH.AUT)");
      return Optional.empty();
    }
    return Optional.of(new OnlineCheck.NoUpdate(pruefziffer(request.kvnr())));
  }

  /** The Testhub mock's Prüfziffer for {@code kvnr}. */
  static byte[] pruefziffer(String kvnr) {
    try {
      byte[] digest =
          MessageDigest.getInstance("SHA-512").digest(kvnr.getBytes(StandardCharsets.UTF_8));
      return Arrays.copyOf(digest, LENGTH);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }
}

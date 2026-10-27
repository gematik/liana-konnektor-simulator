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

import java.util.Arrays;
import java.util.Objects;

/**
 * Authentication to the Konnektor ({@code .kon} §6). {@code toString} never shows the password or
 * key material.
 */
public sealed interface Credentials {

  /** No authentication (ANCL_CAUT_MANDATORY off). */
  static Credentials none() {
    return None.INSTANCE;
  }

  /** HTTP Basic (ANCL_CAUT_MODE PASSWORD). */
  static Credentials basic(String username, String password) {
    return new Basic(username, password);
  }

  /** TLS client certificate from a PKCS#12 container (ANCL_CAUT_MODE CERTIFICATE). */
  static Credentials pkcs12(byte[] data, char[] password) {
    return new Pkcs12(data, password);
  }

  enum None implements Credentials {
    INSTANCE
  }

  record Basic(String username, String password) implements Credentials {
    public Basic {
      Objects.requireNonNull(username, "username");
      Objects.requireNonNull(password, "password");
    }

    @Override
    @SuppressWarnings("java:S2068") // masks the password, contains none
    public String toString() {
      return "Basic[username=" + username + ", password=***]";
    }
  }

  record Pkcs12(byte[] data, char[] password) implements Credentials {
    public Pkcs12 {
      data = Objects.requireNonNull(data, "data").clone();
      password = password == null ? new char[0] : password.clone();
    }

    @Override
    public byte[] data() {
      return data.clone();
    }

    @Override
    public char[] password() {
      return password.clone();
    }

    @Override
    public boolean equals(Object o) {
      return o instanceof Pkcs12 other
          && Arrays.equals(data, other.data)
          && Arrays.equals(password, other.password);
    }

    @Override
    public int hashCode() {
      return Arrays.hashCode(data);
    }

    @Override
    @SuppressWarnings("java:S2068") // masks the password, contains none
    public String toString() {
      return "Pkcs12[data=" + data.length + " Byte, password=***]";
    }
  }

  /**
   * Entry in the operating system's credential store ({@code .kon} §6.3); not yet resolved by the
   * client.
   */
  record SystemStore(String name) implements Credentials {
    public SystemStore {
      Objects.requireNonNull(name, "name");
    }
  }
}

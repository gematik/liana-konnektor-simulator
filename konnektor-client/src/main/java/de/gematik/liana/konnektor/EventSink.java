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

import java.util.Objects;

/**
 * Ereignissenke of the client (LIANA-137): the address at which the Konnektor reaches the client
 * ({@code EventTo cetp://host:port}), and whether the sink speaks TLS. CETP over TLS (CETP1,
 * TIP1-A_4595) needs a server identity as PKCS#12; without TLS (CETP2) only if ANCL_TLS_MANDATORY
 * is off (TAB_KON_852, the default in LIANA).
 *
 * @param host name or address that the Konnektor can reach (in Docker e.g. {@code
 *     host.docker.internal})
 * @param port port, {@code 0}: chosen freely
 * @param tls server identity for TLS, {@code null}: without TLS
 */
public record EventSink(String host, int port, Credentials.Pkcs12 tls) {

  public EventSink {
    Objects.requireNonNull(host, "host");
  }

  /** Without TLS (CETP2). */
  public static EventSink plain(String host, int port) {
    return new EventSink(host, port, null);
  }

  /** With TLS (CETP1) and this server identity. */
  public static EventSink tls(String host, int port, byte[] pkcs12, char[] password) {
    return new EventSink(host, port, new Credentials.Pkcs12(pkcs12, password));
  }
}

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
package de.gematik.liana.kern.trace;

import java.net.InetAddress;
import java.time.Instant;
import java.util.function.BooleanSupplier;
import java.util.regex.Pattern;

/**
 * Port for tracing (LIANA-195): LIANA reports every message it sends or receives, as plaintext
 * after TLS, to a linked Tiger proxy. The reports are supplementary: the proxy drops a message it
 * also sees on the wire, so LIANA reports everything without knowing which routes are observed.
 *
 * <p>Addresses are {@code name/IP:Port} where there is a socket (LIANA-195.04): Rbel splits that
 * into hostname and IP without DNS, the IP is the one on the wire, the name makes the trace
 * independent of the run and becomes the symbolic name in Tiger's sequence diagram and topology.
 * LIANA itself is {@link #name()}.
 */
public interface Traffic {

  /** Hostname characters; an IP literal or localhost does not count as name. */
  Pattern NAME = Pattern.compile("[A-Za-z0-9][A-Za-z0-9.-]*");

  /**
   * Whether Tiger keeps {@code value} as server name: a hostname, not an IP and not {@code
   * localhost} ({@code ServerNameFromKnownHostname}).
   */
  static boolean isName(String value) {
    return value != null
        && NAME.matcher(value).matches()
        && !value.equalsIgnoreCase("localhost")
        && !value.matches("[0-9.]+");
  }

  /** Symbolic name of this connector when nothing else is configured. */
  String DEFAULT_NAME = "konnektor";

  /** No reports, the default without {@code liana.trace.push-url}. */
  Traffic OFF = (message, sender, receiver, time, responseTo) -> null;

  /**
   * Reports {@code message} from {@code sender} to {@code receiver} (each {@code host:port}),
   * asynchronously; a slow or missing proxy holds up nothing.
   *
   * @param responseTo UUID of the request this message answers, or {@code null}
   * @return UUID of the reported message, for {@code responseTo} of its response; {@code null} if
   *     nothing is reported
   */
  String report(byte[] message, String sender, String receiver, Instant time, String responseTo);

  /** Whether reports go anywhere; callers skip collecting the bytes otherwise. */
  default boolean active() {
    return this != OFF;
  }

  /**
   * Symbolic name of this connector in the trace ({@code liana.trace.name}); never an IP and never
   * {@code localhost}, so that Tiger takes it as the server name.
   */
  default String name() {
    return DEFAULT_NAME;
  }

  /** {@code name/IP:Port}; without {@code ip} only {@code name:Port}. */
  static String address(String name, InetAddress ip, int port) {
    return address(name, ip == null ? null : ip.getHostAddress(), port);
  }

  /**
   * {@code name/IP:Port} with the IP as literal; without {@code ip}, or if the name is the IP
   * itself, only {@code name:Port}; without port (not connected) without {@code :Port}.
   */
  static String address(String name, String ip, int port) {
    String host = ip == null || ip.isEmpty() || ip.equals(name) ? name : name + "/" + ip;
    return port > 0 ? host + ":" + port : host;
  }

  /** {@code name/IP:Port} of this connector's end of a connection. */
  default String self(InetAddress ip, int port) {
    return address(name(), ip, port);
  }

  /**
   * This traffic for one channel that can be switched off at runtime (LIANA-195.05): reports only
   * while {@code on} holds, asked per message. {@link #active()} stays that of this traffic, so
   * that a channel switched on later reports without rewiring.
   */
  default Traffic gated(BooleanSupplier on) {
    Traffic traffic = this;
    if (traffic == OFF) {
      return OFF;
    }
    return new Traffic() {
      @Override
      public String report(
          byte[] message, String sender, String receiver, Instant time, String responseTo) {
        return on.getAsBoolean()
            ? traffic.report(message, sender, receiver, time, responseTo)
            : null;
      }

      @Override
      public boolean active() {
        return traffic.active();
      }

      @Override
      public String name() {
        return traffic.name();
      }
    };
  }
}

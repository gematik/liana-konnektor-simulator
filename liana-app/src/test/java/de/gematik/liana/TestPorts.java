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

import io.quarkus.test.junit.QuarkusTestProfile;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.ServerSocket;
import java.util.HashMap;
import java.util.Map;

/**
 * Free ports for tests that need LIANA with fixed ports: the ITs against the built artifact (prod
 * profile, otherwise 8080/8443/9090) and tests whose configuration names their own port ({@code
 * kon-export.url}). Assigned once per test JVM so that a running Testhub or LIANA container on the
 * default ports does not interfere.
 */
public final class TestPorts {

  /**
   * Ports already assigned; declared before the constants that call {@link #free()} during class
   * loading.
   */
  private static final java.util.Set<Integer> TAKEN =
      java.util.concurrent.ConcurrentHashMap.newKeySet();

  public static final int HTTP = free();
  public static final int HTTPS = free();
  public static final int ADMIN = free();
  public static final int TLS = free();

  /**
   * Only for the compatibility listeners ({@code liana.kms.port}, {@code
   * liana.cats.terminals[].port}).
   */
  public static final int KMS = free();

  public static final int CATS = free();

  /** Stub UFS of the Onlineprüfung (LIANA-141). */
  public static final int UFS = free();

  static {
    // The @QuarkusIntegrationTest launcher takes the HTTP port from the test configuration, not
    // from the
    // profile
    System.setProperty("quarkus.http.test-port", String.valueOf(HTTP));
    System.setProperty("quarkus.http.test-ssl-port", String.valueOf(HTTPS));
  }

  private TestPorts() {}

  /** All ports as configuration, extended by {@code extra}. */
  public static Map<String, String> config(String... extra) {
    Map<String, String> config =
        new HashMap<>(
            Map.of(
                "quarkus.http.test-port", String.valueOf(HTTP),
                "quarkus.http.test-ssl-port", String.valueOf(HTTPS),
                "liana.admin.port", String.valueOf(ADMIN),
                "liana.tls.port", String.valueOf(TLS)));
    for (int i = 0; i < extra.length; i += 2) {
      config.put(extra[i], extra[i + 1]);
    }
    return config;
  }

  /** Profile for ITs without their own configuration. */
  public static class Profile implements QuarkusTestProfile {
    @Override
    public Map<String, String> getConfigOverrides() {
      return config();
    }
  }

  /** Below the ephemeral ranges of Linux (from 32768) and macOS (from 49152), LIANA-154. */
  static final int RANGE_START = 20000;

  static final int RANGE_END = 32000;

  /**
   * A free port from {@link #RANGE_START}..{@link #RANGE_END}, checked on all addresses the way
   * LIANA binds. Port 0 would assign an ephemeral port that an outgoing connection of the same JVM
   * could occupy as its local port before Quarkus starts (LIANA-154: BindException across several
   * Quarkus starts in one run).
   */
  static int free() {
    java.util.Random random = new java.util.Random();
    for (int i = 0; i < 1000; i++) {
      int port = RANGE_START + random.nextInt(RANGE_END - RANGE_START);
      if (TAKEN.contains(port)) {
        continue;
      }
      try (ServerSocket socket = new ServerSocket()) {
        socket.setReuseAddress(false);
        socket.bind(new java.net.InetSocketAddress(port));
        TAKEN.add(port);
        return port;
      } catch (IOException e) {
        // in use, next one
      }
    }
    throw new UncheckedIOException(
        new IOException("kein freier Port in " + RANGE_START + ".." + RANGE_END));
  }
}

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
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * {@code kartos terminal} as eHealth KT for LIANA ({@code infrastructure.terminals.KT-01.type:
 * sicct}) (LIANA-81, decision-11): slots in the order of {@link #IMAGES} like KT-01 of the fake
 * terminal, plus the gSMC-KT as TLS identity; a pairing with {@link #SHARED_SECRET} and the key of
 * LIANA's ID.SAK.AUT is preset, as if LIANA had paired earlier (TUC_KON_053, gemSpec_KT
 * TIP1-A_3046-01). Loopback only, ports chosen freely, service discovery over the same port as
 * SICCT (TERMINAL_UDP_DISCOVERY_PORT=0).
 */
final class KartosTerminalProcess implements AutoCloseable {

  static final String SHARED_SECRET = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf";

  /**
   * Slot 1 eGK, slot 2 SMC-B like KT-01 in {@code application.yaml}; the gSMC-KT provides
   * C.SMKT.AUT.
   */
  static final List<String> IMAGES = List.of("egk-valid", "smcb-valid", "gsmckt-valid");

  private static final Duration START_TIMEOUT = Duration.ofSeconds(10);

  private final Process process;
  private final Path state;
  private final int port;

  private KartosTerminalProcess(Process process, Path state, int port) {
    this.process = process;
    this.state = state;
    this.port = port;
  }

  /** Starts kartos with its log in {@code log} and waits until the SICCT port is open. */
  static KartosTerminalProcess start(Path kartos, Path log) {
    try {
      int port;
      try (var socket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
        port = socket.getLocalPort();
      }
      Path state = Files.createTempDirectory("kartos-terminal");
      Path images = Files.createDirectories(state.resolve("images"));
      for (int i = 0; i < IMAGES.size(); i++) {
        Files.copy(
            Path.of("support/images", IMAGES.get(i) + ".xml"),
            images.resolve((i + 1) + "_" + IMAGES.get(i) + ".xml"));
      }
      Files.createDirectories(state.resolve("state"));
      Files.writeString(
          state.resolve("state").resolve("pairing.json"),
          "[{\"shared_secret\":\""
              + SHARED_SECRET
              + "\",\"konnektor_keys\":[\""
              + lianaKey()
              + "\"],\"created_at\":\"2026-10-09T00:00:00Z\","
              + "\"known_ips\":[]}]");
      Files.createDirectories(log.getParent());
      var builder =
          new ProcessBuilder(
                  kartos.toString(),
                  "terminal",
                  "--workdir",
                  images.toString(),
                  "--port",
                  String.valueOf(port))
              .redirectErrorStream(true)
              .redirectOutput(log.toFile());
      var env = builder.environment();
      env.put("TERMINAL_STATE_DIR", state.resolve("state").toString());
      env.put("TERMINAL_BIND_ADDR", "127.0.0.1");
      env.put("TERMINAL_ADVERTISE_IP", "127.0.0.1");
      env.put("TERMINAL_ADVERTISE_MAC", "02:00:00:4C:49:81");
      env.put("TERMINAL_FRIENDLY_NAME", "kartos-kt-trace");
      env.put("TERMINAL_UDP_DISCOVERY_PORT", "0");
      env.put("TERMINAL_BROADCAST_ADDR", "127.0.0.1");
      env.put("TERMINAL_ANNOUNCE_ON_STARTUP", "false");
      env.put("TERMINAL_ANNOUNCE_INTERVAL_SECS", "0");
      env.put("TERMINAL_CONTROL_ADDR", "127.0.0.1:0");
      var kt = new KartosTerminalProcess(builder.start(), state, port);
      kt.awaitPort(log);
      return kt;
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  /**
   * Configuration with which LIANA addresses KT-01 via SICCT instead of the fake terminal; KT-02
   * remains an empty fake KT, the workplace only knows KT-01.
   */
  List<String> lianaConfig() {
    return List.of(
        "liana.infrastructure.terminals.KT-01.type=sicct",
        "liana.infrastructure.terminals.KT-01.host=127.0.0.1",
        "liana.infrastructure.terminals.KT-01.shared-secret=" + SHARED_SECRET,
        "liana.ctm.service-discovery-port=" + port,
        "liana.ctm.service-announcement-port=0",
        "liana.ctm.service-discovery-timeout=2s",
        "liana.infomodel.workplaces[0].terminals=KT-01");
  }

  /**
   * {@code SubjectPublicKeyInfo} (hex) of LIANA's ID.SAK.AUT; kartos binds the pairing block to it.
   */
  private static String lianaKey() throws IOException {
    try (var in = Files.newInputStream(Path.of("support/pki/server/sak-aut-bp256.pem"))) {
      var cert = java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(in);
      return java.util.HexFormat.of().formatHex(cert.getPublicKey().getEncoded());
    } catch (java.security.cert.CertificateException e) {
      throw new IOException(e);
    }
  }

  private void awaitPort(Path log) throws IOException {
    var deadline = Instant.now().plus(START_TIMEOUT);
    while (Instant.now().isBefore(deadline)) {
      try (var probe = new Socket(InetAddress.getLoopbackAddress(), port)) {
        return;
      } catch (IOException notYet) {
        if (!process.isAlive()) {
          break;
        }
        try {
          TimeUnit.MILLISECONDS.sleep(20);
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
          break;
        }
      }
    }
    close();
    throw new IllegalStateException("kartos terminal startet nicht:\n" + Files.readString(log));
  }

  @Override
  public void close() {
    process.destroy();
    try {
      if (!process.waitFor(5, TimeUnit.SECONDS)) {
        process.destroyForcibly();
      }
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      process.destroyForcibly();
    }
    try (var files = Files.walk(state)) {
      files.sorted(java.util.Comparator.reverseOrder()).forEach(path -> path.toFile().delete());
    } catch (IOException ignored) {
      // temp directory; left behind if need be
    }
  }
}

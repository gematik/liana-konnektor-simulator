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
package de.gematik.liana.sicct;

import de.gematik.liana.adapter.fake.KartosLocator;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;

/**
 * {@code kartos terminal} as a separate process for ITs (decision-11): workdir {@code
 * support/images}, state in a temp folder, loopback only. TCP and UDP port chosen freely; service
 * announcements go to {@code announceTo} on 127.0.0.1 if set.
 */
public final class KartosTerminal implements AutoCloseable {

  /**
   * ID.SAK.AUT with which LIANA authenticates to the KT via TLS ({@code
   * liana.infrastructure.konnektor.gsmc-k.sak-aut}).
   */
  public static final Path SAK_AUT_CERT = Path.of("support/pki/server/sak-aut-bp256.pem");

  /** Public key of {@link #SAK_AUT_CERT}, as kartos stores it in the pairing block. */
  public static final String LIANA_KEY = subjectPublicKeyInfo(SAK_AUT_CERT);

  private final Process process;
  private final Path state;
  private final int port;
  private final int controlPort;

  private KartosTerminal(Process process, Path state, int port, int controlPort) {
    this.process = process;
    this.state = state;
    this.port = port;
    this.controlPort = controlPort;
  }

  /**
   * Starts kartos and waits until the SICCT port is open.
   *
   * @param mac CT.MAC_ADRESS that the KT announces
   * @param name SICCT terminal name (CT.HOSTNAME)
   * @param announceTo UDP port for the service announcement at startup, 0 for none
   */
  public static KartosTerminal start(
      String mac, String name, int announceTo, Map<String, String> env) {
    return start(mac, name, announceTo, env, null);
  }

  /**
   * Like {@link #start(String, String, int, Map)}, with an already stored pairing block for {@code
   * sharedSecretHex} and the key of LIANA's ID.SAK.AUT in {@code <state>/pairing.json}, as if LIANA
   * had paired earlier (TUC_KON_053).
   */
  public static KartosTerminal start(
      String mac, String name, int announceTo, Map<String, String> env, String sharedSecretHex) {
    return start(mac, name, announceTo, env, sharedSecretHex, null);
  }

  /**
   * As above, with the slots filled with {@code images} (names from {@code support/images}) in this
   * order, slot 1 first; {@code null} takes {@code support/images} as it is.
   */
  public static KartosTerminal start(
      String mac,
      String name,
      int announceTo,
      Map<String, String> env,
      String sharedSecretHex,
      java.util.List<String> images) {
    try {
      int[] ports = freeTcpPorts(2);
      int port = ports[0];
      int control = ports[1];
      Path state = Files.createTempDirectory("kartos-terminal");
      String workdir = "support/images";
      if (images != null) {
        Path dir = Files.createDirectories(state.resolve("images"));
        for (int i = 0; i < images.size(); i++) {
          Files.copy(
              Path.of("support/images", images.get(i) + ".xml"),
              dir.resolve((i + 1) + "_" + images.get(i) + ".xml"));
        }
        workdir = dir.toString();
      }
      if (sharedSecretHex != null) {
        Files.createDirectories(state.resolve("state"));
        Files.writeString(
            state.resolve("state").resolve("pairing.json"),
            pairingBlock(sharedSecretHex, LIANA_KEY));
      }
      ProcessBuilder builder =
          new ProcessBuilder(
                  kartosBinary().toString(),
                  "terminal",
                  "--workdir",
                  workdir,
                  "--port",
                  String.valueOf(port))
              .redirectErrorStream(true)
              .redirectOutput(state.resolve("kartos.log").toFile());
      Map<String, String> e = builder.environment();
      e.put("TERMINAL_STATE_DIR", state.resolve("state").toString());
      e.put("TERMINAL_TRACES_DIR", state.resolve("traces").toString());
      e.put("TERMINAL_BIND_ADDR", "127.0.0.1");
      e.put("TERMINAL_ADVERTISE_IP", "127.0.0.1");
      e.put("TERMINAL_ADVERTISE_MAC", mac);
      e.put("TERMINAL_FRIENDLY_NAME", name);
      e.put("TERMINAL_UDP_DISCOVERY_PORT", "0");
      e.put("TERMINAL_BROADCAST_ADDR", "127.0.0.1");
      e.put("TERMINAL_ANNOUNCE_ON_STARTUP", String.valueOf(announceTo != 0));
      e.put("TERMINAL_ANNOUNCE_PORT", String.valueOf(announceTo != 0 ? announceTo : port));
      e.put("TERMINAL_ANNOUNCE_INTERVAL_SECS", "0");
      e.put("TERMINAL_CONTROL_ADDR", "127.0.0.1:" + control);
      e.put("RUST_LOG", "info");
      e.putAll(env);
      Process process = builder.start();
      KartosTerminal kt = new KartosTerminal(process, state, port, control);
      long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
      while (true) {
        try (Socket probe = new Socket(InetAddress.getLoopbackAddress(), port)) {
          return kt;
        } catch (IOException notYet) {
          if (!process.isAlive() || System.nanoTime() > deadline) {
            kt.close();
            throw new IllegalStateException("kartos terminal startet nicht: " + kt.log());
          }
          Thread.sleep(20);
        }
      }
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IllegalStateException(e);
    }
  }

  /**
   * kartos binary: {@code LIANA_KARTOS_BIN}, otherwise the checked-in one from {@code
   * tools/kartos/} ({@link KartosLocator}).
   */
  public static Path kartosBinary() {
    String override = System.getenv("LIANA_KARTOS_BIN");
    if (override != null && !override.isBlank()) {
      return Path.of(override);
    }
    return KartosLocator.bundledPath(Path.of(""))
        .orElseThrow(
            () ->
                new IllegalStateException(
                    "kein kartos-Binary für "
                        + System.getProperty("os.name")
                        + "/"
                        + System.getProperty("os.arch")
                        + ": LIANA_KARTOS_BIN setzen"));
  }

  /**
   * SICCT TCP port; the service request goes to the same UDP port (TERMINAL_UDP_DISCOVERY_PORT=0).
   */
  public int port() {
    return port;
  }

  /** Process ID, e.g. to mute kartos via SIGSTOP. */
  public long pid() {
    return process.pid();
  }

  /**
   * Control interface (LIANA-72, kartos 0.8.0: {@code
   * crates/kartos-terminal/openapi/kartos-terminal-control-v1.yaml}).
   */
  public int controlPort() {
    return controlPort;
  }

  /** Request to the control interface under {@code /api/v1}, JSON. */
  public io.restassured.specification.RequestSpecification control() {
    return io.restassured.RestAssured.given()
        .port(controlPort)
        .basePath("/api/v1")
        .contentType("application/json");
  }

  /** ICCSN of the card in {@code slot}, as the kartos card library keeps it. */
  public String iccsn(int slot) {
    return control().get("/slots/" + slot).then().statusCode(200).extract().path("iccsn");
  }

  /** Pulls the card from {@code slot} back into the card library; LIANA sees 85. */
  public void eject(int slot) {
    control().delete("/slots/" + slot + "/card").then().statusCode(200);
  }

  /** Inserts the card {@code iccsn} from the card library into {@code slot}; LIANA sees 84. */
  public void insert(int slot, String iccsn) {
    control()
        .body("{\"iccsn\":\"" + iccsn + "\"}")
        .put("/slots/" + slot + "/card")
        .then()
        .statusCode(200);
  }

  /**
   * Fault at {@code slot} (feature {@code fault-injection}), e.g. {@code
   * {"type":"mute","count":1}}.
   */
  public void fault(int slot, String json) {
    control().body(json).put("/slots/" + slot + "/fault").then().statusCode(200);
  }

  /**
   * Next PIN entries on the keypad as a script, e.g. {@code [{"outcome":"cancel","slotNo":2}]};
   * effective in input mode {@code script} ({@code TERMINAL_INPUT_MODE=script} at startup); without
   * a matching entry the auto PIN applies.
   */
  public void pinScript(String json) {
    control().body(json).post("/tui/script").then().statusCode(200);
  }

  /**
   * {@code pairing.json} with one pairing block (gemSpec_KT TIP1-A_3045, TIP1-A_3046-01): shared
   * secret and the public keys of the Konnektor certificates, each {@code SubjectPublicKeyInfo} as
   * hex (kartos format).
   */
  public static String pairingBlock(String sharedSecretHex, String... konnektorKeys) {
    return "[{\"shared_secret\":\""
        + sharedSecretHex
        + "\",\"konnektor_keys\":["
        + java.util.Arrays.stream(konnektorKeys)
            .map(k -> "\"" + k + "\"")
            .collect(java.util.stream.Collectors.joining(","))
        + "],\"created_at\":\"2026-10-09T00:00:00Z\",\"known_ips\":[]}]";
  }

  /** {@code SubjectPublicKeyInfo} (DER, hex) of the certificate in {@code pem}. */
  public static String subjectPublicKeyInfo(Path pem) {
    try (var in = Files.newInputStream(pem)) {
      var cert =
          (java.security.cert.X509Certificate)
              java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(in);
      return java.util.HexFormat.of().formatHex(cert.getPublicKey().getEncoded());
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    } catch (java.security.GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  /** Replaces {@code <state>/pairing.json}; kartos rereads the file on every pairing command. */
  public void pairingStore(String json) {
    try {
      Files.writeString(
          Files.createDirectories(state.resolve("state")).resolve("pairing.json"), json);
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  /** {@code <state>/pairing.json} of kartos, empty if there is none (yet). */
  public String pairingStore() {
    try {
      Path store = state.resolve("state").resolve("pairing.json");
      return Files.exists(store) ? Files.readString(store) : "";
    } catch (IOException e) {
      return e.getMessage();
    }
  }

  /**
   * The kartos wire trace (JSONL, one line per envelope with {@code dir}, {@code msg}, {@code fu},
   * {@code seq} and {@code hex}), only with {@code TERMINAL_TRACE=true} in the {@code env} of
   * {@link #start}; all connections.
   */
  public java.util.List<String> wire() {
    try (var files = Files.list(state.resolve("traces"))) {
      java.util.List<String> lines = new java.util.ArrayList<>();
      for (Path file : files.sorted().toList()) {
        lines.addAll(Files.readAllLines(file));
      }
      return lines;
    } catch (IOException e) {
      return java.util.List.of();
    }
  }

  public String log() {
    try {
      return Files.readString(state.resolve("kartos.log"));
    } catch (IOException e) {
      return e.getMessage();
    }
  }

  /**
   * {@code count} distinct free TCP ports from 20000..32000, each checked via bind (like {@code
   * LianaProcess.freePorts}, LIANA-89). Two ports obtained one after the other via ServerSocket(0)
   * can be the same port on Linux, and port 0 assigns ephemeral ports that outgoing connections may
   * occupy until startup (LIANA-162).
   */
  public static int[] freeTcpPorts(int count) {
    java.util.Random random = new java.util.Random();
    java.util.Set<Integer> ports = new java.util.LinkedHashSet<>();
    for (int i = 0; i < 1000 && ports.size() < count; i++) {
      int port = 20000 + random.nextInt(12000);
      if (ports.contains(port)) {
        continue;
      }
      try (ServerSocket socket = new ServerSocket()) {
        socket.setReuseAddress(false);
        socket.bind(new java.net.InetSocketAddress(InetAddress.getLoopbackAddress(), port));
        ports.add(port);
      } catch (IOException taken) {
        // in use, next one
      }
    }
    if (ports.size() < count) {
      throw new UncheckedIOException(
          new IOException("keine " + count + " freien Ports in 20000..32000"));
    }
    return ports.stream().mapToInt(Integer::intValue).toArray();
  }

  /** A free UDP port on loopback. */
  public static int freeUdpPort() throws IOException {
    try (DatagramSocket socket = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
      return socket.getLocalPort();
    }
  }

  @Override
  public void close() {
    process.destroy();
    try {
      process.waitFor();
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }
}

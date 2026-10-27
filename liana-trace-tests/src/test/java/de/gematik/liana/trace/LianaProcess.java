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

import de.gematik.liana.adapter.fake.KartosLocator;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

/**
 * The built LIANA as a separate process: {@code quarkus-run.jar} or the native image (system
 * property {@code liana.runner}, set by the Failsafe plugin). Ports chosen freely, output to a log
 * file.
 *
 * <p>All TCP ports LIANA binds (HTTP, HTTPS, management port with Admin API, KMS and CATS) come
 * from {@link #freePorts}. Between releasing them there and binding in LIANA another process may
 * take one of them; if LIANA therefore exits with {@code BindException}, {@link #start} restarts
 * with new ports (LIANA-89). The log of the failed attempt is kept as {@code
 * liana-<name>.bind-<n>.log}.
 *
 * <p>With {@code -Dliana.trace.terminal=sicct} (Failsafe execution {@code sicct}, LIANA-81) KT-01
 * is not in the fake terminal but is an eHealth KT {@code kartos terminal} ({@link
 * KartosTerminalProcess}); LIANA addresses it via SICCT. LIANA is then only ready once KT-01 has
 * reported its cards.
 */
final class LianaProcess implements ReplayTarget {

  private static final Duration START_TIMEOUT = Duration.ofSeconds(30);
  static final int START_ATTEMPTS = 3;

  /**
   * HTTP, HTTPS ({@code liana.tls.port}), management port ({@code liana.admin.port}: Admin API,
   * KMS, CATS)
   */
  static final int PORTS = 3;

  /** Cards KT-01 reports at startup: eGK in slot 1, SMC-B in slot 2. */
  private static final List<String> KT01_CARDS =
      List.of("CARD/INSERTED KT-01/1 ", "CARD/INSERTED KT-01/2 ");

  private final Process process;
  private final Path log;
  private final int[] ports;
  private final KartosTerminalProcess kartosTerminal;

  private LianaProcess(
      Process process, Path log, int[] ports, KartosTerminalProcess kartosTerminal) {
    this.process = process;
    this.log = log;
    this.ports = ports;
    this.kartosTerminal = kartosTerminal;
  }

  /** {@code true} if KT-01 is an eHealth KT via SICCT ({@code -Dliana.trace.terminal=sicct}). */
  static boolean sicct() {
    return "sicct".equals(System.getProperty("liana.trace.terminal", "fake"));
  }

  static LianaProcess start(String name, List<String> config) {
    return start(name, config, () -> freePorts(PORTS));
  }

  /**
   * Starts LIANA with ports from {@code ports} ({@link #PORTS} of them: HTTP, HTTPS, management
   * port); on {@code BindException} up to {@link #START_ATTEMPTS} attempts, each with newly drawn
   * ports.
   */
  static LianaProcess start(String name, List<String> config, Supplier<int[]> ports) {
    var runner =
        Path.of(System.getProperty("liana.runner", "liana-app/target/quarkus-app/quarkus-run.jar"));
    if (!Files.isRegularFile(runner)) {
      throw new IllegalStateException("LIANA nicht gebaut: " + runner.toAbsolutePath() + " fehlt");
    }
    var suffix = sicct() ? "-sicct" : "";
    var log = Path.of("liana-trace-tests", "target", "liana-" + name + suffix + ".log");
    for (int attempt = 1; ; attempt++) {
      KartosTerminalProcess kt = null;
      try {
        var effective = config;
        if (sicct()) {
          kt =
              KartosTerminalProcess.start(
                  kartosBin()
                      .orElseThrow(
                          () -> new IllegalStateException("kein kartos-Binary für dieses System")),
                  log.resolveSibling("kartos-" + name + ".log"));
          effective = new ArrayList<>(kt.lianaConfig());
          effective.addAll(config);
        }
        return launch(runner, log, effective, ports.get(), kt);
      } catch (PortTaken e) {
        if (kt != null) {
          kt.close();
        }
        try {
          Files.move(
              log,
              log.resolveSibling("liana-" + name + suffix + ".bind-" + attempt + ".log"),
              StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException moveFailed) {
          throw new UncheckedIOException(moveFailed);
        }
        if (attempt == START_ATTEMPTS) {
          throw new IllegalStateException(
              "LIANA nach " + START_ATTEMPTS + " Versuchen ohne freie Ports:\n" + e.getMessage());
        }
      }
    }
  }

  private static LianaProcess launch(
      Path runner,
      Path log,
      List<String> config,
      int[] ports,
      KartosTerminalProcess kartosTerminal) {
    var properties = new ArrayList<String>();
    properties.add("-Dquarkus.http.port=" + ports[0]);
    properties.add("-Dliana.tls.port=" + ports[1]);
    properties.add("-Dliana.admin.port=" + ports[2]);
    kartosBin()
        .ifPresent(kartos -> properties.add("-Dliana.card.kartos-bin=" + kartos.toAbsolutePath()));
    config.forEach(entry -> properties.add("-D" + entry));

    var command = new ArrayList<String>();
    if (runner.toString().endsWith(".jar")) {
      command.add(Path.of(System.getProperty("java.home"), "bin", "java").toString());
      command.addAll(properties);
      command.add("-jar");
      command.add(runner.toString());
    } else {
      command.add(runner.toString());
      command.addAll(properties);
    }
    try {
      Files.createDirectories(log.getParent());
      var process =
          new ProcessBuilder(command)
              .redirectErrorStream(true)
              .redirectOutput(log.toFile())
              .start();
      var liana = new LianaProcess(process, log, ports, kartosTerminal);
      try {
        liana.awaitPort();
      } catch (RuntimeException e) {
        liana.close();
        throw e;
      }
      return liana;
    } catch (IOException e) {
      if (kartosTerminal != null) {
        kartosTerminal.close();
      }
      throw new UncheckedIOException(e);
    }
  }

  /**
   * Whether LIANA failed at startup because of a port in use: {@code BindException} (management
   * port, TLS) or the Quarkus message for the HTTP port, which appears in the log without
   * BindException (LIANA-154, CatsStepsIT).
   */
  static boolean portTaken(String log) {
    return log.contains("java.net.BindException")
        || log.contains("seems to be in use by another process");
  }

  /** LIANA could not bind a port at startup. */
  static final class PortTaken extends RuntimeException {
    PortTaken(String log) {
      super(log);
    }
  }

  /**
   * kartos for the inserted cards (TUC_KON_001 reads them at startup): {@code LIANA_KARTOS_BIN},
   * otherwise the checked-in binary according to LIANA's rule ({@link KartosLocator}). Empty on
   * other systems; LIANA then does not start with fake terminals (LIANA-121).
   */
  static Optional<Path> kartosBin() {
    var explicit = System.getenv("LIANA_KARTOS_BIN");
    if (explicit != null && !explicit.isBlank()) {
      return Optional.of(Path.of(explicit));
    }
    return KartosLocator.bundledPath(Path.of(""));
  }

  /** Base URL of the Konnektor interface, e.g. {@code http://localhost:54321}. */
  @Override
  public String baseUrl() {
    return "http://localhost:" + ports[0];
  }

  /** Admin API (decision-4). */
  String adminUrl() {
    return "http://localhost:" + ports[2];
  }

  /** Base URL of the CATS terminal for KT-01 (LIANA-67) on the management port (LIANA-147). */
  String catsUrl() {
    return "http://127.0.0.1:" + ports[2] + "/cats/KT-01";
  }

  private void awaitPort() throws IOException {
    var deadline = Instant.now().plus(START_TIMEOUT);
    while (Instant.now().isBefore(deadline)) {
      if (!process.isAlive()) {
        String text = logText();
        if (portTaken(text)) {
          throw new PortTaken(text);
        }
        throw new IllegalStateException(
            "LIANA beendet sich beim Start (Exit " + process.exitValue() + "):\n" + text);
      }
      if (ready()) {
        return;
      }
      try {
        TimeUnit.MILLISECONDS.sleep(100);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new IllegalStateException(e);
      }
    }
    close();
    throw new IllegalStateException(
        "LIANA nicht bereit nach " + START_TIMEOUT.toSeconds() + " s:\n" + logText());
  }

  /**
   * Ready when Quarkus reports „started in“ – which only comes after all startup observers, i.e.
   * after HTTPS, Admin and KMS are bound as well (a port in use there terminates LIANA only after
   * the HTTP port) – and the HTTP port responds. With SICCT, LIANA adds the KT only after startup
   * in the background (TUC_KON_054/050); so ready only once it has reported eGK and SMC-B.
   */
  private boolean ready() throws IOException {
    String text = logText();
    if (!text.contains(" started in ")) {
      return false;
    }
    if (kartosTerminal != null && !KT01_CARDS.stream().allMatch(text::contains)) {
      return false;
    }
    try (var socket = new Socket()) {
      socket.connect(new InetSocketAddress("localhost", ports[0]), 200);
      return true;
    } catch (IOException notYet) {
      return false;
    }
  }

  private String logText() throws IOException {
    return Files.readString(log);
  }

  /** {@code count} distinct free ports; the sockets stay open until all are chosen. */
  /** Below the ephemeral ranges of Linux (from 32768) and macOS (from 49152), LIANA-154. */
  static final int RANGE_START = 20000;

  static final int RANGE_END = 32000;

  /**
   * {@code count} distinct free ports from {@link #RANGE_START}..{@link #RANGE_END}, checked on all
   * addresses the way LIANA binds. Port 0 would hand out ephemeral ports, which outgoing
   * connections may occupy until startup.
   */
  static int[] freePorts(int count) {
    var random = new java.util.Random();
    var ports = new java.util.LinkedHashSet<Integer>();
    for (int i = 0; i < 1000 && ports.size() < count; i++) {
      int port = RANGE_START + random.nextInt(RANGE_END - RANGE_START);
      if (ports.contains(port)) {
        continue;
      }
      try (var socket = new ServerSocket()) {
        socket.setReuseAddress(false);
        socket.bind(new InetSocketAddress(port));
        ports.add(port);
      } catch (IOException e) {
        // in use, next
      }
    }
    if (ports.size() < count) {
      throw new UncheckedIOException(
          new IOException("keine " + count + " freien Ports in " + RANGE_START + ".." + RANGE_END));
    }
    return ports.stream().mapToInt(Integer::intValue).toArray();
  }

  @Override
  public void close() {
    try {
      stop();
    } finally {
      if (kartosTerminal != null) {
        kartosTerminal.close();
      }
    }
  }

  private void stop() {
    process.destroy();
    try {
      if (!process.waitFor(10, TimeUnit.SECONDS)) {
        process.destroyForcibly();
      }
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      process.destroyForcibly();
    }
  }
}

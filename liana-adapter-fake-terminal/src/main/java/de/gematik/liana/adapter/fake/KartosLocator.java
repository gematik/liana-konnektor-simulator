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
package de.gematik.liana.adapter.fake;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

/**
 * Finds the kartos binary (decision-7), one rule for LIANA and the tests (LIANA-121): first the
 * configured path ({@code liana.card.kartos-bin}, in the image {@code /opt/liana/bin/kartos}),
 * otherwise the checked-in {@code tools/kartos/kartos-<os>-<arch>} under the working directory
 * (Linux and macOS, amd64 and arm64), so that {@code ./mvnw quarkus:dev} runs in the repo without
 * additional configuration. A candidate counts only if {@code kartos --version} responds; this also
 * catches a binary of the wrong architecture.
 */
public final class KartosLocator {

  /** Environment variable for {@code liana.card.kartos-bin}. */
  public static final String ENV = "LIANA_CARD_KARTOS_BIN";

  private static final long VERSION_TIMEOUT_SECONDS = 10;

  private KartosLocator() {}

  /** A runnable kartos and its version line ({@code kartos 0.7.1}). */
  public record Kartos(Path path, String version) {}

  /**
   * The kartos for LIANA: {@code configured}, otherwise the checked-in one under {@code root}.
   *
   * @throws IllegalStateException if none of the candidates is runnable; the message names each
   *     with its reason
   */
  public static Kartos resolve(Path configured, Path root) {
    List<String> tried = new ArrayList<>();
    List<Path> candidates = new ArrayList<>();
    candidates.add(configured);
    bundledPath(root)
        .ifPresentOrElse(
            candidates::add,
            () ->
                tried.add(
                    "tools/kartos/: kein eingechecktes Binary für "
                        + System.getProperty("os.name")
                        + "/"
                        + System.getProperty("os.arch")));
    for (Path candidate : candidates) {
      try {
        return new Kartos(candidate, version(candidate));
      } catch (IOException e) {
        tried.add(candidate + ": " + e.getMessage());
      }
    }
    throw new IllegalStateException(
        "kartos nicht gefunden, Fake-Terminals brauchen es als Card-Engine. Geprüft:\n    "
            + String.join("\n    ", tried)
            + "\n  Pfad über liana.card.kartos-bin bzw. "
            + ENV
            + " setzen oder LIANA im Repo-Wurzelverzeichnis starten (tools/kartos/).");
  }

  /** The checked-in kartos under {@code root} for this system, if it is there and executable. */
  public static Optional<Path> bundled(Path root) {
    return bundledPath(root).filter(Files::isExecutable);
  }

  /**
   * Where the checked-in kartos for this system lies under {@code root}; empty on other systems.
   */
  public static Optional<Path> bundledPath(Path root) {
    String osName = System.getProperty("os.name").toLowerCase(Locale.ROOT);
    String os = osName.contains("linux") ? "linux" : osName.contains("mac") ? "darwin" : null;
    String arch =
        switch (System.getProperty("os.arch")) {
          case "amd64", "x86_64" -> "amd64";
          case "aarch64", "arm64" -> "arm64";
          default -> null;
        };
    if (os == null || arch == null) {
      return Optional.empty();
    }
    return Optional.of(root.resolve("tools/kartos/kartos-" + os + "-" + arch));
  }

  /**
   * First line of {@code kartos --version}; IOException if it does not start, hangs or does not
   * return 0.
   */
  static String version(Path kartos) throws IOException {
    if (!Files.isRegularFile(kartos)) {
      throw new IOException("fehlt");
    }
    if (!Files.isExecutable(kartos)) {
      throw new IOException("nicht ausführbar");
    }
    Process process =
        new ProcessBuilder(kartos.toString(), "--version").redirectErrorStream(true).start();
    try {
      if (!process.waitFor(VERSION_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
        process.destroyForcibly();
        throw new IOException("--version antwortet nicht in " + VERSION_TIMEOUT_SECONDS + " s");
      }
    } catch (InterruptedException e) {
      process.destroyForcibly();
      Thread.currentThread().interrupt();
      throw new IOException("--version unterbrochen", e);
    }
    String output =
        new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8).strip();
    if (process.exitValue() != 0) {
      throw new IOException(
          "--version endet mit Exit "
              + process.exitValue()
              + (output.isEmpty() ? "" : ": " + output.lines().findFirst().orElse("")));
    }
    return output.lines().findFirst().orElse("kartos");
  }
}

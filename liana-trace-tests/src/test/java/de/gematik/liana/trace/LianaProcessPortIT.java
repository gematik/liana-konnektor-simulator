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

import static org.assertj.core.api.Assertions.assertThat;

import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * LIANA-89: startup in the trace test survives a port that another process takes between selection
 * and binding.
 */
class LianaProcessPortIT {

  @ParameterizedTest(name = "Port {0} ({1})")
  @CsvSource({
    "0, HTTP – Quarkus meldet ‚seems to be in use‘ ohne BindException (LIANA-154)",
    "1, HTTPS – BindException",
    "2, Management-Port – BindException (LIANA-89, LIANA-154 CatsStepsIT)"
  })
  @DisplayName(
      "Ist ein Port beim ersten Versuch belegt, startet LianaProcess mit neuen Ports und hebt das Log "
          + "des gescheiterten Versuchs auf")
  void belegterPortWirdNeuGezogen(int index, String port) throws Exception {
    Path failed = Path.of("liana-trace-tests", "target", "liana-LianaProcessPortIT.bind-1.log");
    Files.deleteIfExists(failed);
    var attempts = new AtomicInteger();
    try (var taken = new ServerSocket(0);
        var liana =
            LianaProcess.start(
                "LianaProcessPortIT",
                List.of(),
                () -> {
                  int[] ports = LianaProcess.freePorts(LianaProcess.PORTS);
                  if (attempts.incrementAndGet() == 1) {
                    ports[index] = taken.getLocalPort();
                  }
                  return ports;
                })) {
      assertThat(attempts).hasValue(2);
      assertThat(LianaProcess.portTaken(Files.readString(failed))).isTrue();
      var sds =
          HttpClient.newHttpClient()
              .send(
                  HttpRequest.newBuilder(URI.create(liana.baseUrl() + "/connector.sds")).build(),
                  HttpResponse.BodyHandlers.ofString());
      assertThat(sds.statusCode()).isEqualTo(200);
    }
  }
}

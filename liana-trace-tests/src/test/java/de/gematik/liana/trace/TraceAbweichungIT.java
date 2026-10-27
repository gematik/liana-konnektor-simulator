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

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The trace requires CardService 8.3.0, the response has 8.1.0 to 8.2.1 like LIANA (LIANA-120): the
 * comparison must report it.
 */
@TraceReplay("liana-trace-tests/src/test/resources/traces/connector-sds-cardservice-8.3.tgr")
@GegenStub(
    value = "liana-trace-tests/src/test/resources/traces/connector-sds-cardservice-8.3.stub.tgr",
    why = "prüft die Abweichungsmeldung des Replay-Frameworks, nicht LIANA")
@LianaConfig(
    value = "liana.kon-export.url=http://liana:8080",
    why = "popp-client kennt LIANA als http://liana:8080")
class TraceAbweichungIT {

  private static final String VERSION =
      "$.body.ConnectorServices.ServiceInformation.Service[?(@.Name=='CardService')].Versions.Version.Version";

  @Test
  @DisplayName("abweichende Antwort: Meldung nennt RbelPath, Trace-Wert und LIANA-Wert")
  void abweichungWirdGemeldet(Replay replay) {
    assertThatThrownBy(() -> replay.onlyExchange().assertSameAt(VERSION))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining(VERSION)
        .hasMessageContaining("Trace: [8.3.0]")
        .hasMessageContaining("LIANA: [8.1.0, 8.1.1, 8.1.2, 8.2.0, 8.2.1]");
  }

  @Test
  @DisplayName("Tippfehler im RbelPath ist ein Fehler, kein Gleichstand")
  void pfadOhneTrefferWirdGemeldet(Replay replay) {
    assertThatThrownBy(
            () -> replay.onlyExchange().assertSameAt("$.body.ConnectorServices.Gibtsnicht"))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining("trifft im Trace nichts");
  }
}

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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.gematik.rbellogger.data.RbelElement;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Synthetic trace: request 1 fetches {@code connector.sds} (trace: FWVersion 9.9.9), request 2
 * carries the FWVersion, the CtId of the TU terminal and a similar value 9.9.99 in the body.
 */
@TraceReplay("liana-trace-tests/src/test/resources/traces/carry-replace.tgr")
@LianaConfig(
    value = "liana.kon-export.url=http://liana:8080",
    why = "popp-client kennt LIANA als http://liana:8080")
@Replace(
    trace = "56e0aec6-cb06-43ce-8b55-4db3bc39559d",
    liana = "KT-01",
    why = "CtId des TU-Terminals")
@Carry(value = ReplayErsetzungIT.FW_VERSION, why = "FWVersion ist LIANAs Version")
@GegenStub(
    value = "liana-trace-tests/src/test/resources/traces/carry-replace.stub.tgr",
    why =
        "prüft das Replay-Framework, nicht LIANA: FWVersion 0.0.1-stub statt LIANAs, Echo mit 500")
class ReplayErsetzungIT {

  static final String FW_VERSION =
      "$.body.ConnectorServices.ProductInformation.ProductIdentification.ProductVersion.Local.FWVersion.text";
  private static final String ECHO = "$.body.Envelope.Body.Echo.";

  @Test
  @DisplayName("carry: der Wert aus der LIANA-Antwort ersetzt den Trace-Wert im späteren Request")
  void carry(Replay replay) {
    String lianaVersion = text(replay.exchange(0).lianaResponse(), FW_VERSION);
    assertThat(lianaVersion).isNotEqualTo("9.9.9");

    replay
        .exchange(1)
        .assertThatSentRequest()
        .hasStringContentEqualToAtPosition(ECHO + "FWVersion.text", lianaVersion)
        .hasStringContentEqualToAtPosition(ECHO + "Other.text", "9.9.99");
    assertThat(replay.exchange(1).request())
        .satisfies(r -> assertThat(text(r, ECHO + "FWVersion.text")).isEqualTo("9.9.9"));
  }

  @Test
  @DisplayName(
      "replace: feste Umgebungswerte stehen ersetzt im gesendeten Request, Content-Length passt")
  void replace(Replay replay) {
    var exchange = replay.exchange(1);
    exchange
        .assertThatSentRequest()
        .hasStringContentEqualToAtPosition(ECHO + "CtId.text", "KT-01")
        .hasStringContentEqualToAtPosition(
            "$.header.Content-Length",
            String.valueOf(
                exchange.sentRequest().findElement("$.body").orElseThrow().getRawContent().length));
    assertThat(replay.exchange(0).replaced()).isEmpty();
    assertThat(exchange.replaced())
        .containsExactly(
            Map.entry("56e0aec6-cb06-43ce-8b55-4db3bc39559d", "KT-01"),
            Map.entry("9.9.9", text(replay.exchange(0).lianaResponse(), FW_VERSION)));
  }

  @Test
  @DisplayName("Abweichung nennt die Anpassungen am Request mit Begründung")
  void abweichungNenntAnpassungen(Replay replay) {
    assertThatThrownBy(() -> replay.exchange(1).assertSameAt("$.responseCode"))
        .isInstanceOf(AssertionError.class)
        .hasMessageContaining("Request für LIANA angepasst:")
        .hasMessageContaining(
            "CtId des TU-Terminals: 56e0aec6-cb06-43ce-8b55-4db3bc39559d → KT-01");
  }

  private static String text(RbelElement element, String rbelPath) {
    return element.findElement(rbelPath).orElseThrow().getRawStringContent();
  }
}

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

import static de.gematik.rbellogger.testutil.RbelElementAssertion.assertThat;
import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * Reads the first lab recording of tiger-vsdm-e2e-testsuite against the secunet Konnektor
 * (LIANA-101) without starting LIANA: the reference for the VSDM business module (Fachmodul VSDM,
 * LIANA-103).
 */
@Tag("vendor-data")
class VsdmReadSecunetTraceTest {

  private static final TraceFile TRACE =
      TraceFile.read(Path.of("support/vendor/traces/vsdm/vsdm-read-secunet.tgr"));

  private static final String SOAP_BODY = "$.body.Envelope.Body.";
  private static final String READ_VSD = SOAP_BODY + "ReadVSD.";
  private static final String READ_VSD_RESPONSE = SOAP_BODY + "ReadVSDResponse.";

  @Test
  @DisplayName(
      "connector.sds, drei Roboter-Kommandos, dann GetCards SM-B, VerifyPin, GetCards, ReadVSD")
  void ablaufWieImLab() {
    var requests = TRACE.requests();

    assertThat(requests).hasSize(9);
    assertThat(requests.getFirst()).hasStringContentEqualToAtPosition("$.path", "/connector.sds");
    assertThat(
            requests.subList(1, 4).stream()
                .map(r -> r.findElement("$.body.command").orElseThrow().getRawStringContent())
                .toList())
        .containsExactly("selTerminal2", "moveto", "PP");
    var operations = List.of("GetCards", "VerifyPin", "GetCards", "GetCards", "ReadVSD");
    for (int i = 0; i < operations.size(); i++) {
      assertThat(requests.get(4 + i)).hasChildWithPath(SOAP_BODY + operations.get(i));
    }
  }

  @Test
  @DisplayName("Konnektor laut connector.sds: secunet konnektor 2.0.0")
  void konnektor() {
    assertThat(TRACE.responseTo(TRACE.requests().getFirst()))
        .hasStringContentEqualToAtPosition("$..ProductName.text", "secunet konnektor 2.0.0");
  }

  @Test
  @DisplayName(
      "ReadVSD mit Onlineprüfung und Prüfungsnachweis: VSD in drei Teilen, Prüfungsnachweis, VSD_Status")
  void readVsd() {
    var request = TRACE.requests().getLast();
    assertThat(request)
        .hasStringContentEqualToAtPosition(READ_VSD + "PerformOnlineCheck.text", "true")
        .hasStringContentEqualToAtPosition(READ_VSD + "ReadOnlineReceipt.text", "true")
        .hasStringContentEqualToAtPosition(READ_VSD + "EhcHandle.text", "EGK-572")
        .hasStringContentEqualToAtPosition(READ_VSD + "HpcHandle.text", "SMC-B-571");

    var response = TRACE.responseTo(request);
    assertThat(response)
        .hasStringContentEqualToAtPosition("$.responseCode", "200")
        .hasChildWithPath(READ_VSD_RESPONSE + "PersoenlicheVersichertendaten")
        .hasChildWithPath(READ_VSD_RESPONSE + "AllgemeineVersicherungsdaten")
        .hasChildWithPath(READ_VSD_RESPONSE + "GeschuetzteVersichertendaten")
        .hasChildWithPath(READ_VSD_RESPONSE + "Pruefungsnachweis")
        .hasStringContentEqualToAtPosition(READ_VSD_RESPONSE + "VSD_Status.Status.text", "0")
        .hasStringContentEqualToAtPosition(READ_VSD_RESPONSE + "VSD_Status.Version.text", "5.2.0");
  }
}

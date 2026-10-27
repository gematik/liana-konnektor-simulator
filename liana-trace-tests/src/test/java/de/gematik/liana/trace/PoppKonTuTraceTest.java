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

import de.gematik.rbellogger.data.RbelElement;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Reads the golden trace popp-client ↔ TU Konnektor without starting LIANA: content and order as
 * the phase 1 tickets use it as reference.
 */
@Tag("vendor-data")
class PoppKonTuTraceTest {

  private static final TraceFile TRACE =
      TraceFile.read(Path.of("support/vendor/traces/popp-kon-tu/popp-client.tgr"));

  private static final String SOAP_BODY = "$.body.Envelope.Body.";
  private static final String SCENARIO =
      SOAP_BODY + "SecureSendAPDU.SignedScenario.text.body.message";

  @Test
  @DisplayName("12 SOAP-Paare in der Reihenfolge des Logs")
  void operationenInReihenfolge() {
    var operations =
        List.of(
            "GetCards",
            "StartCardSession",
            "GetCards",
            "ReadCardCertificate",
            "GetCards",
            "VerifyPin",
            "ExternalAuthenticate",
            "SecureSendAPDU",
            "SecureSendAPDU",
            "SecureSendAPDU",
            "SecureSendAPDU",
            "StopCardSession");
    var requests = TRACE.requests();

    assertThat(requests).hasSize(operations.size());
    for (int i = 0; i < operations.size(); i++) {
      assertThat(requests.get(i)).hasChildWithPath(SOAP_BODY + operations.get(i));
    }
  }

  @Test
  @DisplayName("GetCards (EGK) liefert den CardHandle, mit dem StartCardSession arbeitet")
  void cardHandleAusGetCards() {
    var requests = TRACE.requests();
    var handle =
        TRACE
            .responseTo(requests.get(0))
            .findElement(SOAP_BODY + "GetCardsResponse.Cards.Card.CardHandle.text")
            .orElseThrow()
            .getRawStringContent();

    assertThat(handle).isEqualTo("EGK-24");
    assertThat(requests.get(1))
        .hasStringContentEqualToAtPosition(SOAP_BODY + "StartCardSession.CardHandle.text", handle);
  }

  @Test
  @DisplayName("StopCardSession nach dem letzten Szenario: Fault 4288 „Unbekannte Session ID“")
  void stopCardSessionNachLetztemSzenario() {
    var stop = TRACE.requests().getLast();

    assertThat(TRACE.responseTo(stop))
        .hasStringContentEqualToAtPosition("$.responseCode", "500")
        .hasStringContentEqualToAtPosition(SOAP_BODY + "Fault.detail.Error.Trace.Code.text", "4288")
        .hasStringContentEqualToAtPosition(
            SOAP_BODY + "Fault.faultstring.text", "Unbekannte Session ID");
  }

  @ParameterizedTest(name = "Sequenz {0}")
  @ValueSource(ints = {0, 1, 2})
  @DisplayName(
      "SignedScenario der Sequenzen 0, 1 und 2 entspricht dem Blueprint – Sequenz 2 ist auf dem "
          + "Konnektor-Pfad poppApdusSequence2.json, nicht poppApdusSequence2Connector.json")
  void sequenzWieBlueprint(int sequence) {
    var request = scenario(sequence);
    var blueprint =
        TRACE.parse(Path.of("support/blueprints/poppApdusSequence" + sequence + ".json"));

    // hex upper/lower case differs between PoPP service and blueprint
    assertThat(upper(request, SCENARIO + ".steps.*.commandApdu"))
        .isEqualTo(upper(blueprint, "$.steps.*.commandApdu"));
    assertThat(upper(request, SCENARIO + ".steps.*.expectedStatusWords.*"))
        .isEqualTo(upper(blueprint, "$.steps.*.expectedStatusWords.*"));
  }

  @Test
  @DisplayName(
      "Sequenz 3 der TU: nach GENERAL AUTHENTICATE Secure Messaging (CLA 0C), nicht der Klartext aus "
          + "poppApdusSequence3.json; Statuswörter wie im Blueprint")
  void sequenz3MitSecureMessaging() {
    var request = scenario(3);
    var blueprint = TRACE.parse(Path.of("support/blueprints/poppApdusSequence3.json"));

    var apdus = upper(request, SCENARIO + ".steps.*.commandApdu");
    var blueprintApdus = upper(blueprint, "$.steps.*.commandApdu");
    assertThat(apdus).hasSameSizeAs(blueprintApdus);
    // GENERAL AUTHENTICATE carries the ephemeral key of the PoPP service
    assertThat(apdus.getFirst()).startsWith("00860000").isNotEqualTo(blueprintApdus.getFirst());
    assertThat(apdus.subList(1, apdus.size())).allMatch(apdu -> apdu.startsWith("0C"));
    assertThat(blueprintApdus.subList(1, blueprintApdus.size()))
        .allMatch(apdu -> apdu.startsWith("00"));
    assertThat(upper(request, SCENARIO + ".steps.*.expectedStatusWords.*"))
        .isEqualTo(upper(blueprint, "$.steps.*.expectedStatusWords.*"));
  }

  private static RbelElement scenario(int sequence) {
    return TRACE.requests().stream()
        .filter(
            r ->
                r.findElement(SCENARIO + ".sequenceCounter")
                    .map(RbelElement::getRawStringContent)
                    .filter(String.valueOf(sequence)::equals)
                    .isPresent())
        .findFirst()
        .orElseThrow();
  }

  private static List<String> upper(RbelElement element, String rbelPath) {
    return element.findRbelPathMembers(rbelPath).stream()
        .map(e -> e.getRawStringContent().toUpperCase())
        .toList();
  }
}

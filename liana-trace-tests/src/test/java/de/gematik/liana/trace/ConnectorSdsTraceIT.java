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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * At startup popp-client fetches {@code connector.sds} and takes the highest version with its
 * endpoint per service. Since LIANA-120 LIANA offers all served versions per service; the one
 * popp-client takes is compared.
 */
@TraceReplay("support/traces/connector-sds/popp-client.tgr")
@LianaConfig(
    value = "liana.kon-export.url=http://liana:8080",
    why = "popp-client kennt LIANA als http://liana:8080")
class ConnectorSdsTraceIT {

  private static final String SERVICE = "$.body.ConnectorServices.ServiceInformation.Service";

  @ParameterizedTest(name = "{0} {1}")
  @CsvSource({"EventService, 7.2.0", "CardService, 8.2.1"})
  @DisplayName(
      "TIP1-A_4528 Dienste aus dem Trace mit Version, Namespace und Endpunkt wie im Trace (die höchste "
          + "Version, die der popp-client nimmt); LIANA bietet darüber hinaus weitere Dienste (CertificateService für "
          + "ZETA, LIANA-30) und ältere Versionen an (TIP1-A_4586-04, LIANA-120)")
  void diensteWieImTrace(String service, String highest, Replay replay) {
    String version =
        SERVICE
            + "[?(@.Name=='"
            + service
            + "')].Versions.Version[?(@.Version=='"
            + highest
            + "')]";
    // InformationDate and FWVersion are deliberately missing: timestamp and LIANA version
    // legitimately change
    replay
        .onlyExchange()
        .assertSameAt(
            "$.responseCode",
            "$.body.ConnectorServices.TLSMandatory.text",
            version + ".Version",
            version + ".TargetNamespace",
            version + ".Endpoint.Location");
  }

  @Test
  @DisplayName("TIP1-A_4529-02 CardService 8.2.1 ohne TLS unter /ws/CardService")
  void cardServiceFuerPoppClient(Replay replay) {
    replay
        .onlyExchange()
        .assertThatLianaResponse()
        .andPrintTree()
        .hasStringContentEqualToAtPosition("$.responseCode", "200")
        .hasStringContentEqualToAtPosition(
            SERVICE + "[?(@.Name=='CardService')].Versions.Version[?(@.Version=='8.2.1')].Version",
            "8.2.1")
        .hasStringContentEqualToAtPosition(
            SERVICE
                + "[?(@.Name=='CardService')].Versions.Version[?(@.Version=='8.2.1')].Endpoint.Location",
            "http://liana:8080/ws/CardService");
  }
}

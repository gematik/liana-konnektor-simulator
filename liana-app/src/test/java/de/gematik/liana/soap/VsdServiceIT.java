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
package de.gematik.liana.soap;

import static de.gematik.liana.soap.EventServiceTest.bodyElement;
import static de.gematik.liana.soap.EventServiceTest.getCards;
import static de.gematik.liana.soap.EventServiceTest.xpath;
import static de.gematik.liana.soap.VsdServiceTest.gunzip;
import static de.gematik.liana.soap.VsdServiceTest.readVsd;
import static de.gematik.liana.soap.VsdServiceTest.verifyPin;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.TestPorts;
import io.quarkus.test.junit.QuarkusIntegrationTest;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;

/**
 * ReadVSD from the built artifact (LIANA-119 AC #4): with {@code -Dnative} (CI, native build)
 * against the native image from which the release image is built, with {@code ./mvnw verify
 * -DskipITs=false} against {@code quarkus-run.jar}. Cards from the boot YAML in kartos: egk-valid
 * in KT-01/1, smcb-valid in KT-01/2; the simulated PIN pad enters 123456.
 */
@QuarkusIntegrationTest
@TestProfile(TestPorts.Profile.class)
class VsdServiceIT {

  private static String cardHandle(String cardType) throws Exception {
    String xml =
        given()
            .contentType("text/xml; charset=utf-8")
            .header("SOAPAction", "\"http://ws.gematik.de/conn/EventService/v7.2#GetCards\"")
            .body(
                getCards(
                    "M1",
                    "CS1",
                    "WP1",
                    "<ns5:CtId>KT-01</ns5:CtId><ns5:CardType>" + cardType + "</ns5:CardType>"))
            .post("/ws/EventService")
            .then()
            .statusCode(200)
            .extract()
            .asString();
    return xpath(bodyElement(xml), "//*[local-name()='Card'][1]/*[local-name()='CardHandle']");
  }

  @Test
  @DisplayName(
      "VSDM-A_2567: VerifyPin PIN.SMC, dann ReadVSD → KVNR und Namen aus PD, Kostenträgerkennung aus VD")
  void readVsdAusDemArtefakt() throws Exception {
    String egk = cardHandle("EGK");
    String smcb = cardHandle("SMC-B");
    verifyPin(smcb);

    Element response = bodyElement(readVsd(egk, smcb, false).statusCode(200).extract().asString());
    String pd = gunzip(xpath(response, "//*[local-name()='PersoenlicheVersichertendaten']"));
    assertTrue(
        pd.contains("<Versicherten_ID>X110630769</Versicherten_ID>")
            && pd.contains("<Vorname>Dörthe Abigail</Vorname>")
            && pd.contains("<Nachname>Dåmmer-Ørsted</Nachname>"),
        pd);
    assertTrue(
        gunzip(xpath(response, "//*[local-name()='AllgemeineVersicherungsdaten']"))
            .contains("<Kostentraegerkennung>109500969</Kostentraegerkennung>"));
  }
}

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
import static de.gematik.liana.soap.SignDocumentKartosIT.TEXT;
import static de.gematik.liana.soap.SignDocumentKartosIT.base64Data;
import static de.gematik.liana.soap.SignDocumentKartosIT.cades;
import static de.gematik.liana.soap.SignDocumentKartosIT.post;
import static de.gematik.liana.soap.SignDocumentKartosIT.signDocument;
import static de.gematik.liana.soap.SignDocumentKartosIT.signed;
import static de.gematik.liana.soap.SignDocumentKartosIT.verify;
import static de.gematik.liana.soap.VsdServiceTest.verifyPin;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.gematik.liana.TestPorts;
import io.quarkus.test.junit.QuarkusIntegrationTest;
import io.quarkus.test.junit.TestProfile;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * SignDocument nonQES from the built artifact (LIANA-112.02 AC #4): with {@code -Dnative} against
 * the native image (BouncyCastle CMS, Qute template), otherwise against {@code quarkus-run.jar}.
 * smcb-valid from the boot YAML in kartos (KT-01/2), the simulated PIN pad enters 123456;
 * BouncyCastle verifies the signatures in the test.
 */
@QuarkusIntegrationTest
@TestProfile(TestPorts.Profile.class)
class SignDocumentIT {

  private static String smcb() throws Exception {
    String xml =
        given()
            .contentType("text/xml; charset=utf-8")
            .header("SOAPAction", "\"http://ws.gematik.de/conn/EventService/v7.2#GetCards\"")
            .body(
                getCards(
                    "M1",
                    "CS1",
                    "WP1",
                    "<ns5:CtId>KT-01</ns5:CtId><ns5:CardType>SMC-B</ns5:CardType>"))
            .post("/ws/EventService")
            .then()
            .statusCode(200)
            .extract()
            .asString();
    return xpath(bodyElement(xml), "//*[local-name()='Card'][1]/*[local-name()='CardHandle']");
  }

  @Test
  @DisplayName(
      "TIP1-A_5010-11 / TUC_KON_160: CAdES enveloping und (Default, TAB_KON_583) detached mit "
          + "PrK.HCI.OSIG.E256, beide gültig; SignaturePlacement → Warnung 4197")
  void cadesAusDemArtefakt() throws Exception {
    String smcb = smcb();
    verifyPin(smcb);
    CMSSignedData enveloping =
        signed(
            post(
                signDocument(
                    smcb,
                    "NAT-001",
                    cades(true),
                    base64Data("text/plain; charset=utf-8", TEXT),
                    false),
                200),
            "OK");
    assertArrayEquals(TEXT, (byte[]) enveloping.getSignedContent().getContent());
    verify(enveloping);

    CMSSignedData detached =
        signed(
            post(signDocument(smcb, "NAT-002", "", base64Data("text/plain", TEXT), false), 200),
            "OK");
    verify(new CMSSignedData(new CMSProcessableByteArray(TEXT), detached.getEncoded()));

    String warning =
        xpath(
            post(
                signDocument(
                    smcb,
                    "NAT-003",
                    cades(true)
                        + "<ns3:SignaturePlacement "
                        + "WhichDocument=\"DokumentID\"><ns3:XPathFirstChildOf>/*</ns3:XPathFirstChildOf>"
                        + "</ns3:SignaturePlacement>",
                    base64Data("text/plain", TEXT),
                    false),
                200),
            "//*[local-name()='Trace']/*[local-name()='Code']");
    assertEquals("4197", warning);
  }
}

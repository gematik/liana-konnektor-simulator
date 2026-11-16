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

import static de.gematik.liana.soap.AuthSignatureServiceTest.HASH;
import static de.gematik.liana.soap.AuthSignatureServiceTest.cAut;
import static de.gematik.liana.soap.AuthSignatureServiceTest.externalAuthenticate;
import static de.gematik.liana.soap.AuthSignatureServiceTest.verifyPin;
import static de.gematik.liana.soap.EventServiceTest.bodyElement;
import static de.gematik.liana.soap.EventServiceTest.getCards;
import static de.gematik.liana.soap.EventServiceTest.xpath;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.TestPorts;
import de.gematik.liana.crypto.TestP12;
import io.quarkus.test.junit.QuarkusIntegrationTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;

/**
 * LIANA-220 from the built artifact: with {@code -Dnative} against the native image, otherwise
 * against {@code quarkus-run.jar}. The PKCS#12 is written by BC like the gematik test SMC-B
 * (certificates PBEWithSHAAnd40BitRC2-CBC, key 3DES), password 00; KT-02/1 selects it by name.
 */
@QuarkusIntegrationTest
@TestProfile(P12SmcbIT.P12Folder.class)
class P12SmcbIT {

  static final Path FOLDER;

  static {
    try {
      FOLDER = Files.createTempDirectory("liana-220-it-");
      TestP12.write(FOLDER.resolve("smcb_private.p12"), "00", "1-SMC-B-Testkarte--883110000999940");
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  /** The p12 folder behind the shipped image folders, KT-02/1 from the p12. */
  public static class P12Folder implements QuarkusTestProfile {
    @Override
    public Map<String, String> getConfigOverrides() {
      return TestPorts.config(
          "liana.card-images",
          "./support/images,./support/images/gsmc-kt,./support/images/g20,./support/images/gsmc-k,"
              + "./support/images/kvk,"
              + FOLDER,
          "liana.infrastructure.terminals.KT-02.slots.1",
          "smcb_private");
    }
  }

  @Test
  @DisplayName(
      "LIANA-220 SMC-B aus PKCS#12 im Artefakt: GetCards KT-02 SMC-B mit ICCSN nach Regel A,"
          + " C.AUT gleich dem Zertifikat der p12, ExternalAuthenticate prüfbar, GET /admin/images"
          + " listet die p12")
  void smcbAusP12() throws Exception {
    Element cards =
        bodyElement(
            given()
                .contentType("text/xml; charset=utf-8")
                .header("SOAPAction", "\"http://ws.gematik.de/conn/EventService/v7.2#GetCards\"")
                .body(
                    getCards(
                        "M1",
                        "CS1",
                        "WP1",
                        "<ns5:CtId>KT-02</ns5:CtId><ns5:CardType>SMC-B</ns5:CardType>"))
                .post("/ws/EventService")
                .then()
                .statusCode(200)
                .extract()
                .asString());
    assertEquals(
        "80276883110000999940",
        xpath(cards, "//*[local-name()='Card'][1]/*[local-name()='Iccsn']"));
    String smcb = xpath(cards, "//*[local-name()='Card'][1]/*[local-name()='CardHandle']");

    verifyPin(smcb);
    Element response =
        bodyElement(
            externalAuthenticate(smcb, HASH, "application/octet-stream")
                .statusCode(200)
                .extract()
                .asString());

    X509Certificate certificate = TestP12.certificate(FOLDER.resolve("smcb_private.p12"), "00");
    assertArrayEquals(certificate.getEncoded(), cAut(smcb).getEncoded());
    Signature verify = Signature.getInstance("NONEwithECDSA", "BC");
    verify.initVerify(certificate);
    verify.update(Base64.getDecoder().decode(HASH));
    assertTrue(
        verify.verify(
            Base64.getDecoder().decode(xpath(response, "//*[local-name()='Base64Signature']"))));
    given()
        .port(TestPorts.ADMIN)
        .get("/admin/images")
        .then()
        .statusCode(200)
        .body("images.file", hasItem(FOLDER.resolve("smcb_private.p12").toString()));
  }
}

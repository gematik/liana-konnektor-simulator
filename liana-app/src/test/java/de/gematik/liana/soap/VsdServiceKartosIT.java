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
import static de.gematik.liana.soap.EventServiceTest.xpath;
import static de.gematik.liana.soap.VsdServiceTest.gunzip;
import static de.gematik.liana.soap.VsdServiceTest.readVsd;
import static de.gematik.liana.soap.VsdServiceTest.verifyPin;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.admin.AdminServer;
import de.gematik.liana.kern.card.CardList;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Element;

/**
 * ReadVSD without Onlineprüfung (LIANA-119) against cards in kartos: egk-valid in KT-01/1,
 * smcb-valid in KT-01/2. After each test {@code POST /admin/reset}.
 */
@QuarkusTest
@TestProfile(PinPadKartosIT.KartosCards.class)
class VsdServiceKartosIT {

  @Inject AdminServer admin;

  @Inject CardList cards;

  @TempDir Path images;

  @AfterEach
  void reset() {
    given().port(admin.port()).post("/admin/reset").then().statusCode(200);
  }

  private String egk() {
    return cards.card("KT-01", 1).orElseThrow().cardHandle();
  }

  private String smcb() {
    return cards.card("KT-01", 2).orElseThrow().cardHandle();
  }

  @Test
  @DisplayName(
      "VSDM-A_2567: ReadVSD nach VerifyPin PIN.SMC (PIN-Pad, Script correct) liefert die PD und VD der "
          + "eGK in kartos")
  void pdUndVd() throws Exception {
    given()
        .port(admin.port())
        .contentType("application/json")
        .body("[{\"outcome\":\"correct\"}]")
        .post("/admin/terminals/KT-01/pin-script")
        .then()
        .statusCode(200);
    verifyPin(smcb());

    Element response =
        bodyElement(readVsd(egk(), smcb(), false).statusCode(200).extract().asString());
    assertTrue(
        gunzip(xpath(response, "//*[local-name()='PersoenlicheVersichertendaten']"))
            .contains("<Versicherten_ID>X110630769</Versicherten_ID>"));
    assertTrue(
        gunzip(xpath(response, "//*[local-name()='AllgemeineVersicherungsdaten']"))
            .contains("<Kostentraegerkennung>109500969</Kostentraegerkennung>"));
  }

  @Test
  @DisplayName(
      "VSDM-A_2568 / TUC_KON_018: DF.HCA im Image deaktiviert (kartos: SELECT → 6283) → 114, ohne "
          + "freigeschaltete SM-B")
  void gesperrteGesundheitsanwendung() throws Exception {
    String xml = Files.readString(Path.of("support/images/egk-valid.xml"), StandardCharsets.UTF_8);
    String activated = "<attribute id=\"lifeCycleStatus\">ACTIVATED</attribute>";
    int status = xml.indexOf(activated, xml.indexOf("<child id=\"DF.HCA\""));
    Path image = images.resolve("egk-hca-deactivated.xml");
    Files.writeString(
        image,
        xml.substring(0, status)
            + activated.replace("ACTIVATED", "DEACTIVATED")
            + xml.substring(status + activated.length()),
        StandardCharsets.UTF_8);
    given().port(admin.port()).delete("/admin/terminals/KT-01/slots/1").then().statusCode(200);
    given()
        .port(admin.port())
        .contentType("application/json")
        .body(Map.of("image", image.toString()))
        .put("/admin/terminals/KT-01/slots/1")
        .then()
        .statusCode(200);

    Element fault = bodyElement(readVsd(egk(), smcb(), false).statusCode(500).extract().asString());
    assertEquals("114", xpath(fault, "//*[local-name()='Code']"));
  }
}

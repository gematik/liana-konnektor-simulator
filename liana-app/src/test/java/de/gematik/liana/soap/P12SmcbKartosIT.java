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
import static de.gematik.liana.soap.EventServiceTest.xpath;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.admin.AdminServer;
import de.gematik.liana.crypto.TestP12;
import de.gematik.liana.kern.card.CardData;
import de.gematik.liana.kern.card.CardList;
import de.gematik.liana.kern.card.CardType;
import de.gematik.liana.wiring.RecordedCardEngine;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Signature;
import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;

/**
 * LIANA-220: SMC-B from a PKCS#12 in kartos. A folder in {@code liana.card-images} holds {@code
 * smcb_private.p12} (password 00, Telematik-ID by rule A) and {@code kaputt.p12} (password not in
 * the list); KT-02/1 selects the first by name, as the Testhub release does.
 */
@QuarkusTest
@TestProfile(P12SmcbKartosIT.P12Folder.class)
class P12SmcbKartosIT {

  static final Path FOLDER;
  static final String TELEMATIK_ID = "1-SMC-B-Testkarte--883110000999920";

  static {
    try {
      FOLDER = Files.createTempDirectory("liana-220-");
      TestP12.write(FOLDER.resolve("smcb_private.p12"), "00", TELEMATIK_ID);
      TestP12.write(FOLDER.resolve("kaputt.p12"), "geheim-220", TELEMATIK_ID);
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  /** Cards in kartos, the p12 folder behind the shipped image folders, KT-02/1 from the p12. */
  public static class P12Folder implements QuarkusTestProfile {
    @Override
    public Map<String, String> getConfigOverrides() {
      return Map.of(
          RecordedCardEngine.KARTOS,
          "kartos",
          "liana.card-images",
          "./support/images,./support/images/gsmc-kt,./support/images/g20,./support/images/gsmc-k,"
              + "./support/images/kvk,"
              + FOLDER,
          "liana.infrastructure.terminals.KT-02.slots.1",
          "smcb_private");
    }
  }

  @Inject CardList cards;

  @Inject AdminServer admin;

  @AfterEach
  void reset() {
    given().port(admin.port()).post("/admin/reset").then().statusCode(200);
  }

  @Test
  @DisplayName(
      "LIANA-220 SMC-B aus PKCS#12: GetCards SMC-B mit ICCSN nach Regel A, VerifyPin PIN.SMC,"
          + " ReadCardCertificate C.AUT gleich dem Zertifikat der p12, ExternalAuthenticate prüfbar"
          + " mit dessen Schlüssel")
  void smcbAusP12() throws Exception {
    CardData data = cards.card("KT-02", 1).orElseThrow().data();
    assertEquals(CardType.SMC_B, data.type());
    assertEquals("80276883110000999920", data.iccsn());
    String smcb = cards.card("KT-02", 1).orElseThrow().cardHandle();

    verifyPin(smcb);
    Element response =
        bodyElement(
            externalAuthenticate(smcb, HASH, "application/octet-stream")
                .statusCode(200)
                .extract()
                .asString());

    var certificate = TestP12.certificate(FOLDER.resolve("smcb_private.p12"), "00");
    assertArrayEquals(certificate.getEncoded(), cAut(smcb).getEncoded());
    Signature verify = Signature.getInstance("NONEwithECDSA", "BC");
    verify.initVerify(certificate);
    verify.update(Base64.getDecoder().decode(HASH));
    assertTrue(
        verify.verify(
            Base64.getDecoder().decode(xpath(response, "//*[local-name()='Base64Signature']"))),
        "Signatur passt zum Zertifikat der p12");
  }

  @Test
  @DisplayName(
      "LIANA-220 Admin-API: GET /admin/images listet die p12 mit ihrem Pfad und der ICCSN; PUT"
          + " steckt sie per Name, eine unbrauchbare p12 ergibt 400 mit Datei und Grund")
  void adminApi() {
    given()
        .port(admin.port())
        .get("/admin/images")
        .then()
        .statusCode(200)
        .body("images.name", hasItem("smcb_private"))
        .body("images.file", hasItem(FOLDER.resolve("smcb_private.p12").toString()))
        .body("images.iccsn", hasItem("80276883110000999920"));

    given()
        .port(admin.port())
        .contentType("application/json")
        .body("{\"image\": \"smcb_private.p12\"}")
        .put("/admin/terminals/KT-02/slots/2")
        .then()
        .statusCode(200);
    assertEquals(CardType.SMC_B, cards.card("KT-02", 2).orElseThrow().data().type());

    given()
        .port(admin.port())
        .contentType("application/json")
        .body("{\"image\": \"kaputt\"}")
        .put("/admin/terminals/KT-02/slots/2")
        .then()
        .statusCode(400)
        .body(
            "error",
            startsWith(
                "KT-02/2: "
                    + FOLDER.resolve("kaputt.p12")
                    + ": keine lesbare PKCS#12, keins der 7"));
  }
}

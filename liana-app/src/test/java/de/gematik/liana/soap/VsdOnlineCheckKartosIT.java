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
import static de.gematik.liana.soap.VsdServiceTest.pruefungsnachweis;
import static de.gematik.liana.soap.VsdServiceTest.readVsd;
import static de.gematik.liana.soap.VsdServiceTest.verifyPin;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.TestPorts;
import de.gematik.liana.admin.AdminServer;
import de.gematik.liana.crypto.TlsStubServer;
import de.gematik.liana.kern.card.CardList;
import de.gematik.liana.wiring.RecordedCardEngine;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Onlineprüfung over HTTPS (LIANA-141, TUC_KON_110) against kartos: the stub UFS ({@link
 * TlsStubServer}, C.FD.TLS-S from a throwaway CA in {@code liana.pki.imported-cas}) requires a
 * client certificate; LIANA authenticates with C.HCI.AUT of smcb-valid in KT-01/2 and lets kartos
 * sign the handshake hash (PSO COMPUTE DIGITAL SIGNATURE).
 */
@QuarkusTest
@TestProfile(VsdOnlineCheckKartosIT.Profile.class)
class VsdOnlineCheckKartosIT {

  static final String RECEIPT = "UHLDvGZ6aWZmZXIgZGVzIFVGUw==";
  static final TlsStubServer UFS =
      TlsStubServer.start(
          TestPorts.UFS,
          request ->
              """
            <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>\
            <r:GetUpdateFlagsResponse xmlns:r="http://ws.gematik.de/cm/uf/CmUfServiceResponse/v2.0" \
            xmlns:CM="http://ws.gematik.de/cm/common/CmCommon/v2.0"><CM:ServiceReceipt><CM:ServiceLocalization>\
            <CM:Type>UFS</CM:Type><CM:Provider>109500969</CM:Provider></CM:ServiceLocalization>\
            <CM:Receipt>%s</CM:Receipt></CM:ServiceReceipt></r:GetUpdateFlagsResponse></soap:Body>\
            </soap:Envelope>"""
                  .formatted(RECEIPT));

  public static class Profile implements QuarkusTestProfile {
    @Override
    public Map<String, String> getConfigOverrides() {
      Path ca;
      try {
        ca = UFS.writeCa(Files.createTempFile("liana-ufs-ca", ".pem"));
      } catch (IOException e) {
        throw new IllegalStateException(e);
      }
      return Map.of(
          RecordedCardEngine.KARTOS,
          "kartos",
          "liana.pki.imported-cas",
          "./support/pki/replay/replay-ca.pem," + ca,
          "liana.vsdm.online.sources",
          "ufs",
          "liana.vsdm.online.ufs.endpoints[0].url",
          "https://localhost:" + UFS.port() + "/ufs",
          "liana.vsdm.online.ufs.retry-after",
          "0s");
    }
  }

  @Inject AdminServer admin;

  @Inject CardList cards;

  @AfterEach
  void reset() {
    given().port(admin.port()).post("/admin/reset").then().statusCode(200);
  }

  @Test
  @DisplayName(
      "TIP1-A_4720-03 / Tab_FM_VSDM_15: GetUpdateFlags über TLS mit C.HCI.AUT der SM-B, Signatur von kartos; "
          + "Ergebnis 2 mit der Prüfziffer des UFS")
  void https() throws Exception {
    given()
        .port(admin.port())
        .contentType("application/json")
        .body("[{\"outcome\":\"correct\"}]")
        .post("/admin/terminals/KT-01/pin-script")
        .then()
        .statusCode(200);
    String egk = cards.card("KT-01", 1).orElseThrow().cardHandle();
    String smcb = cards.card("KT-01", 2).orElseThrow().cardHandle();
    verifyPin(smcb);

    String pn =
        pruefungsnachweis(
            bodyElement(readVsd(egk, smcb, true, true).statusCode(200).extract().asString()));

    assertTrue(pn.contains("<E>2</E><PZ>" + RECEIPT + "</PZ>"), pn);
    X509Certificate client =
        (X509Certificate)
            CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(UFS.clientCertificate()));
    String holder = cards.card("KT-01", 2).orElseThrow().data().cardHolderName();
    assertTrue(
        client.getSubjectX500Principal().getName().contains("CN=" + holder),
        client.getSubjectX500Principal().getName());
    assertEquals(1, UFS.requests().size());
    given()
        .port(admin.port())
        .get("/admin/vsdm/online-checks")
        .then()
        .body("checks.find { it.cardHandle == '" + egk + "' }.source", equalTo("ufs"));
  }
}

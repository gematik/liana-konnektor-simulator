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

import static de.gematik.liana.soap.EventServiceTest.xpath;
import static de.gematik.liana.soap.SignDocumentKartosIT.TEXT;
import static de.gematik.liana.soap.SignDocumentKartosIT.base64Data;
import static de.gematik.liana.soap.SignDocumentKartosIT.cades;
import static de.gematik.liana.soap.SignDocumentKartosIT.post;
import static de.gematik.liana.soap.SignDocumentKartosIT.signDocument;
import static de.gematik.liana.soap.SignDocumentKartosIT.verify;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.admin.AdminServer;
import de.gematik.liana.kern.card.CardList;
import de.gematik.liana.kern.management.ComfortSettings;
import de.gematik.liana.kern.management.ManagementSettings;
import de.gematik.liana.wiring.ObservedKartos;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.bouncycastle.cms.CMSSignedData;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;

/**
 * QES batch in SE #2 over trusted channels against kartos (LIANA-112.13): hba-valid in KT-01/3, the
 * gSMC-KT of the KT ({@code gsmckt-root6}) for PIN.QES in the remote PIN procedure, the gSMC-K
 * ({@code gsmc-k.image: gsmc-k} of application.yaml) for PSO CDS. {@link ObservedKartos} records
 * the APDUs to the HBA.
 */
@QuarkusTest
@TestProfile(TrustedChannelSignatureKartosIT.Profile.class)
class TrustedChannelSignatureKartosIT {

  public static class Profile implements QuarkusTestProfile {
    @Override
    public Set<Class<?>> getEnabledAlternatives() {
      return Set.of(ObservedKartos.class);
    }
  }

  private static final String HBA = "hba-valid";
  private static final String SIGN_RESPONSE = "(//*[local-name()='SignResponse'])[%d]";

  /** MSE RESTORE SE #2 (gemSpec_COS CosT_6fc). */
  private static final String RESTORE_SE2 = "0022F302";

  /**
   * MSE SET AT elcSessionkey4SM with PrK.HPC.AUTD_SUK_CVC.E256 (TUC_KON_005, TAB_KON_674 tKeyRef).
   */
  private static final String SET_AT = "002241A406840109800154";

  /** READ BINARY EF.C.HPC.AUTD_SUK_CVC.E256 via SFI. */
  private static final String READ_SUK_CVC = "00B08900";

  private static int jobs;

  @Inject AdminServer admin;

  @Inject CardList cards;

  @Inject ManagementSettings settings;

  @Inject ObservedKartos kartos;

  @Inject ComfortSettings comfort;

  @BeforeEach
  void online() {
    settings.online(true);
    kartos.take(HBA);
  }

  @AfterEach
  void reset() {
    comfort.enabled(false);
    given().port(admin.port()).post("/admin/reset").then().statusCode(200);
  }

  private String hba() {
    return cards.card("KT-01", 3).orElseThrow().cardHandle();
  }

  /**
   * SignDocument with {@code n} SignRequests R1…Rn over the same text, CAdES enveloping
   * (KUC_1602_070).
   */
  private String batch(int n) {
    String one =
        signDocument(
            hba(),
            "TCH-%03d".formatted(++jobs),
            cades(true),
            base64Data("text/plain; charset=utf-8", TEXT),
            false);
    int start = one.indexOf("<ns4:SignRequest ");
    int end = one.indexOf("</ns4:SignRequest>") + "</ns4:SignRequest>".length();
    StringBuilder requests = new StringBuilder();
    for (int i = 1; i <= n; i++) {
      requests.append(
          one.substring(start, end)
              .replace("RequestID=\"RequestID\"", "RequestID=\"R" + i + "\"")
              .replace("ID=\"DokumentID\"", "ID=\"D" + i + "\""));
    }
    return one.substring(0, start) + requests + one.substring(end);
  }

  private static void assertSigned(Element response, int n) throws Exception {
    for (int i = 1; i <= n; i++) {
      String r = SIGN_RESPONSE.formatted(i);
      assertEquals(
          "OK",
          xpath(response, r + "//*[local-name()='Result']"),
          xpath(response, "//*[local-name()='ErrorText']"));
      verify(
          new CMSSignedData(
              Base64.getDecoder()
                  .decode(xpath(response, r + "//*[local-name()='Base64Signature']"))));
    }
  }

  private static List<String> commands(List<String[]> apdus) {
    return apdus.stream().map(apdu -> apdu[0]).toList();
  }

  private static int count(List<String> commands, String prefix) {
    return (int) commands.stream().filter(command -> command.startsWith(prefix)).count();
  }

  @Test
  @DisplayName(
      "TIP1-A_4651-03 TUC_KON_154 Stapel: SE #2, PIN.QES im Remote-PIN-Verfahren über die gSMC-KT "
          + "(TIP1-A_5012), TUC_KON_005 gSMC-K↔HBA, PSO CDS unter Secure Messaging, eine PIN.QES für drei Signaturen")
  void stapelImSe2() throws Exception {
    assertSigned(post(batch(3), 200), 3);
    List<String[]> apdus = kartos.take(HBA);
    List<String> commands = commands(apdus);
    int restore = commands.indexOf(RESTORE_SE2);
    assertTrue(restore >= 0, "MSE RESTORE SE #2: " + commands);
    assertEquals(2, count(commands, SET_AT), "zwei C2C: gSMC-KT, dann gSMC-K");
    assertEquals(1, count(commands, "0C2000"), "eine PIN.QES, VERIFY unter Secure Messaging");
    assertEquals(0, count(commands, "002000"), "kein VERIFY ohne Secure Messaging");
    assertEquals(3, count(commands, "0C2A9E9A"), "drei PSO CDS unter Secure Messaging");
    assertEquals(0, count(commands, "002A9E9A"), "kein PSO CDS ohne Secure Messaging");
    apdus.stream()
        .filter(apdu -> apdu[0].startsWith("0C"))
        .forEach(
            apdu ->
                assertTrue(
                    apdu[1].endsWith("9000"), "gesichertes Kommando " + apdu[0] + " → " + apdu[1]));
  }

  @Test
  @DisplayName(
      "TUC_KON_154 Sicherheitsanforderungen: DF.QES bleibt zwischen C2C und Signatur gewählt, das CVC des HBA "
          + "liest LIANA vor DF.QES und nur einmal je Kartensitzung")
  void dfQesBleibtCvcGecacht() throws Exception {
    assertSigned(post(batch(2), 200), 2);
    List<String> first = commands(kartos.take(HBA));
    int read = first.indexOf(READ_SUK_CVC + "000000");
    // TUC_KON_150 steps 6 and 7: the last SELECT DF.QES before PIN and signature
    int qes = first.lastIndexOf("00A4040C06D27600006601");
    assertTrue(read >= 0 && read < qes, "EF.C.HPC.AUTD_SUK_CVC.E256 vor DF.QES: " + first);
    int lastSignature =
        first.lastIndexOf(
            first.stream().filter(c -> c.startsWith("0C2A9E9A")).reduce((a, b) -> b).orElseThrow());
    List<String> between = first.subList(qes + 1, lastSignature);
    assertFalse(
        between.stream().anyMatch(command -> command.startsWith("00A4")),
        "kein SELECT zwischen DF.QES und letzter Signatur: " + between);

    assertSigned(post(batch(2), 200), 2);
    assertEquals(
        0, count(commands(kartos.take(HBA)), READ_SUK_CVC), "zweiter Auftrag: CVC aus dem Cache");
  }

  @Test
  @DisplayName(
      "SAK_SIMPLE_SIGNATURE_MODE = SE#1 (TAB_KON_596): ein Dokument nach TUC_KON_168 ohne C2C und ohne "
          + "Secure Messaging")
  void einDokumentImSe1() throws Exception {
    assertSigned(post(batch(1), 200), 1);
    List<String> commands = commands(kartos.take(HBA));
    assertEquals(0, count(commands, RESTORE_SE2));
    assertEquals(1, count(commands, "002A9E9A"));
  }

  @Test
  @DisplayName(
      "A_19104-05 TUC_KON_171: PIN.QES im SE #2 über die gSMC-KT; A_19102-05 TUC_KON_158 Schritt 1 / A_19258: "
          + "je SignDocument ein Trusted Channel gSMC-K↔HBA, PSO CDS unter Secure Messaging, keine weitere PIN")
  void komfortImSe2() throws Exception {
    comfort.enabled(true);
    String context =
        DocumentOperationsTest.context("M1", "CS1", "WP1", UUID.randomUUID().toString());
    String activate =
        """
                <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Header/>\
                <SOAP-ENV:Body><ns4:ActivateComfortSignature xmlns:ns2="http://ws.gematik.de/conn/ConnectorCommon/v5.0" \
                xmlns:ns4="http://ws.gematik.de/conn/SignatureService/v7.5"><ns2:CardHandle>%s</ns2:CardHandle>%s\
                </ns4:ActivateComfortSignature></SOAP-ENV:Body></SOAP-ENV:Envelope>"""
            .formatted(hba(), context);
    given()
        .contentType("text/xml; charset=utf-8")
        .header(
            "SOAPAction",
            "\"http://ws.gematik.de/conn/SignatureService/v7.5#ActivateComfortSignature\"")
        .body(activate)
        .post("/ws/SignatureService")
        .then()
        .statusCode(200);
    List<String> activation = commands(kartos.take(HBA));
    assertEquals(1, count(activation, RESTORE_SE2), activation::toString);
    assertEquals(1, count(activation, "0C2000"), "PIN.QES im Kanal gSMC-KT↔HBA: " + activation);

    for (int i = 0; i < 2; i++) {
      String body = batch(1).replace(SignDocumentKartosIT.CONTEXT, context);
      assertSigned(post(body, 200), 1);
      List<String> commands = commands(kartos.take(HBA));
      assertEquals(1, count(commands, SET_AT), "C2C gSMC-K↔HBA je Auftrag: " + commands);
      assertEquals(1, count(commands, "0C2A9E9A"), commands::toString);
      assertEquals(
          0, count(commands, "0C2000") + count(commands, "002000"), "keine PIN: " + commands);
      assertEquals(0, count(commands, RESTORE_SE2), "SE #2 bleibt: " + commands);
    }
  }
}

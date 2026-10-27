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

import static de.gematik.liana.soap.EventServiceTest.serialize;
import static de.gematik.liana.soap.EventServiceTest.xpath;
import static de.gematik.liana.soap.SignDocumentKartosIT.TEXT;
import static de.gematik.liana.soap.SignDocumentKartosIT.assertFault;
import static de.gematik.liana.soap.SignDocumentKartosIT.base64Data;
import static de.gematik.liana.soap.SignDocumentKartosIT.cades;
import static de.gematik.liana.soap.SignDocumentKartosIT.signDocument;
import static de.gematik.liana.soap.SignDocumentKartosIT.signed;
import static de.gematik.liana.soap.SignDocumentKartosIT.verify;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.ShiftableClock;
import de.gematik.liana.adapter.fake.FakeTerminal;
import de.gematik.liana.adapter.fake.FakeTerminals;
import de.gematik.liana.adapter.fake.PinInput;
import de.gematik.liana.admin.AdminServer;
import de.gematik.liana.kern.card.CardList;
import de.gematik.liana.kern.event.SystemLog;
import de.gematik.liana.kern.management.ClientSystemBinding;
import de.gematik.liana.kern.management.ComfortSettings;
import de.gematik.liana.kern.management.ManagementSettings;
import de.gematik.liana.kern.vendor.PeerDeviations;
import de.gematik.liana.sds.XsdValidator;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;

/**
 * Komfortsignatur (LIANA-112.06) against kartos: hba-valid in KT-01/3, requests like
 * konnektor-service-client 1.6.2 in Konnektor-QES KUC_1608_*, responses against
 * SignatureService_V7_5_6.xsd. A listener on the display of the fake KT counts the PIN entries;
 * {@link ShiftableClock} advances the Komfortsignatur timer.
 */
@QuarkusTest
@TestProfile(SignDocumentKartosIT.Profile.class)
class ComfortSignatureKartosIT {

  private static final String SIG = "http://ws.gematik.de/conn/SignatureService/v7.5";
  private static final String COMFORT_PROMPT =
      "Komfortsignatur \u000Baktivieren \u000BHBA\u000FPIN.QES:";
  private static final String XSD = "conn/SignatureService_V7_5_6.xsd";
  private static int jobs;

  @Inject AdminServer admin;

  @Inject CardList cards;

  @Inject FakeTerminals terminals;

  @Inject ManagementSettings settings;

  @Inject ComfortSettings comfort;

  @Inject ClientSystemBinding binding;

  @Inject PeerDeviations deviations;

  @Inject SystemLog systemLog;

  @Inject ShiftableClock clock;

  /**
   * Every prompt for PIN.QES; the PIN pad waits (mode await), the listener types the correct PIN.
   */
  private static final List<String> prompts = new CopyOnWriteArrayList<>();

  private static boolean listening;

  /**
   * The listener stays on the KT of the Quarkus application; it only types while a test of this
   * class is running.
   */
  private static volatile boolean active;

  private String userId;

  @BeforeEach
  void enable() {
    settings.online(true);
    prompts.clear();
    if (!listening) {
      listening = true;
      kt().addDisplayListener(
              display ->
                  display
                      .filter(d -> active && d.endsWith("PIN.QES:"))
                      .ifPresent(
                          prompt -> {
                            prompts.add(prompt);
                            kt().enterPin(3, PinInput.of(PinInput.Outcome.CORRECT));
                          }));
    }
    active = true;
    kt().awaitPinInput(true);
    comfort.enabled(true);
    userId = UUID.randomUUID().toString();
  }

  @AfterEach
  void reset() {
    active = false;
    kt().awaitPinInput(false);
    given().port(admin.port()).post("/admin/reset").then().statusCode(200);
  }

  private FakeTerminal kt() {
    return terminals.terminal("KT-01");
  }

  private String hba() {
    return cards.card("KT-01", 3).orElseThrow().cardHandle();
  }

  private String context() {
    return DocumentOperationsTest.context("M1", "CS1", "WP1", userId);
  }

  private static Element call(String operation, String inner, int status) throws Exception {
    String body =
        """
                <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Header/>\
                <SOAP-ENV:Body><ns4:%s xmlns:ns2="http://ws.gematik.de/conn/ConnectorCommon/v5.0" xmlns:ns4="%s">%s\
                </ns4:%s></SOAP-ENV:Body></SOAP-ENV:Envelope>"""
            .formatted(operation, SIG, inner, operation);
    String xml =
        given()
            .contentType("text/xml; charset=utf-8")
            .header("SOAPAction", "\"" + SIG + "#" + operation + "\"")
            .body(body)
            .post("/ws/SignatureService")
            .then()
            .statusCode(status)
            .extract()
            .asString();
    Element response = EventServiceTest.bodyElement(xml);
    if (status == 200) {
      XsdValidator.validate(XSD, serialize(response));
    }
    return response;
  }

  private Element activate(int status) throws Exception {
    return call(
        "ActivateComfortSignature",
        "<ns2:CardHandle>" + hba() + "</ns2:CardHandle>" + context(),
        status);
  }

  private Element deactivate(String... cardHandles) throws Exception {
    StringBuilder inner = new StringBuilder();
    for (String cardHandle : cardHandles) {
      inner.append("<ns2:CardHandle>").append(cardHandle).append("</ns2:CardHandle>");
    }
    return call("DeactivateComfortSignature", inner.toString(), 200);
  }

  private Element mode() throws Exception {
    return call(
        "GetSignatureMode", "<ns2:CardHandle>" + hba() + "</ns2:CardHandle>" + context(), 200);
  }

  /** SignDocument CAdES enveloping (KUC_1608_021) with the UserId of the test. */
  private Element sign(int requests, int status) throws Exception {
    String one =
        signDocument(
                hba(),
                "KOM-%03d".formatted(++jobs),
                cades(true),
                base64Data("text/plain; charset=utf-8", TEXT),
                false)
            .replace(SignDocumentKartosIT.CONTEXT, context());
    int start = one.indexOf("<ns4:SignRequest ");
    int end = one.indexOf("</ns4:SignRequest>") + "</ns4:SignRequest>".length();
    if (requests == 1) {
      return SignDocumentKartosIT.post(one, status);
    }
    StringBuilder batch = new StringBuilder();
    for (int i = 1; i <= requests; i++) {
      batch.append(
          one.substring(start, end)
              .replace("RequestID=\"RequestID\"", "RequestID=\"R" + i + "\"")
              .replace("ID=\"DokumentID\"", "ID=\"D" + i + "\""));
    }
    return SignDocumentKartosIT.post(one.substring(0, start) + batch + one.substring(end), status);
  }

  private static String text(Element element, String name) throws Exception {
    return xpath(element, "//*[local-name()='" + name + "']");
  }

  @Test
  @DisplayName(
      "A_19107-01 ActivateComfortSignature, TUC_KON_171 / A_19109-02 GetSignatureMode, TUC_KON_173 / "
          + "A_19103-08 TUC_KON_170: einmal PIN.QES mit „Komfortsignatur aktivieren“ (TAB_KON_090), dann signiert der "
          + "HBA ohne PIN, CountRemaining zählt herunter; A_19108 DeactivateComfortSignature: danach wieder PIN.QES "
          + "(KUC_1608_021)")
  void einschaltenSignierenAusschalten() throws Exception {
    Element before = mode();
    assertEquals("ENABLED", text(before, "ComfortSignatureStatus"));
    assertEquals("100", text(before, "ComfortSignatureMax"));
    assertEquals("PT6H", text(before, "ComfortSignatureTimer"));
    assertEquals("0", xpath(before, "count(//*[local-name()='SessionInfo'])"));

    Element activated = activate(200);
    assertEquals("OK", text(activated, "Result"));
    assertEquals("COMFORT", text(activated, "SignatureMode"));
    assertEquals(List.of(COMFORT_PROMPT), prompts);

    Element session = mode();
    assertEquals("COMFORT", text(session, "SignatureMode"));
    assertEquals("100", text(session, "CountRemaining"));
    Duration left = Duration.parse(text(session, "TimeRemaining"));
    assertTrue(
        left.compareTo(Duration.ofHours(6)) <= 0 && left.compareTo(Duration.ofHours(5)) > 0,
        left::toString);

    for (int i = 0; i < 2; i++) {
      verify(signed(sign(1, 200), "OK"));
    }
    assertEquals(1, prompts.size(), "keine weitere PIN-Eingabe: " + prompts);
    assertEquals("98", text(mode(), "CountRemaining"));

    Element deactivated = deactivate(hba());
    assertEquals("OK", text(deactivated, "Result"));
    assertEquals("0", xpath(mode(), "count(//*[local-name()='SessionInfo'])"));
    verify(signed(sign(1, 200), "OK"));
    assertEquals(2, prompts.size(), "nach dem Ausschalten wieder PIN.QES: " + prompts);
    assertEquals(COMFORT_PROMPT, prompts.get(0));
    assertTrue(prompts.get(1).contains("SignaturPIN"), prompts.get(1));
  }

  @Test
  @DisplayName("A_19102-05 TUC_KON_158 Stapel im Komfortsignaturmodus ohne PIN (KUC_1608_037)")
  void stapel() throws Exception {
    activate(200);
    Element response = sign(3, 200);
    assertEquals(
        "3",
        xpath(
            response, "count(//*[local-name()='SignResponse'][.//*[local-name()='Result']='OK'])"));
    assertEquals(1, prompts.size(), prompts::toString);
    assertEquals("97", text(mode(), "CountRemaining"));
  }

  @Test
  @DisplayName(
      "A_19100-01 Komfortsignatur-Zähler: nach SAK_COMFORT_SIGNATURE_MAX = 2 endet die dritte Signatur mit "
          + "4271, TUC_KON_172 beendet die Session, DeactivateComfortSignature danach OK (KUC_1608_024)")
  void zaehler() throws Exception {
    comfort.max(2);
    activate(200);
    verify(signed(sign(1, 200), "OK"));
    verify(signed(sign(1, 200), "OK"));
    assertEquals("0", text(mode(), "CountRemaining"));
    Element fault = sign(1, 500);
    assertFault(fault, "4271", "Technical", "Komfortsignaturmodus abgebrochen");
    assertEquals("Konnektor-Lokal", text(fault, "Instance"));
    assertEquals("0", xpath(mode(), "count(//*[local-name()='SessionInfo'])"));
    assertEquals("OK", text(deactivate(hba()), "Result"));
    assertEquals(1, prompts.size(), prompts::toString);
  }

  @Test
  @DisplayName(
      "A_18686-01 Komfortsignatur-Timer: nach SAK_COMFORT_SIGNATURE_TIMER = 1 h endet SignDocument mit 4271 "
          + "(KUC_1608_025 ohne 3600 s Wartezeit)")
  void timer() throws Exception {
    comfort.timer(Duration.ofHours(1));
    activate(200);
    verify(signed(sign(1, 200), "OK"));
    clock.advance(Duration.ofMinutes(61));
    assertEquals("PT0S", text(mode(), "TimeRemaining"));
    assertFault(sign(1, 500), "4271", "Technical", "Komfortsignaturmodus abgebrochen");
    assertEquals("0", xpath(mode(), "count(//*[local-name()='SessionInfo'])"));
  }

  @Test
  @DisplayName(
      "A_20074 UserId der letzten 1.000 Aktivierungen → 4270 (KUC_1608_022); A_20073-01 UserId keine UUID "
          + "→ 4272 (KUC_1608_023)")
  void userId() throws Exception {
    activate(200);
    assertEquals("OK", text(deactivate(hba()), "Result"));
    assertFault(
        activate(500),
        "4270",
        "Technical",
        "UserId wurde in den letzten 1.000 Vorgängen bereits verwendet");
    userId = UUID.randomUUID().toString().substring(0, 8);
    assertFault(activate(500), "4272", "Technical", "UserId nicht zulässig");
    assertEquals(1, prompts.size(), prompts::toString);
  }

  @Test
  @DisplayName(
      "TUC_KON_000 R9: im Modus Comfort hält die Session die PIN.QES, eine andere UserId desselben "
          + "Clientsystems bekommt 4018 bei SignDocument und GetSignatureMode, ohne PIN-Eingabe (EE_KT_T_SIGNATUR_"
          + "COMFORTSIGNATUR_); TAB_KON_877 CardNeedsReset: ActivateComfortSignature der anderen UserId setzt den HBA "
          + "zurück und schaltet ein, dann bekommt die erste 4018")
  void andereUserId() throws Exception {
    activate(200);
    String first = userId;
    userId = UUID.randomUUID().toString();
    assertFault(
        sign(1, 500),
        "4018",
        "Security",
        "Der HBAx hat mindestens eine Kartensitzung zu einer anderen UserId, deren Sicherheitszustand erhöht ist.");
    assertFault(
        call("GetSignatureMode", "<ns2:CardHandle>" + hba() + "</ns2:CardHandle>" + context(), 500),
        "4018",
        "Security",
        "Der HBAx hat mindestens eine Kartensitzung zu einer anderen UserId, deren "
            + "Sicherheitszustand erhöht ist.");
    assertEquals(1, prompts.size(), prompts::toString);

    assertEquals("COMFORT", text(activate(200), "SignatureMode"));
    assertEquals(2, prompts.size(), prompts::toString);
    verify(signed(sign(1, 200), "OK"));
    userId = first;
    assertFault(
        sign(1, 500),
        "4018",
        "Security",
        "Der HBAx hat mindestens eine Kartensitzung zu einer anderen UserId, deren Sicherheitszustand erhöht ist.");
    assertEquals(2, prompts.size(), prompts::toString);
  }

  @Test
  @DisplayName(
      "TUC_KON_171 (->1) SAK_COMFORT_SIGNATURE = Disabled → 4263, keine PIN-Eingabe; TUC_KON_173 meldet "
          + "DISABLED")
  void ausgeschaltet() throws Exception {
    comfort.enabled(false);
    assertEquals("DISABLED", text(mode(), "ComfortSignatureStatus"));
    assertFault(activate(500), "4263", "Technical", "Komfortsignaturfunktion nicht aktiviert");
    assertTrue(prompts.isEmpty(), prompts::toString);
  }

  @Test
  @DisplayName(
      "A_19105 TUC_KON_172 durch den Administrator: SAK_COMFORT_SIGNATURE = Disabled beendet die Session, "
          + "SignDocument verlangt wieder PIN.QES")
  void administratorSchaltetAus() throws Exception {
    activate(200);
    comfort.enabled(false);
    assertEquals("0", xpath(mode(), "count(//*[local-name()='SessionInfo'])"));
    verify(signed(sign(1, 200), "OK"));
    assertEquals(2, prompts.size(), prompts::toString);
  }

  @Test
  @DisplayName(
      "TAB_KON_887 DeactivateComfortSignature: unbekanntes CardHandle → Warnung 4265, HBA ohne Session → "
          + "Warnung 4266, beide in einem GERROR:Error")
  void deaktivierenWarnungen() throws Exception {
    Element response = deactivate("unbekannt", hba());
    assertEquals("Warning", text(response, "Result"));
    assertEquals("4265", xpath(response, "(//*[local-name()='Code'])[1]"));
    assertEquals(
        "Karten-Handle ungültig unbekannt", xpath(response, "(//*[local-name()='ErrorText'])[1]"));
    assertEquals("4266", xpath(response, "(//*[local-name()='Code'])[2]"));
    assertEquals(
        "Keine Kartensitzung vorhanden " + hba(),
        xpath(response, "(//*[local-name()='ErrorText'])[2]"));
  }

  @Test
  @DisplayName("TAB_KON_874 nur der HBA: ActivateComfortSignature mit der SM-B → 4274")
  void nurHba() throws Exception {
    String smcb = cards.card("KT-01", 1).orElseThrow().cardHandle();
    Element fault =
        call(
            "ActivateComfortSignature",
            "<ns2:CardHandle>" + smcb + "</ns2:CardHandle>" + context(),
            500);
    assertFault(fault, "4274", "Technical", "Komfortsignaturen werden nur für den HBA unterstützt");
  }

  @Test
  @DisplayName(
      "TAB_KON_596 SAK_COMFORT_SIGNATURE ohne ANCL_TLS_MANDATORY/ANCL_CAUT_MANDATORY: Warnung "
          + "LIANA/DEVIATION im Systemprotokoll, mit liana.strict abgelehnt (Entscheidung des Users)")
  void ohneTlsPflicht() {
    comfort.enabled(false);
    systemLog.clear();
    comfort.enabled(true);
    Consumer<String> deviation =
        severity ->
            assertTrue(
                systemLog.entries(null, null).stream()
                    .anyMatch(
                        e ->
                            e.topic().equals(PeerDeviations.TOPIC)
                                && e.severity().value().equals(severity)
                                && "COMFORT_WITHOUT_CLIENT_TLS"
                                    .equals(e.parameters().get("Deviation"))),
                severity);
    deviation.accept("Warning");
    comfort.enabled(false);
    deviations.setStrict(true);
    assertThrows(IllegalStateException.class, () -> comfort.enabled(true));
    deviation.accept("Error");
    assertFalse(comfort.enabled());
    binding.state(
        binding
            .state()
            .withTlsMandatory(true)
            .withAuthentication(ClientSystemBinding.Authentication.CERTIFICATE));
    comfort.enabled(true);
    assertTrue(comfort.enabled());
  }
}

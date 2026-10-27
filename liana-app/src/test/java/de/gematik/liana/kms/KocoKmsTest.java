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
package de.gematik.liana.kms;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.admin.AdminServer;
import de.gematik.liana.kern.event.SystemLog;
import de.gematik.liana.kern.management.ComfortSettings;
import de.gematik.liana.kern.management.ManagementSettings;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import jakarta.inject.Inject;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * The KOCO KMS (LIANA-96) on the management port over HTTPS, step by step like {@code
 * KmsKoco.login} and the group parameters in kms-client, against the KOCO spec V2.20 (ch. 1, 15.1,
 * 15.2).
 */
@QuarkusTest
class KocoKmsTest {

  @Inject AdminServer admin;

  @Inject ManagementSettings settings;

  @Inject ComfortSettings comfort;

  @Inject SystemLog systemLog;

  @AfterEach
  void reset() {
    given().port(admin.port()).post("/admin/reset").then().statusCode(200);
  }

  private void vendor(String vendor) {
    given()
        .port(admin.port())
        .contentType("application/json")
        .body(Map.of("vendor", vendor))
        .put("/admin/vendor")
        .then()
        .statusCode(200);
  }

  private RequestSpecification kms() {
    return given()
        .relaxedHTTPSValidation()
        .baseUri("https://localhost")
        .port(admin.port())
        .redirects()
        .follow(false);
  }

  private Response securityCheck(String password) {
    return kms()
        .contentType("application/x-www-form-urlencoded")
        .formParam("j_username", "super")
        .formParam("j_password", password)
        .formParam("login", "Anmelden")
        .post(KocoKms.SECURITY_CHECK);
  }

  /** Session and X-TOKEN as after {@code KmsKoco.login}. */
  private record Session(String id, String token) {
    RequestSpecification json(RequestSpecification request) {
      return request
          .cookie(KocoKms.TOKEN_COOKIE, token)
          .cookie(KocoKms.SESSION_COOKIE, id)
          .header("X-Token", token);
    }
  }

  private Session login() {
    String id =
        securityCheck("33ee§§EE")
            .then()
            .statusCode(303)
            .header("Location", KocoKms.START)
            .extract()
            .cookie(KocoKms.SESSION_COOKIE);
    String token =
        kms()
            .cookie(KocoKms.SESSION_COOKIE, id)
            .get(KocoKms.START)
            .then()
            .statusCode(302)
            .header("Location", KocoKms.START)
            .extract()
            .cookie(KocoKms.TOKEN_COOKIE);
    kms()
        .cookie(KocoKms.TOKEN_COOKIE, token)
        .cookie(KocoKms.SESSION_COOKIE, id)
        .get(KocoKms.START)
        .then()
        .statusCode(200)
        .body(containsString("<textarea id='x-token' style='display:none'>" + token));
    return new Session(id, token);
  }

  @ParameterizedTest(name = "{0}")
  @DisplayName(
      "KOCO-Spec Kap. 1: j_security_check → 303 mit JSESSIONID, start.htm erst 302 mit X-TOKEN, dann 200 mit "
          + "dem Token; Verwaltung lesen mit X-Token (KOCO und CGM)")
  @ValueSource(strings = {"KOCO", "CGM"})
  void login(String vendor) {
    vendor(vendor);
    Session session = login();
    session
        .json(kms())
        .get(KocoKms.MANAGEMENT_RETRIEVE)
        .then()
        .statusCode(200)
        .body("MGM_LU_ONLINE", equalTo("ENABLE"));
  }

  @Test
  @DisplayName(
      "KOCO-Spec Kap. 1: falsches Passwort → 303 auf login.htm ohne Sitzung; geschützte Pfade ohne Sitzung → "
          + "302 auf login.htm mit leerem Body")
  void loginRejected() {
    vendor("KOCO");
    assertNull(
        securityCheck("falsch")
            .then()
            .statusCode(303)
            .header("Location", containsString(KocoKms.LOGIN_PAGE))
            .extract()
            .cookie(KocoKms.SESSION_COOKIE));
    kms()
        .get(KocoKms.START)
        .then()
        .statusCode(302)
        .header("Location", KocoKms.LOGIN_PAGE)
        .body(equalTo(""));
    kms()
        .cookie(KocoKms.SESSION_COOKIE, "unbekannt")
        .get(KocoKms.MANAGEMENT_RETRIEVE)
        .then()
        .statusCode(302)
        .header("Location", KocoKms.LOGIN_PAGE);
  }

  @Test
  @DisplayName(
      "KOCO-Spec Kap. 1: JSON-Aufruf ohne passenden X-Token-Header → 403 mit KONNEKTOR-ERROR")
  void xToken() {
    vendor("KOCO");
    Session session = login();
    kms()
        .cookie(KocoKms.SESSION_COOKIE, session.id())
        .get(KocoKms.MANAGEMENT_RETRIEVE)
        .then()
        .statusCode(403)
        .body("KONNEKTOR-ERROR", equalTo(true))
        .body("TRACES[0].msg", containsString("X-Token"));
    kms()
        .cookie(KocoKms.SESSION_COOKIE, session.id())
        .header("X-Token", "falsch")
        .get(KocoKms.MANAGEMENT_RETRIEVE)
        .then()
        .statusCode(403);
  }

  @Test
  @DisplayName(
      "TAB_KON_658 / KOCO-Spec 15.2: MGM_LU_ONLINE über json-store/management setzen (ENABLE/DISABLE), "
          + "Änderung → OK und Systemprotokoll, gleicher Wert → NOP, andere Werte → 400")
  void online() {
    vendor("KOCO");
    Session session = login();
    String group =
        "{\"MGM_REMOTE_ALLOWED\":\"DISABLE\",\"MGM_LU_ONLINE\":\"%s\",\"MGM_STANDALONE_KON\":\"DISABLE\","
            + "\"MGM_LU_SAK\":\"ENABLE\"}";
    session
        .json(kms())
        .contentType("application/json")
        .body(group.formatted("DISABLE"))
        .post(KocoKms.MANAGEMENT_STORE)
        .then()
        .statusCode(200)
        .body("OK", equalTo(true));
    assertFalse(settings.online());
    assertEquals(
        List.of(Map.of("Active", "Disabled")),
        systemLog.entries(null, null).stream()
            .filter(e -> e.topic().equals(ManagementSettings.LU_ONLINE_CHANGED))
            .map(SystemLog.Entry::parameters)
            .toList());
    session
        .json(kms())
        .get(KocoKms.MANAGEMENT_RETRIEVE)
        .then()
        .body("MGM_LU_ONLINE", equalTo("DISABLE"));
    session
        .json(kms())
        .contentType("application/json")
        .body(group.formatted("DISABLE"))
        .post(KocoKms.MANAGEMENT_STORE)
        .then()
        .statusCode(200)
        .body("NOP", equalTo(true));
    session
        .json(kms())
        .contentType("application/json")
        .body("{\"MGM_LU_ONLINE\":\"AUS\"}")
        .post(KocoKms.MANAGEMENT_STORE)
        .then()
        .statusCode(400)
        .body("KONNEKTOR-ERROR", equalTo(true));
    session
        .json(kms())
        .contentType("application/json")
        .body(group.formatted("ENABLE"))
        .post(KocoKms.MANAGEMENT_STORE)
        .then()
        .statusCode(200)
        .body("OK", equalTo(true));
    assertTrue(settings.online());
  }

  @Test
  @DisplayName(
      "TAB_KON_554 Kartendienst über json-store/cardservice (KUC_1602_034 „TKQES setzt Karten Timeout auf 3 "
          + "Sekunden“): CARD_TIMEOUT_CARD und CARD_SESSION_TIMEOUT in Sekunden, gleicher Wert → NOP, ungültig → 400, "
          + "reset → YAML-Stand")
  void cardservice() {
    vendor("KOCO");
    Session session = login();
    Duration boot = settings.cardTimeout();
    session
        .json(kms())
        .get(KocoKms.CARDSERVICE_RETRIEVE)
        .then()
        .statusCode(200)
        .body("CARD_TIMEOUT_CARD", equalTo((int) boot.toSeconds()))
        .body("CARD_SESSION_TIMEOUT", equalTo((int) settings.sessionTimeout().toSeconds()));
    String group = "{\"CARD_TIMEOUT_CARD\":%s,\"CARD_SESSION_TIMEOUT\":40}";
    session
        .json(kms())
        .contentType("application/json")
        .body(group.formatted("3"))
        .post(KocoKms.CARDSERVICE_STORE)
        .then()
        .statusCode(200)
        .body("OK", equalTo(true));
    assertEquals(Duration.ofSeconds(3), settings.cardTimeout());
    assertEquals(Duration.ofSeconds(40), settings.sessionTimeout());
    session
        .json(kms())
        .contentType("application/json")
        .body(group.formatted("3"))
        .post(KocoKms.CARDSERVICE_STORE)
        .then()
        .statusCode(200)
        .body("NOP", equalTo(true));
    session
        .json(kms())
        .contentType("application/json")
        .body(group.formatted("0"))
        .post(KocoKms.CARDSERVICE_STORE)
        .then()
        .statusCode(400)
        .body("KONNEKTOR-ERROR", equalTo(true));
    assertEquals(Duration.ofSeconds(3), settings.cardTimeout());
    given().port(admin.port()).post("/admin/reset").then().statusCode(200);
    assertEquals(boot, settings.cardTimeout());
  }

  @Test
  @DisplayName(
      "TAB_KON_596 Signaturdienst über json-store/signservice (KUC_1608_005, KUC_1608_024): "
          + "SAK_COMFORT_SIGNATURE ENABLE/DISABLE, _MAX und _TIMER (Stunden) setzbar, außerhalb 1–250 bzw. 1–24 h "
          + "bleibt der Wert bei 200 stehen, SAK_SIMPLE_SIGNATURE_MODE nur SE#1 (sonst 501), reset → Defaults")
  void signservice() {
    vendor("KOCO");
    Session session = login();
    session
        .json(kms())
        .get(KocoKms.SIGNSERVICE_RETRIEVE)
        .then()
        .statusCode(200)
        .body("SAK_COMFORT_SIGNATURE", equalTo("DISABLE"))
        .body("SAK_COMFORT_SIGNATURE_MAX", equalTo(100))
        .body("SAK_COMFORT_SIGNATURE_TIMER", equalTo(6))
        .body("SAK_SIMPLE_SIGNATURE_MODE", equalTo("SE#1"))
        .body("ANCL_TLS_MANDATORY", equalTo(false))
        .body("ANCL_CAUT_MANDATORY", equalTo(false));
    String group =
        "{\"SAK_COMFORT_SIGNATURE\":\"ENABLE\",\"SAK_COMFORT_SIGNATURE_MAX\":\"%s\","
            + "\"SAK_COMFORT_SIGNATURE_TIMER\":%s,\"SAK_SIMPLE_SIGNATURE_MODE\":\"SE#1\","
            + "\"ANCL_TLS_MANDATORY\":false,\"ANCL_CAUT_MANDATORY\":false}";
    session
        .json(kms())
        .contentType("application/json")
        .body(group.formatted("250", "1"))
        .post(KocoKms.SIGNSERVICE_STORE)
        .then()
        .statusCode(200)
        .body("OK", equalTo(true));
    assertTrue(comfort.enabled());
    assertEquals(250, comfort.max());
    assertEquals(Duration.ofHours(1), comfort.timer());
    session
        .json(kms())
        .contentType("application/json")
        .body(group.formatted("0", "25"))
        .post(KocoKms.SIGNSERVICE_STORE)
        .then()
        .statusCode(200)
        .body("NOP", equalTo(true));
    session
        .json(kms())
        .get(KocoKms.SIGNSERVICE_RETRIEVE)
        .then()
        .statusCode(200)
        .body("SAK_COMFORT_SIGNATURE_MAX", equalTo(250))
        .body("SAK_COMFORT_SIGNATURE_TIMER", equalTo(1));
    session
        .json(kms())
        .contentType("application/json")
        .body(group.formatted("250", "1").replace("SE#1", "SE#2"))
        .post(KocoKms.SIGNSERVICE_STORE)
        .then()
        .statusCode(501);
    given().port(admin.port()).post("/admin/reset").then().statusCode(200);
    assertFalse(comfort.enabled());
    assertEquals(ComfortSettings.DEFAULT_MAX, comfort.max());
  }

  @Test
  @DisplayName("KOCO-Spec Kap. 1: logout beendet die Sitzung, danach 302 auf login.htm")
  void logout() {
    vendor("KOCO");
    Session session = login();
    session
        .json(kms())
        .get(KocoKms.LOGOUT)
        .then()
        .statusCode(302)
        .header("Location", KocoKms.LOGIN_PAGE);
    session
        .json(kms())
        .get(KocoKms.MANAGEMENT_RETRIEVE)
        .then()
        .statusCode(302)
        .header("Location", KocoKms.LOGIN_PAGE);
  }

  @Test
  @DisplayName(
      "decision-12: nicht umgesetzte KOCO-Operationen (Netzwerk, MGM_STANDALONE_KON setzen) → 501 mit "
          + "Profil, Methode und Pfad")
  void notImplemented() {
    vendor("KOCO");
    Session session = login();
    session
        .json(kms())
        .get("/administration/json-retrieve/network")
        .then()
        .statusCode(501)
        .body("vendor", equalTo("KOCO"))
        .body("method", equalTo("GET"))
        .body("path", equalTo("/administration/json-retrieve/network"));
    session
        .json(kms())
        .contentType("application/json")
        .body("{\"MGM_STANDALONE_KON\":\"ENABLE\"}")
        .post(KocoKms.MANAGEMENT_STORE)
        .then()
        .statusCode(501)
        .body("path", equalTo(KocoKms.MANAGEMENT_STORE));
  }

  @ParameterizedTest(name = "{0}")
  @DisplayName("decision-12: KoCoBox-Pfade bei Profilen ohne KOCO-KMS → 501 mit dem Profil")
  @ValueSource(strings = {"neutral", "EHEX", "SECUNET", "RISE"})
  void anderesProfil(String vendor) {
    vendor(vendor);
    securityCheck("33ee§§EE")
        .then()
        .statusCode(501)
        .body("vendor", equalTo(vendor))
        .body("path", equalTo(KocoKms.SECURITY_CHECK));
    kms().get(KocoKms.MANAGEMENT_RETRIEVE).then().statusCode(501).body("vendor", equalTo(vendor));
  }
}

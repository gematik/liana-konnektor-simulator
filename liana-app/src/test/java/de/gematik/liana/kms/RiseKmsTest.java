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

import de.gematik.liana.TlsProbe;
import de.gematik.liana.admin.AdminServer;
import de.gematik.liana.kern.event.SystemLog;
import de.gematik.liana.kern.management.ComfortSettings;
import de.gematik.liana.kern.management.ManagementSettings;
import de.gematik.liana.tls.KonnektorTlsServer;
import de.gematik.liana.tls.KonnektorTlsServerTest;
import io.quarkus.test.junit.QuarkusTest;
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
 * The RISE KMS (LIANA-97) like {@code KmsRise} in kms-client, against the RISE API v1.21: on the
 * HTTPS port of the Konnektor interface, where konnektor-service-client addresses it on 8443, and
 * on the management port.
 */
@QuarkusTest
class RiseKmsTest {

  private static final String USER = "{\"user\":\"super\",\"password\":\"33ee§§EE\"}";

  @Inject AdminServer admin;

  @Inject KonnektorTlsServer tls;

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

  private RequestSpecification konnektor() {
    return given().relaxedHTTPSValidation().baseUri("https://localhost").port(tls.port());
  }

  private RequestSpecification management() {
    return given().relaxedHTTPSValidation().baseUri("https://localhost").port(admin.port());
  }

  private RequestSpecification port(String port) {
    return "konnektor".equals(port) ? konnektor() : management();
  }

  /**
   * Session as after {@code KmsRise.login}: cookie and CSRF header ({@code
   * getVendorSpecificHttpHeader}).
   */
  private record Session(String id) {
    RequestSpecification on(RequestSpecification request) {
      return request
          .cookie(RiseKms.SESSION_COOKIE, id)
          .header(RiseKms.CSRF_HEADER, RiseKms.CSRF_VALUE);
    }
  }

  private Session login(RequestSpecification request) {
    return new Session(
        request
            .contentType("application/json")
            .body(USER)
            .post(RiseKms.LOGIN)
            .then()
            .statusCode(200)
            .header("Set-Cookie", containsString("JSESSIONID="))
            .body("username", equalTo("super"))
            .extract()
            .cookie(RiseKms.SESSION_COOKIE));
  }

  @ParameterizedTest(name = "{0}")
  @DisplayName(
      "RISE-API /v1/auth/login: 200 mit User und JSESSIONID, danach /v1/mgm/config lesen; auf dem HTTPS-Port "
          + "der Konnektor-Schnittstelle (konnektor-service-client: RISE 8443) und auf dem Management-Port")
  @ValueSource(strings = {"konnektor", "management"})
  void login(String port) {
    vendor("RISE");
    Session session = login(port(port));
    session
        .on(port(port))
        .get(RiseKms.MGM_CONFIG)
        .then()
        .statusCode(200)
        .body("MGM_LU_ONLINE", equalTo(true))
        .body("MGM_LU_SAK", equalTo(true))
        .body("MGM_STANDALONE_KON", equalTo(false));
  }

  @Test
  @DisplayName(
      "LIANA-97 AC2: unter RISE bleibt SOAP über HTTPS auf demselben Port, connector.sds meldet RISEG")
  void soapDaneben() throws Exception {
    vendor("RISE");
    login(konnektor());
    TlsProbe.Result soap =
        TlsProbe.bc()
            .soap(
                tls.port(),
                "/ws/EventService",
                KonnektorTlsServerTest.GET_CARDS_ACTION,
                KonnektorTlsServerTest.GET_CARDS);
    assertEquals(200, soap.status(), soap.response());
    assertTrue(TlsProbe.bc().get(tls.port(), "/connector.sds").body().contains("RISEG"));
  }

  @Test
  @DisplayName(
      "falsches Passwort → 401 ohne Sitzung; ohne Sitzung → 401 (ErrorMessage der RISE-API)")
  void loginRejected() {
    vendor("RISE");
    assertNull(
        konnektor()
            .contentType("application/json")
            .body("{\"user\":\"super\",\"password\":\"falsch\"}")
            .post(RiseKms.LOGIN)
            .then()
            .statusCode(401)
            .body("type", equalTo("Security"))
            .extract()
            .cookie(RiseKms.SESSION_COOKIE));
    konnektor().get(RiseKms.MGM_CONFIG).then().statusCode(401).body("severity", equalTo("Error"));
    konnektor()
        .cookie(RiseKms.SESSION_COOKIE, "unbekannt")
        .header(RiseKms.CSRF_HEADER, RiseKms.CSRF_VALUE)
        .get(RiseKms.MGM_CONFIG)
        .then()
        .statusCode(401);
  }

  @Test
  @DisplayName("RISE-API CSRF-Schutz: ohne X-Requested-With: RISEHttpRequest → 403")
  void csrf() {
    vendor("RISE");
    Session session = login(konnektor());
    konnektor()
        .cookie(RiseKms.SESSION_COOKIE, session.id())
        .get(RiseKms.MGM_CONFIG)
        .then()
        .statusCode(403)
        .body("text", containsString(RiseKms.CSRF_HEADER));
  }

  @Test
  @DisplayName(
      "TAB_KON_658 / RISE-API MGMConfig: MGM_LU_ONLINE per PUT /v1/mgm/config setzen (boolean), Antwort mit "
          + "den geschriebenen Werten, Systemprotokoll; kein boolean → 400")
  void online() {
    vendor("RISE");
    Session session = login(konnektor());
    String group =
        "{\"MGM_LU_ONLINE\":%s,\"MGM_LU_SAK\":true,\"MGM_STANDALONE_KON\":false,"
            + "\"MGM_REMOTE_ALLOWED\":false}";
    session
        .on(konnektor())
        .contentType("application/json")
        .body(group.formatted("false"))
        .put(RiseKms.MGM_CONFIG)
        .then()
        .statusCode(200)
        .body("MGM_LU_ONLINE", equalTo(false));
    assertFalse(settings.online());
    assertEquals(
        List.of(Map.of("Active", "Disabled")),
        systemLog.entries(null, null).stream()
            .filter(e -> e.topic().equals(ManagementSettings.LU_ONLINE_CHANGED))
            .map(SystemLog.Entry::parameters)
            .toList());
    session
        .on(konnektor())
        .contentType("application/json")
        .body(group.formatted("\"Disabled\""))
        .put(RiseKms.MGM_CONFIG)
        .then()
        .statusCode(400)
        .body("type", equalTo("Technical"));
    session
        .on(konnektor())
        .contentType("application/json")
        .body(group.formatted("true"))
        .put(RiseKms.MGM_CONFIG)
        .then()
        .statusCode(200)
        .body("MGM_LU_ONLINE", equalTo(true));
    assertTrue(settings.online());
  }

  @Test
  @DisplayName(
      "TAB_KON_554 / RISE-API CardServiceConfig (KUC_1602_071 „TKQES setzt Karten Timeout auf 3 Sekunden“): "
          + "CARD_TIMEOUT_CARD und CARD_SESSION_TIMEOUT in Sekunden per PUT /v1/card/config, Antwort mit den "
          + "geschriebenen Werten; außerhalb 1–60 → 400; reset → YAML-Stand")
  void cardConfig() {
    vendor("RISE");
    Session session = login(konnektor());
    Duration boot = settings.cardTimeout();
    session
        .on(konnektor())
        .get(RiseKms.CARD_CONFIG)
        .then()
        .statusCode(200)
        .body("CARD_TIMEOUT_CARD", equalTo((int) boot.toSeconds()))
        .body("CARD_SESSION_TIMEOUT", equalTo((int) settings.sessionTimeout().toSeconds()));
    String group = "{\"CARD_TIMEOUT_CARD\":%s,\"CARD_SESSION_TIMEOUT\":40}";
    session
        .on(konnektor())
        .contentType("application/json")
        .body(group.formatted("3"))
        .put(RiseKms.CARD_CONFIG)
        .then()
        .statusCode(200)
        .body("CARD_TIMEOUT_CARD", equalTo(3))
        .body("CARD_SESSION_TIMEOUT", equalTo(40));
    assertEquals(Duration.ofSeconds(3), settings.cardTimeout());
    assertEquals(Duration.ofSeconds(40), settings.sessionTimeout());
    session
        .on(konnektor())
        .contentType("application/json")
        .body(group.formatted("61"))
        .put(RiseKms.CARD_CONFIG)
        .then()
        .statusCode(400)
        .body("type", equalTo("Technical"));
    assertEquals(Duration.ofSeconds(3), settings.cardTimeout());
    given().port(admin.port()).post("/admin/reset").then().statusCode(200);
    assertEquals(boot, settings.cardTimeout());
  }

  @Test
  @DisplayName(
      "TAB_KON_596 /v1/sak/config (KUC_1608_005, KUC_1608_024): SAK_COMFORT_SIGNATURE true/false, _MAX und "
          + "_TIMER (Stunden), außerhalb 1–250 bzw. 1–24 h bleibt der Wert bei 200 stehen, SAK_SIMPLE_SIGNATURE_MODE nur "
          + "SE_1 (sonst 501)")
  void sakConfig() {
    vendor("RISE");
    Session session = login(konnektor());
    session
        .on(konnektor())
        .get(RiseKms.SAK_CONFIG)
        .then()
        .statusCode(200)
        .body("SAK_COMFORT_SIGNATURE", equalTo(false))
        .body("SAK_COMFORT_SIGNATURE_MAX", equalTo(100))
        .body("SAK_COMFORT_SIGNATURE_TIMER", equalTo(6))
        .body("SAK_SIMPLE_SIGNATURE_MODE", equalTo("SE_1"));
    String group =
        "{\"SAK_COMFORT_SIGNATURE\":true,\"SAK_COMFORT_SIGNATURE_MAX\":%s,"
            + "\"SAK_COMFORT_SIGNATURE_TIMER\":%s,\"SAK_SIMPLE_SIGNATURE_MODE\":\"SE_1\"}";
    session
        .on(konnektor())
        .contentType("application/json")
        .body(group.formatted("2", "24"))
        .put(RiseKms.SAK_CONFIG)
        .then()
        .statusCode(200)
        .body("SAK_COMFORT_SIGNATURE", equalTo(true))
        .body("SAK_COMFORT_SIGNATURE_MAX", equalTo(2))
        .body("SAK_COMFORT_SIGNATURE_TIMER", equalTo(24));
    assertTrue(comfort.enabled());
    session
        .on(konnektor())
        .contentType("application/json")
        .body(group.formatted("251", "0"))
        .put(RiseKms.SAK_CONFIG)
        .then()
        .statusCode(200)
        .body("SAK_COMFORT_SIGNATURE_MAX", equalTo(2))
        .body("SAK_COMFORT_SIGNATURE_TIMER", equalTo(24));
    session
        .on(konnektor())
        .contentType("application/json")
        .body(group.formatted("2", "24").replace("SE_1", "SE_2"))
        .put(RiseKms.SAK_CONFIG)
        .then()
        .statusCode(501);
    given().port(admin.port()).post("/admin/reset").then().statusCode(200);
    assertFalse(comfort.enabled());
  }

  @Test
  @DisplayName("RISE-API /v1/auth/logout: 204, danach keine Sitzung mehr (401)")
  void logout() {
    vendor("RISE");
    Session session = login(konnektor());
    session.on(konnektor()).post(RiseKms.LOGOUT).then().statusCode(204);
    session.on(konnektor()).get(RiseKms.MGM_CONFIG).then().statusCode(401);
  }

  @Test
  @DisplayName(
      "decision-12: nicht umgesetzte RISE-Operationen (BNetzA-VL, MGM_STANDALONE_KON setzen) → 501 mit Profil, "
          + "Methode und Pfad")
  void notImplemented() {
    vendor("RISE");
    Session session = login(konnektor());
    session
        .on(konnektor())
        .get("/api/v1/cert/bNetzATrustList")
        .then()
        .statusCode(501)
        .body("vendor", equalTo("RISE"))
        .body("method", equalTo("GET"))
        .body("path", equalTo("/api/v1/cert/bNetzATrustList"));
    session
        .on(konnektor())
        .contentType("application/json")
        .body("{\"MGM_STANDALONE_KON\":true}")
        .put(RiseKms.MGM_CONFIG)
        .then()
        .statusCode(501)
        .body("path", equalTo(RiseKms.MGM_CONFIG));
  }

  @ParameterizedTest(name = "{0}")
  @DisplayName(
      "Profile ohne RISE-KMS: /api auf der Konnektor-Schnittstelle 404 wie zuvor, auf dem Management-Port 501 "
          + "mit dem Profil (decision-12)")
  @ValueSource(strings = {"neutral", "EHEX", "SECUNET", "KOCO", "CGM"})
  void anderesProfil(String vendor) {
    vendor(vendor);
    konnektor()
        .contentType("application/json")
        .body(USER)
        .post(RiseKms.LOGIN)
        .then()
        .statusCode(404);
    management()
        .contentType("application/json")
        .body(USER)
        .post(RiseKms.LOGIN)
        .then()
        .statusCode(501)
        .body("vendor", equalTo(vendor))
        .body("path", equalTo(RiseKms.LOGIN));
  }

  @Test
  @DisplayName("RISE-KMS an der Konnektor-Schnittstelle nur über TLS: per HTTP 404")
  void nurTls() {
    vendor("RISE");
    given().contentType("application/json").body(USER).post(RiseKms.LOGIN).then().statusCode(404);
  }
}

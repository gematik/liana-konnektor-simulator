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
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.admin.AdminServer;
import de.gematik.liana.kern.card.CardSessions;
import de.gematik.liana.kern.event.SystemLog;
import de.gematik.liana.kern.management.ComfortSettings;
import de.gematik.liana.kern.management.ManagementSettings;
import de.gematik.liana.kern.vendor.Deviation;
import de.gematik.liana.kern.vendor.PeerDeviations;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.specification.RequestSpecification;
import jakarta.inject.Inject;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * The KMS over HTTPS (LIANA-55): the EHEX subset for the profiles EHEX and SECUNET, otherwise HTTP
 * 501 with vendor profile, method and path (decision-12). The login paths of the other profiles are
 * those kms-client starts with ({@code RiseConstants}, {@code KocoConstants}; CGM uses {@code
 * KmsKoco}).
 */
@QuarkusTest
class KmsServerTest {

  private static final String LOGIN_BODY = "{\"username\":\"super\",\"password\":\"33ee§§EE\"}";

  @Inject KmsServer kmsServer;

  @Inject PeerDeviations deviations;

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
    return given().relaxedHTTPSValidation().baseUri("https://localhost").port(admin.port());
  }

  /** Log in like kms-client: POST …/konten/login, token from the {@code Authorization} header. */
  private String login() {
    return kms()
        .contentType("application/json")
        .body(LOGIN_BODY)
        .post(EhexKms.LOGIN)
        .then()
        .statusCode(204)
        .extract()
        .header("Authorization");
  }

  private RequestSpecification authorized() {
    return kms().header("Authorization", login());
  }

  @ParameterizedTest(name = "{0}: {1} {2} → 501")
  @DisplayName(
      "decision-12: KMS-Anfrage bei Profil ohne EHEX-KMS und Login-Pfade anderer Hersteller (kms-client "
          + "RiseConstants, KocoConstants) auf dem Management-Port → HTTP 501 mit Herstellerprofil, Methode und Pfad")
  @CsvSource({
    "neutral, POST, /rest/mgmt/ak/konten/login",
    "RISE,    GET,  /rest/mgmt/ak/dienste/karten/einstellungen",
    "SECUNET, POST, /api/v1/auth/login",
    "KOCO,    POST, /login.htm",
    "CGM,     POST, /login.htm",
    "EHEX,    POST, /api/v1/auth/login"
  })
  void notImplemented(String vendor, String method, String path) {
    vendor(vendor);
    kms()
        .contentType("application/json")
        .body("{}")
        .request(method, path)
        .then()
        .statusCode(501)
        .contentType("application/json")
        .body("vendor", equalTo(vendor))
        .body("method", equalTo(method))
        .body("path", equalTo(path))
        .body("error", containsString("Herstellerprofils " + vendor + ": " + method + " " + path))
        .body("error", containsString("in LIANA nicht umgesetzt"));
  }

  @ParameterizedTest(name = "{0}")
  @DisplayName(
      "LIANA-55: EHEX-KMS bei EHEX und SECUNET – Login 204 mit Token, falsches Passwort 400, ohne Token 401, Logout entwertet das Token")
  @ValueSource(strings = {"EHEX", "SECUNET"})
  void loginLogout(String vendor) {
    vendor(vendor);
    String token = login();
    assertTrue(token.startsWith("Bearer "), token);
    kms()
        .contentType("application/json")
        .body("{\"username\":\"super\",\"password\":\"falsch\"}")
        .post(EhexKms.LOGIN)
        .then()
        .statusCode(400);
    kms().get(EhexKms.CARD_SETTINGS).then().statusCode(401);
    kms().header("Authorization", token).get(EhexKms.CARD_SETTINGS).then().statusCode(200);
    kms().header("Authorization", token).delete(EhexKms.LOGOUT).then().statusCode(204);
    kms().header("Authorization", token).get(EhexKms.CARD_SETTINGS).then().statusCode(401);
  }

  @Test
  @DisplayName(
      "decision-017 / TIP1-A_5661: KMS auch per HTTP auf dem Management-Port, Token gilt für beide")
  void http() {
    vendor("EHEX");
    String token =
        given()
            .port(admin.port())
            .contentType("application/json")
            .body(LOGIN_BODY)
            .post(EhexKms.LOGIN)
            .then()
            .statusCode(204)
            .extract()
            .header("Authorization");
    given()
        .port(admin.port())
        .header("Authorization", token)
        .get(EhexKms.CARD_SETTINGS)
        .then()
        .statusCode(200)
        .body("cardSessionTimeout.unit", equalTo("SECONDS"));
    kms().header("Authorization", token).get(EhexKms.CARD_SETTINGS).then().statusCode(200);
  }

  @Test
  @DisplayName("LIANA-146: unbekannter Pfad unter /admin bleibt 404, auch per HTTPS")
  void adminUnbekannt() {
    kms()
        .get("/admin/gibtsnicht")
        .then()
        .statusCode(404)
        .body("error", containsString("/admin/gibtsnicht"));
  }

  @Test
  @DisplayName("LIANA-146: ohne liana.kms.port kein eigener KMS-Listener")
  void keinKompatibilitaetsListener() {
    assertTrue(kmsServer.compatibilityPort().isEmpty());
  }

  @Test
  @DisplayName(
      "TAB_KON_596 Signaturdienst /ak/dienste/signatur/einstellungen (KUC_1608_005 für SECUNET): "
          + "sakComfortSignatureActive, sakComfortSignatureMax, sakComfortSignatureTimer {amount, HOURS}; außerhalb "
          + "1–250 bzw. 1–24 h bleibt der Wert bei 200 stehen; sakActive und simpleSignatureMode nur true (sonst 501)")
  void signatureSettings() {
    vendor("SECUNET");
    String token = login();
    kms()
        .header("Authorization", token)
        .get(EhexKms.SIGNATURE_SETTINGS)
        .then()
        .statusCode(200)
        .body("sakActive", equalTo(true))
        .body("simpleSignatureMode", equalTo(true))
        .body("sakComfortSignatureActive", equalTo(false))
        .body("sakComfortSignatureMax", equalTo(100))
        .body("sakComfortSignatureTimer.amount", equalTo(6))
        .body("sakComfortSignatureTimer.unit", equalTo("HOURS"));
    // like kms-client: whole group back, amount as a string
    String group =
        "{\"sakActive\":true,\"simpleSignatureMode\":true,\"sakComfortSignatureActive\":true,"
            + "\"sakComfortSignatureMax\":%s,\"sakComfortSignatureTimer\":{\"amount\":\"%s\",\"unit\":\"HOURS\"}}";
    kms()
        .header("Authorization", token)
        .contentType("application/json")
        .body(group.formatted("1", "1"))
        .put(EhexKms.SIGNATURE_SETTINGS)
        .then()
        .statusCode(200)
        .body("sakComfortSignatureMax", equalTo(1))
        .body("sakComfortSignatureTimer.amount", equalTo(1));
    assertTrue(comfort.enabled());
    kms()
        .header("Authorization", token)
        .contentType("application/json")
        .body(group.formatted("0", "25"))
        .put(EhexKms.SIGNATURE_SETTINGS)
        .then()
        .statusCode(200)
        .body("sakComfortSignatureMax", equalTo(1))
        .body("sakComfortSignatureTimer.amount", equalTo(1));
    kms()
        .header("Authorization", token)
        .contentType("application/json")
        .body(
            group
                .formatted("1", "1")
                .replace("\"simpleSignatureMode\":true", "\"simpleSignatureMode\":false"))
        .put(EhexKms.SIGNATURE_SETTINGS)
        .then()
        .statusCode(501);
    given().port(admin.port()).post("/admin/reset").then().statusCode(200);
    assertFalse(comfort.enabled());
  }

  @Test
  @DisplayName(
      "TAB_KON_554: CARD_SESSION_TIMEOUT lesen und setzen (Kartendienst cardSessionTimeout {amount, unit}), außerhalb 10–180 s → 400")
  void cardSessionTimeout() {
    vendor("EHEX");
    String token = login();
    kms()
        .header("Authorization", token)
        .get(EhexKms.CARD_SETTINGS)
        .then()
        .statusCode(200)
        .body("cardSessionTimeout.amount", equalTo((int) settings.sessionTimeout().toSeconds()))
        .body("cardSessionTimeout.unit", equalTo("SECONDS"));
    String group = kms().header("Authorization", token).get(EhexKms.CARD_SETTINGS).asString();
    // like kms-client: whole group back, amount as a string
    String changed =
        group.replaceFirst(
            "\"cardSessionTimeout\":\\{\"amount\":\\d+",
            "\"cardSessionTimeout\":{\"amount\":\"40\"");
    kms()
        .header("Authorization", token)
        .contentType("application/json")
        .body(changed)
        .put(EhexKms.CARD_SETTINGS)
        .then()
        .statusCode(200)
        .body("cardSessionTimeout.amount", equalTo(40));
    assertEquals(Duration.ofSeconds(40), settings.sessionTimeout());
    kms()
        .header("Authorization", token)
        .contentType("application/json")
        .body("{\"cardSessionTimeout\":{\"amount\":5,\"unit\":\"SECONDS\"}}")
        .put(EhexKms.CARD_SETTINGS)
        .then()
        .statusCode(400)
        .body("fieldErrors.cardSessionTimeout[0].message", containsString("10–180 s"));
    assertEquals(Duration.ofSeconds(40), settings.sessionTimeout());
  }

  @Test
  @DisplayName(
      "TAB_KON_658: MGM_LU_ONLINE lesen und setzen (Leistungsumfang online ENABLED/DISABLED), Änderung im Systemprotokoll, andere Werte → 400")
  void online() {
    vendor("SECUNET");
    String token = login();
    kms()
        .header("Authorization", token)
        .get(EhexKms.SCOPE_SETTINGS)
        .then()
        .statusCode(200)
        .body("online", equalTo("ENABLED"));
    kms()
        .header("Authorization", token)
        .contentType("application/json")
        .body(
            "{\"logicalSeparation\":\"ENABLED\",\"online\":\"DISABLED\",\"standalone\":\"ENABLED\"}")
        .put(EhexKms.SCOPE_SETTINGS)
        .then()
        .statusCode(200)
        .body("online", equalTo("DISABLED"));
    assertFalse(settings.online());
    assertEquals(
        List.of(Map.of("Active", "Disabled")),
        systemLog.entries(null, null).stream()
            .filter(e -> e.topic().equals(ManagementSettings.LU_ONLINE_CHANGED))
            .map(SystemLog.Entry::parameters)
            .toList());
    kms()
        .header("Authorization", token)
        .contentType("application/json")
        .body("{\"online\":\"VIELLEICHT\"}")
        .put(EhexKms.SCOPE_SETTINGS)
        .then()
        .statusCode(400);
  }

  @Test
  @DisplayName(
      "TIP1-A_4715: Systemprotokoll-Download system/OP/{from}/{to} als Text, eine Zeile je Eintrag, Zeitfenster in ms einschließlich")
  void downloadLog() {
    vendor("EHEX");
    String token = login();
    Instant before = Instant.now().minusMillis(1);
    systemLog.sessionTimeout(new CardSessions.Timeout("EGK", "s-1", CardSessions.Timeout.POPP));
    Instant after = Instant.now();
    String text =
        kms()
            .header("Authorization", token)
            .get(
                "/rest/mgmt/ak/dienste/protokoll/download/system/OP/"
                    + before.toEpochMilli()
                    + "/"
                    + after.toEpochMilli())
            .then()
            .statusCode(200)
            .contentType(startsWith("text/plain"))
            .extract()
            .asString();
    List<String> lines = text.lines().filter(l -> l.contains("s-1")).toList();
    assertEquals(1, lines.size(), text);
    assertTrue(
        lines
            .getFirst()
            .matches(
                "timestamp=\\d\\d\\.\\d\\d\\.\\d{4} \\d\\d:\\d\\d:\\d\\d\\.\\d{3};"
                    + "type=op;severity=info;topic=CARD/SESSION/TIMEOUT;CardType=EGK;SessionID=s-1;Timer=PoPP"),
        lines.getFirst());
    // popp-bridge search (SubstringLogSearchAll): every part between @@ occurs in the line,
    // case-insensitive
    String searched =
        "type=op@@severity=info@@topic=CARD/SESSION/TIMEOUT@@CardType=EGK@@SessionID=s-1@@Timer=PoPP";
    assertTrue(
        Arrays.stream(searched.split("@@"))
            .allMatch(part -> lines.getFirst().toLowerCase().contains(part.toLowerCase())));
    String earlier =
        kms()
            .header("Authorization", token)
            .get(
                "/rest/mgmt/ak/dienste/protokoll/download/system/OP/0/"
                    + (before.toEpochMilli() - 1))
            .asString();
    assertFalse(earlier.contains("s-1"), earlier);
  }

  @Test
  @DisplayName(
      "LIANA-126: Abweichung der Gegenstelle im Systemprotokoll-Download, severity=warning, topic=LIANA/DEVIATION")
  void downloadDeviation() {
    vendor("EHEX");
    String token = login();
    Instant before = Instant.now().minusMillis(1);
    deviations.tolerate(Deviation.KARTOS_MODIFY_VERIFICATION_DATA, "KT-kms", Map.of());
    String text =
        kms()
            .header("Authorization", token)
            .get(
                "/rest/mgmt/ak/dienste/protokoll/download/system/OP/"
                    + before.toEpochMilli()
                    + "/"
                    + Instant.now().toEpochMilli())
            .then()
            .statusCode(200)
            .extract()
            .asString();
    List<String> lines = text.lines().filter(l -> l.contains("Peer=KT-kms")).toList();
    assertEquals(1, lines.size(), text);
    assertTrue(
        lines
            .getFirst()
            .contains(
                ";type=op;severity=warning;topic=LIANA/DEVIATION;"
                    + "Deviation=KARTOS_MODIFY_VERIFICATION_DATA;Peer=KT-kms;"),
        lines.getFirst());
  }

  @ParameterizedTest(name = "{0} {1}")
  @DisplayName("decision-12: nicht umgesetzte EHEX-Operationen → 501 mit Profil, Methode und Pfad")
  @CsvSource(
      delimiter = '|',
      value = {
        "GET | /rest/mgmt/ak/dienste/registrierung | ",
        "GET | /rest/mgmt/ak/dienste/protokoll/download/system/SEC/0/0 | ",
        "PUT | /rest/mgmt/ak/dienste/karten/einstellungen | {\"cardCommunicationTimeout\":{\"amount\":99,\"unit\":\"SECONDS\"}}",
        "PUT | /rest/mgmt/nk/leistungsumfang/einstellungen | {\"standalone\":\"DISABLED\"}"
      })
  void ehexNotImplemented(String method, String path, String body) {
    vendor("EHEX");
    authorized()
        .contentType("application/json")
        .body(body == null ? "{}" : body)
        .request(method, path)
        .then()
        .statusCode(501)
        .body("vendor", equalTo("EHEX"))
        .body("method", equalTo(method))
        .body("path", equalTo(path));
  }
}

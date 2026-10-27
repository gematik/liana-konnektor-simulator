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
package de.gematik.liana.admin;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.matchesPattern;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.config.LianaConfig;
import de.gematik.liana.kern.access.Context;
import de.gematik.liana.kern.card.AuthState;
import de.gematik.liana.kern.card.CardList;
import de.gematik.liana.kern.card.CardSessions;
import de.gematik.liana.kern.event.Subscriptions;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.path.json.JsonPath;
import io.restassured.specification.RequestSpecification;
import jakarta.inject.Inject;
import java.net.ServerSocket;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Read-only views of the Admin API for the Control Center (LIANA-149) against the YAML state: KT-01
 * with egk-valid in slot 1 and further cards, KT-02 empty.
 */
@QuarkusTest
class AdminViewsTest {

  private static final Context WP1 = new Context("M1", "CS1", "WP1", null);

  @Inject AdminServer server;

  @Inject CardList cards;

  @Inject CardSessions cardSessions;

  @Inject AuthState authState;

  @Inject Subscriptions subscriptions;

  @Inject LianaConfig config;

  private RequestSpecification admin() {
    return given().port(server.port());
  }

  @AfterEach
  void reset() {
    admin().post("/admin/reset").then().statusCode(200);
  }

  private String egk() {
    return cards.card("KT-01", 1).orElseThrow().cardHandle();
  }

  @Test
  @DisplayName(
      "TUC_KON_001 / TAB_KON_531: GET /admin/cards ist CM_CARD_LIST mit Handle, ICCSN, Inhaber, KVNR, "
          + "Version, Steckzeit und Zertifikatsablauf; derselbe Eintrag steht am Slot")
  void karten() {
    JsonPath list = admin().get("/admin/cards").then().statusCode(200).extract().jsonPath();
    Map<String, Object> egk = list.getMap("find { it.ctId == 'KT-01' && it.slotNo == 1 }");
    assertEquals(egk(), egk.get("cardHandle"));
    assertEquals("EGK", egk.get("cardType"));
    assertTrue(String.valueOf(egk.get("iccsn")).matches("[0-9]{20}"), String.valueOf(egk));
    assertTrue(String.valueOf(egk.get("kvnr")).matches("[A-Z][0-9]{9}"), String.valueOf(egk));
    assertTrue(egk.get("cardHolderName") != null, String.valueOf(egk));
    assertTrue(
        String.valueOf(egk.get("certExpirationDate")).matches("\\d{4}-\\d{2}-\\d{2}"),
        String.valueOf(egk));
    assertTrue(
        String.valueOf(egk.get("insertTime")).matches("\\d{4}-\\d{2}-\\d{2}T.*Z"),
        String.valueOf(egk));
    assertTrue(((Map<?, ?>) egk.get("cardVersion")).containsKey("cos"), String.valueOf(egk));
    assertEquals(false, egk.get("locked"));

    admin()
        .get("/admin/terminals/KT-01")
        .then()
        .statusCode(200)
        .body("slots[0].card.cardHandle", equalTo(egk()))
        .body("slots[0].card.iccsn", equalTo(egk.get("iccsn")));
    admin().get("/admin/terminals/KT-02").then().statusCode(200).body("slots[0].card", nullValue());
  }

  @Test
  @DisplayName(
      "LIANA-98: GET /admin/images listet die Ordner aus liana.card-images und je Image Name, Datei und ICCSN")
  void images() {
    admin()
        .get("/admin/images")
        .then()
        .statusCode(200)
        .body("directories.size()", greaterThan(0))
        .body("images.name", hasItem("egk-valid"))
        .body("images.find { it.name == 'egk-valid' }.file", endsWith("egk-valid.xml"))
        .body("images.find { it.name == 'egk-valid' }.iccsn", matchesPattern("[0-9]{20}"));
  }

  @Test
  @DisplayName(
      "TIP1-A_4594 / TUC_KON_256: GET /admin/subscriptions mit Kontext, Ziel, Topic, Ablauf und letzter "
          + "CETP-Zustellung; die gescheiterte Zustellung nennt den Grund")
  void subscriptions() throws Exception {
    int closed;
    try (ServerSocket socket = new ServerSocket(0)) {
      closed = socket.getLocalPort();
    }
    String eventTo = "cetp://127.0.0.1:" + closed;
    String id = subscriptions.subscribe(WP1, eventTo, "CARD", null).id();
    admin()
        .get("/admin/subscriptions")
        .then()
        .statusCode(200)
        .body("[0].id", equalTo(id))
        .body("[0].mandantId", equalTo("M1"))
        .body("[0].clientSystemId", equalTo("CS1"))
        .body("[0].workplaceId", equalTo("WP1"))
        .body("[0].eventTo", equalTo(eventTo))
        .body("[0].topic", equalTo("CARD"))
        .body("[0]", not(hasKey("filter")))
        .body("[0].terminationTime", matchesPattern("\\d{4}-.*Z"))
        .body("[0]", not(hasKey("lastDelivery")));

    admin()
        .contentType("application/json")
        .body("{\"image\":\"egk-valid\"}")
        .put("/admin/terminals/KT-02/slots/1")
        .then()
        .statusCode(200);
    Map<String, Object> delivery = null;
    for (long end = System.nanoTime() + 5_000_000_000L;
        delivery == null && System.nanoTime() < end; ) {
      delivery =
          admin()
              .get("/admin/subscriptions")
              .then()
              .statusCode(200)
              .extract()
              .jsonPath()
              .getMap("[0].lastDelivery");
      if (delivery == null) {
        Thread.sleep(50);
      }
    }
    assertEquals("CARD/INSERTED", delivery.get("topic"), String.valueOf(delivery));
    assertEquals(false, delivery.get("delivered"));
    assertTrue(String.valueOf(delivery.get("error")).contains("Connect"), String.valueOf(delivery));

    admin().post("/admin/reset").then().statusCode(200);
    admin().get("/admin/subscriptions").then().statusCode(200).body("size()", equalTo(0));
  }

  @Test
  @DisplayName(
      "A_25970-01 / A_25860-01 / TUC_KON_026: GET /admin/sessions zeigt die Kartensitzung mit Ablauf und die "
          + "verifizierten PINs nur mit PinRef; die reservierte Karte ist locked")
  void sitzungen() {
    admin()
        .get("/admin/sessions")
        .then()
        .statusCode(200)
        .body("cardSessions.size()", equalTo(0))
        .body("verifiedPins.size()", equalTo(0));
    String session = cardSessions.start(WP1, egk());
    authState.verified(WP1, egk(), "PIN.CH");

    admin()
        .get("/admin/sessions")
        .then()
        .statusCode(200)
        .body("cardSessions[0].sessionId", equalTo(session))
        .body("cardSessions[0].cardHandle", equalTo(egk()))
        .body("cardSessions[0].ctId", equalTo("KT-01"))
        .body("cardSessions[0].slotNo", equalTo(1))
        .body("cardSessions[0].timer", equalTo("Konnektor"))
        .body("cardSessions[0].deadline", matchesPattern("\\d{4}-.*Z"))
        .body("verifiedPins[0].cardHandle", equalTo(egk()))
        .body("verifiedPins[0].mandantId", equalTo("M1"))
        .body("verifiedPins[0].clientSystemId", equalTo("CS1"))
        .body("verifiedPins[0].pinRef", equalTo("PIN.CH"))
        .body("verifiedPins[0]", not(hasKey("pin")));
    admin()
        .get("/admin/cards")
        .then()
        .body("find { it.cardHandle == '" + egk() + "' }.locked", equalTo(true));

    cardSessions.stop(session);
    admin().get("/admin/sessions").then().body("cardSessions.size()", equalTo(0));
  }

  @Test
  @DisplayName(
      "TAB_KON_506-01 / A_17124-03: GET /admin/tls mit ANCL_DVD_OPEN, TLS_USE_ECC_FOR_CS, Software-Schlüssel, "
          + "TLS 1.2, Cipher-Suites und Kurven mit brainpoolP256r1")
  void tls() {
    admin()
        .get("/admin/tls")
        .then()
        .statusCode(200)
        .body("dvdOpen", notNullValue())
        .body("eccForClientSystems", notNullValue())
        .body("serverSoftwareKey", equalTo(false))
        .body("protocol", equalTo("TLSv1.2"))
        .body(
            "cipherSuites",
            hasItems(
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"))
        .body("namedGroups", hasItems("brainpoolP256r1", "secp256r1"));
  }

  @Test
  @DisplayName(
      "TUC_KON_037: GET /admin/pki mit Datei, Sequenznummer, nextUpdate und Zahl der CAs der TSL")
  void pki() {
    admin()
        .get("/admin/pki")
        .then()
        .statusCode(200)
        .body("tsl.file", endsWith("ECC-RSA_TSL-ref.xml"))
        .body("tsl.sequenceNumber", notNullValue())
        .body("tsl.nextUpdate", notNullValue())
        .body("tsl.caCount", greaterThan(0))
        .body("importedCas", equalTo(config.pki().importedCas().map(List::size).orElse(0)));
  }

  @Test
  @DisplayName(
      "TAB_KON_554 / TAB_KON_658: GET/PUT /admin/settings setzt CARD_SESSION_TIMEOUT (10–180 s) und "
          + "MGM_LU_ONLINE flüchtig, die Änderung von MGM_LU_ONLINE steht im Protokoll; reset stellt die YAML her")
  void einstellungen() {
    admin()
        .get("/admin/settings")
        .then()
        .statusCode(200)
        .body("cardSessionTimeout", equalTo(120))
        .body("cardSessionTimeoutBoot", equalTo(120))
        .body("luOnline", equalTo(true));
    admin()
        .contentType("application/json")
        .body("{\"cardSessionTimeout\":30}")
        .put("/admin/settings")
        .then()
        .statusCode(200)
        .body("cardSessionTimeout", equalTo(30))
        .body("luOnline", equalTo(true));
    String session = cardSessions.start(WP1, egk());
    admin().get("/admin/sessions").then().body("cardSessions[0].sessionId", equalTo(session));
    String deadline =
        admin().get("/admin/sessions").then().extract().path("cardSessions[0].deadline");
    assertEquals(
        30.0,
        Duration.between(Instant.now(), Instant.parse(deadline)).toSeconds(),
        2.0,
        "gilt für neue Sitzungen");
    cardSessions.stop(session);

    admin()
        .contentType("application/json")
        .body("{\"luOnline\":false}")
        .put("/admin/settings")
        .then()
        .statusCode(200)
        .body("luOnline", equalTo(false))
        .body("cardSessionTimeout", equalTo(30));
    admin().get("/admin/log").then().body("topic", hasItem("MGM/LU_CHANGED/LU_ONLINE"));

    admin()
        .contentType("application/json")
        .body("{\"cardSessionTimeout\":5}")
        .put("/admin/settings")
        .then()
        .statusCode(400)
        .body("error", containsString("TAB_KON_554"));
    admin()
        .contentType("application/json")
        .body("{}")
        .put("/admin/settings")
        .then()
        .statusCode(400);
    admin().post("/admin/reset").then().statusCode(200);
    admin()
        .get("/admin/settings")
        .then()
        .body("cardSessionTimeout", equalTo(120))
        .body("luOnline", equalTo(true));
  }

  @Test
  @DisplayName(
      "LIANA-126: GET /admin/deviations listet die bekannten Abweichungen mit Gegenstelle, Spec, Beobachtung "
          + "und Ausweichen, strict folgt PUT /admin/vendor")
  void abweichungen() {
    admin()
        .get("/admin/deviations")
        .then()
        .statusCode(200)
        .body("strict", equalTo(false))
        .body("deviations.id", hasItem("KARTOS_MODIFY_VERIFICATION_DATA"))
        .body(
            "deviations.find { it.id == 'KARTOS_MODIFY_VERIFICATION_DATA' }.peer",
            equalTo("kartos terminal 0.8.0"))
        .body(
            "deviations.find { it.id == 'KARTOS_MODIFY_VERIFICATION_DATA' }.spec",
            containsString("SICCT"));
    admin()
        .contentType("application/json")
        .body("{\"strict\":true}")
        .put("/admin/vendor")
        .then()
        .statusCode(200);
    admin().get("/admin/deviations").then().body("strict", equalTo(true));
  }

  @Test
  @DisplayName(
      "TUC_KON_054: POST /admin/ct-discovery ohne eHealth-KTs liefert die leere CTM_CT_LIST, ein Fake-KT ist "
          + "kein konfiguriertes eHealth-KT (404, 4007)")
  void discovery() {
    admin().post("/admin/ct-discovery").then().statusCode(200).body("size()", equalTo(0));
    admin()
        .contentType("application/json")
        .body("{}")
        .post("/admin/ct-discovery")
        .then()
        .statusCode(200);
    admin()
        .contentType("application/json")
        .body("{\"ctId\":\"KT-01\"}")
        .post("/admin/ct-discovery")
        .then()
        .statusCode(404)
        .body("code", equalTo(4007));
  }

  @Test
  @DisplayName(
      "LIANA-149 AC 4: keine Antwort der Admin-API enthält PIN-Werte oder private Schlüssel (außer der "
          + ".kon mit pkcs12, kon-format §6)")
  void keineGeheimnisse() {
    String pin = "97531864";
    admin()
        .contentType("application/json")
        .body("[{\"outcome\":\"digits\",\"pin\":\"" + pin + "\"}]")
        .post("/admin/terminals/KT-01/pin-script")
        .then()
        .statusCode(200);
    authState.verified(WP1, egk(), "PIN.CH");
    String session = cardSessions.start(WP1, egk());
    List<String> gets =
        server.adminRoutes().stream()
            .filter(r -> r.startsWith("GET "))
            .map(r -> r.substring(4).replace("{id}", "KT-01").replace("{check}", "brainpool-ecdsa"))
            .filter(path -> !path.endsWith("/config.kon"))
            // the stream does not end; its events carry the same views (AdminEventsTest)
            .filter(path -> !path.equals(AdminEvents.PATH))
            .toList();
    assertTrue(gets.size() >= 15, String.valueOf(gets));
    for (String path : gets) {
      String body = admin().get(path).then().extract().asString();
      assertFalse(body.contains(pin), path + " enthält den PIN-Wert");
      assertFalse(body.matches("(?s).*\"pin\"\\s*:.*"), path + " enthält ein Feld pin");
      assertFalse(body.contains("PRIVATE KEY"), path + " enthält einen privaten Schlüssel");
      assertFalse(
          body.matches(
              "(?is).*\"(privateKey|private|secret|sharedSecret|password)\"\\s*:\\s*\"[^\"]+\".*"),
          path + " enthält ein Geheimnis: " + body);
    }
    cardSessions.stop(session);
  }

  @Test
  @DisplayName(
      "LIANA-149: POST /admin/ct-discovery und GET /admin/selftest/crypto/{check} über HTTPS wie über HTTP")
  void https() {
    given()
        .relaxedHTTPSValidation()
        .baseUri("https://localhost")
        .port(server.port())
        .get("/admin/selftest/crypto/brainpool-ecdsa")
        .then()
        .statusCode(200)
        .body("ok", equalTo(true));
    given()
        .relaxedHTTPSValidation()
        .baseUri("https://localhost")
        .port(server.port())
        .post("/admin/ct-discovery")
        .then()
        .statusCode(200);
  }
}

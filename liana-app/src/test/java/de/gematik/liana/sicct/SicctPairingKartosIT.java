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
package de.gematik.liana.sicct;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.admin.AdminServer;
import de.gematik.liana.crypto.KtTls;
import de.gematik.liana.crypto.SmktCertificateCheck;
import de.gematik.liana.crypto.TlsIdentity;
import de.gematik.liana.crypto.TrustSpace;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.common.QuarkusTestResourceLifecycleManager;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.path.json.JsonPath;
import jakarta.inject.Inject;
import java.io.IOException;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Predicate;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

/**
 * LIANA-77 against {@code kartos terminal}: pairing (TUC_KON_053) and check of the pairing
 * information on connect (TUC_KON_050 steps 5–8, EHEALTH TERMINAL AUTHENTICATE VALIDATE). At
 * startup the KT already knows a pairing with the shared secret from the YAML and LIANA's
 * ID.SAK.AUT (LIANA-88); the tests run in order on the same KT. In addition, the TLS handshake to
 * the KT (TUC_KON_050 step 3, BCJSSE with brainpoolP256r1), previously KtTlsKartosIT.
 */
@QuarkusTest
@QuarkusTestResource(value = SicctPairingKartosIT.Kartos.class, restrictToAnnotatedClass = true)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class SicctPairingKartosIT {

  static final String YAML_SECRET = "00112233445566778899aabbccddeeff";
  static final String FOREIGN_SECRET = "ffeeddccbbaa99887766554433221100";

  /** A different Konnektor: ID.AK.AUT from the test PKI instead of LIANA's ID.SAK.AUT. */
  static final String OTHER_KONNEKTOR_KEY =
      KartosTerminal.subjectPublicKeyInfo(
          java.nio.file.Path.of("support/pki/server/ak-aut-bp256.pem"));

  static final Duration WAIT = Duration.ofSeconds(15);
  static String fingerprint;

  /**
   * kartos with a pairing block for the shared secret from the YAML; LIANA only with this SICCT KT.
   */
  public static class Kartos implements QuarkusTestResourceLifecycleManager {
    static KartosTerminal kt;

    @Override
    public Map<String, String> start() {
      kt = KartosTerminal.start("02:00:00:4C:49:41", "kartos-kt-p1", 0, Map.of(), YAML_SECRET);
      int announcements;
      try {
        announcements = KartosTerminal.freeUdpPort();
      } catch (java.io.IOException e) {
        throw new java.io.UncheckedIOException(e);
      }
      return Map.of(
          "liana.infrastructure.terminals.KT-P1.type", "sicct",
          "liana.cats.terminals[0].terminal", "KT-P1",
          "liana.infrastructure.terminals.KT-P1.host", "127.0.0.1",
          "liana.infrastructure.terminals.KT-P1.shared-secret", YAML_SECRET,
          "liana.ctm.service-discovery-port", String.valueOf(kt.port()),
          "liana.ctm.service-announcement-port", String.valueOf(announcements),
          "liana.ctm.service-discovery-timeout", "2s",
          "liana.infomodel.workplaces[0].terminals", "KT-P1");
    }

    @Override
    public void stop() {
      if (kt != null) {
        kt.close();
      }
    }
  }

  @Inject AdminServer admin;

  private JsonPath kt() {
    return given()
        .port(admin.port())
        .get("/admin/terminals/KT-P1")
        .then()
        .statusCode(200)
        .extract()
        .jsonPath();
  }

  private JsonPath await(Predicate<JsonPath> ready) throws InterruptedException {
    long deadline = System.nanoTime() + WAIT.toNanos();
    JsonPath json;
    do {
      json = kt();
      if (json.get("ct") != null && ready.test(json)) {
        return json;
      }
      Thread.sleep(100);
    } while (System.nanoTime() < deadline);
    throw new AssertionError(
        "KT-P1 nicht bereit: " + json.prettify() + "\nkartos: " + Kartos.kt.log());
  }

  private List<Map<String, Object>> log(String topic) {
    return given()
        .port(admin.port())
        .get("/admin/log")
        .then()
        .statusCode(200)
        .extract()
        .jsonPath()
        .getList("findAll { it.topic == '" + topic + "' }");
  }

  @Test
  @Order(1)
  @DisplayName(
      "TUC_KON_050 mit Shared Secret aus der YAML: TLS, VALIDATE bestanden, CT.CONNECTED = Ja, CT/CONNECTED")
  void bootMitYamlSecret() throws InterruptedException {
    JsonPath kt = await(json -> json.getBoolean("ct.CONNECTED"));
    assertEquals("aktiv", kt.getString("ct.CORRELATION"));
    assertEquals("User", kt.getString("ct.ACTIVEROLE"));
    assertEquals(true, kt.getBoolean("ct.SHARED_SECRET"));
    assertTrue(kt.getString("ct.SMKT_AUT.subject").contains("80276883110000148887"));
    fingerprint = kt.getString("ct.SMKT_AUT.fingerprint");
    assertNotNull(fingerprint);
    assertEquals(
        "KT-P1",
        log("CT/CONNECTED").getFirst().get("parameters") instanceof Map<?, ?> p
            ? p.get("CtID")
            : null);
  }

  @Test
  @Order(2)
  @DisplayName(
      "TUC_KON_050 Schritt 8 (4029): mit fremdem Shared Secret besteht das KT VALIDATE nicht und wird nicht "
          + "verwendet – Korrelation „gepairt“, CT.CONNECTED = Nein, klare Meldung")
  void fremdesSharedSecret() {
    given()
        .port(admin.port())
        .contentType("application/json")
        .body("{\"sharedSecret\":\"" + FOREIGN_SECRET + "\"}")
        .put("/admin/terminals/KT-P1/pairing")
        .then()
        .statusCode(409)
        .body("code", equalTo(4029))
        .body("error", containsString("VALIDATE"))
        .body("error", containsString("anderen Pairing"));
    JsonPath kt = kt();
    assertEquals(false, kt.getBoolean("ct.CONNECTED"));
    assertEquals("gepairt", kt.getString("ct.CORRELATION"));
    Map<?, ?> failure = (Map<?, ?>) log("CT/TLS_ESTABLISHMENT_FAILURE").getLast().get("parameters");
    assertEquals("4029", failure.get("Error"));
    assertEquals(
        "KT-P1",
        ((Map<?, ?>) log("CT/DISCONNECTED").getLast().get("parameters")).get("CtID"),
        "TIP1-A_4537: die alte Arbeitsverbindung endet");
  }

  @Test
  @Order(3)
  @DisplayName(
      "decision-4: POST /admin/reset stellt das Shared Secret der YAML her, TUC_KON_050 verbindet wieder")
  void resetStelltYamlHer() throws InterruptedException {
    given().port(admin.port()).post("/admin/reset").then().statusCode(200);
    JsonPath kt = await(json -> json.getBoolean("ct.CONNECTED"));
    assertEquals("aktiv", kt.getString("ct.CORRELATION"));
  }

  @Test
  @Order(4)
  @DisplayName(
      "TUC_KON_050 Schritt 8 (4029): KT mit fremdem Pairing – der Block mit dem Shared Secret der YAML "
          + "gehört zum Schlüssel eines anderen Konnektors, das KT beantwortet VALIDATE mit 6900 (gemSpec_KT TIP1-A_3126)")
  void fremdesPairingImKt() {
    Kartos.kt.pairingStore(KartosTerminal.pairingBlock(YAML_SECRET, OTHER_KONNEKTOR_KEY));
    given()
        .port(admin.port())
        .contentType("application/json")
        .body("{\"sharedSecret\":\"" + YAML_SECRET + "\"}")
        .put("/admin/terminals/KT-P1/pairing")
        .then()
        .statusCode(409)
        .body("code", equalTo(4029))
        .body("error", containsString("VALIDATE 6900"))
        .body("error", containsString("anderen Pairing"));
    JsonPath kt = kt();
    assertEquals(false, kt.getBoolean("ct.CONNECTED"));
    assertEquals("gepairt", kt.getString("ct.CORRELATION"));
    assertEquals(
        "4029",
        ((Map<?, ?>) log("CT/TLS_ESTABLISHMENT_FAILURE").getLast().get("parameters")).get("Error"));
  }

  @Test
  @Order(5)
  @DisplayName(
      "TUC_KON_053: Pairing löschen, abgelehnter Fingerprint (4041), dann initiales Pairing per Admin-API – "
          + "KT aktiv und verbunden, kartos hat einen neuen Pairing-Block")
  void initialesPairing() throws InterruptedException {
    given()
        .port(admin.port())
        .delete("/admin/terminals/KT-P1/pairing")
        .then()
        .statusCode(200)
        .body("ct.CORRELATION", equalTo("zugewiesen"))
        .body("ct.CONNECTED", equalTo(false))
        .body("ct.SHARED_SECRET", equalTo(false));

    given()
        .port(admin.port())
        .contentType("application/json")
        .body("{\"fingerprint\":\"00:11\"}")
        .post("/admin/terminals/KT-P1/pairing")
        .then()
        .statusCode(409)
        .body("code", equalTo(4041))
        .body("error", containsString("nicht bestätigt"));
    assertEquals("zugewiesen", kt().getString("ct.CORRELATION"));

    String before = Kartos.kt.pairingStore();
    given()
        .port(admin.port())
        .contentType("application/json")
        .body("{\"fingerprint\":\"" + fingerprint + "\"}")
        .post("/admin/terminals/KT-P1/pairing")
        .then()
        .statusCode(200)
        .body("ct.CORRELATION", equalTo("aktiv"))
        .body("ct.CONNECTED", equalTo(true))
        .body("ct.SHARED_SECRET", equalTo(true))
        .body("ct.SMKT_AUT.fingerprint", equalTo(fingerprint));
    String after = Kartos.kt.pairingStore();
    assertTrue(
        after.split("shared_secret").length > before.split("shared_secret").length,
        "kartos speichert einen weiteren Pairing-Block: " + after);
  }

  private static KtTls client(SmktCertificateCheck check) throws Exception {
    return new KtTls(
        TlsIdentity.load(Path.of("support/pki/server/sak-aut-bp256.p12"), "liana"), check);
  }

  @Test
  @Order(6)
  @DisplayName(
      "TUC_KON_050 Schritt 3 (aus KtTlsKartosIT, LIANA-125): TLS 1.2 mit ID.SAK.AUT, ECDHE-ECDSA auf "
          + "brainpoolP256r1, C.SMKT.AUT der gsmckt-valid gegen die TSL geprüft")
  void tlsZumKt() throws Exception {
    var tls =
        client(
            SmktCertificateCheck.of(
                TrustSpace.load(Path.of("support/pki/tsl/ECC-RSA_TSL-ref.xml"), List.of()),
                Clock.systemUTC()));
    try (SSLSocket socket = tls.connect("127.0.0.1", Kartos.kt.port(), WAIT)) {
      assertEquals("TLSv1.2", socket.getSession().getProtocol());
      assertTrue(
          socket.getSession().getCipherSuite().startsWith("TLS_ECDHE_ECDSA_WITH_AES_"),
          socket.getSession().getCipherSuite());
      assertTrue(socket.getSession().getPeerPrincipal().getName().contains("80276883110000148887"));
    }
  }

  @Test
  @Order(7)
  @DisplayName(
      "TUC_KON_050 Schritt 3 (4028, aus KtTlsKartosIT, LIANA-125): ist C.SMKT.AUT nicht prüfbar (Aussteller "
          + "unbekannt), bricht der Handshake ab")
  void ktZertifikatAbgewiesen() throws Exception {
    var tls = client(new SmktCertificateCheck(certificate -> Optional.empty(), Clock.systemUTC()));
    assertThrows(IOException.class, () -> tls.connect("127.0.0.1", Kartos.kt.port(), WAIT));
  }
}

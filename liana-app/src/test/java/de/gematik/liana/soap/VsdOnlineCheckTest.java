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
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import de.gematik.liana.TestPorts;
import de.gematik.liana.admin.AdminServer;
import de.gematik.liana.kern.card.CardList;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Onlineprüfung of ReadVSD (LIANA-141) with the chain {@code [ufs, fixed]} against a stub UFS (JDK
 * HttpServer) on {@link TestPorts#UFS}; MAXTIME_VSDM 3 s, TIMEOUT_VSDM 10 s, so that a hanging UFS
 * uses up the whole chain.
 */
@QuarkusTest
@TestProfile(VsdOnlineCheckTest.Profile.class)
class VsdOnlineCheckTest {

  public static class Profile implements QuarkusTestProfile {
    @Override
    public Map<String, String> getConfigOverrides() {
      return TestPorts.config(
          "liana.vsdm.online.sources", "ufs,fixed",
          "liana.vsdm.online.ufs.endpoints[0].url", "http://127.0.0.1:" + TestPorts.UFS + "/ufs",
          "liana.vsdm.online.ufs.endpoints[0].provider-id", "109500969",
          "liana.vsdm.online.ufs.retry-after", "0s",
          "liana.vsdm.max-time", "3s",
          "liana.vsdm.timeout", "10s");
    }
  }

  private static final String RECEIPT = "UHLDvGZ6aWZmZXIgZGVzIFVGUw==";
  private static final String NO_UPDATE =
      """
            <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>\
            <r:GetUpdateFlagsResponse xmlns:r="http://ws.gematik.de/cm/uf/CmUfServiceResponse/v2.0" \
            xmlns:CM="http://ws.gematik.de/cm/common/CmCommon/v2.0"><CM:ServiceReceipt><CM:ServiceLocalization>\
            <CM:Type>UFS</CM:Type><CM:Provider>109500969</CM:Provider></CM:ServiceLocalization>\
            <CM:Receipt>%s</CM:Receipt></CM:ServiceReceipt></r:GetUpdateFlagsResponse></soap:Body>\
            </soap:Envelope>"""
          .formatted(RECEIPT);
  private static final String UPDATE_PENDING =
      """
            <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>\
            <r:GetUpdateFlagsResponse xmlns:r="http://ws.gematik.de/cm/uf/CmUfServiceResponse/v2.0" \
            xmlns:CM="http://ws.gematik.de/cm/common/CmCommon/v2.0"><CM:UpdateFlag><CM:ServiceLocalization>\
            <CM:Type>VSD</CM:Type><CM:Provider>GEMTK</CM:Provider></CM:ServiceLocalization>\
            <CM:UpdateId>0A0B</CM:UpdateId><CM:UpdatePriority>MANDATORY</CM:UpdatePriority>\
            <CM:ShortDescription>VSD</CM:ShortDescription></CM:UpdateFlag></r:GetUpdateFlagsResponse>\
            </soap:Body></soap:Envelope>""";
  private static final DateTimeFormatter TS =
      DateTimeFormatter.ofPattern("yyyyMMddHHmmss").withZone(ZoneOffset.UTC);

  @Inject CardList cards;

  @Inject AdminServer admin;

  private HttpServer ufs;
  private volatile String answer = NO_UPDATE;
  private volatile long delayMillis;
  private final List<String> requests = new CopyOnWriteArrayList<>();
  private String egk;

  @BeforeEach
  void start() throws IOException {
    ufs = HttpServer.create(new InetSocketAddress("127.0.0.1", TestPorts.UFS), 0);
    ufs.createContext(
        "/ufs",
        exchange -> {
          requests.add(
              new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
          try {
            Thread.sleep(delayMillis);
          } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
          }
          byte[] body = answer.getBytes(StandardCharsets.UTF_8);
          exchange.getResponseHeaders().add("Content-Type", "text/xml; charset=utf-8");
          exchange.sendResponseHeaders(200, body.length);
          exchange.getResponseBody().write(body);
          exchange.close();
        });
    ufs.start();
    egk = cards.card("KT-01", 1).orElseThrow().cardHandle();
    verifyPin(cards.card("KT-01", 2).orElseThrow().cardHandle());
  }

  @AfterEach
  void stop() {
    ufs.stop(0);
    given().port(admin.port()).post("/admin/reset").then().statusCode(200);
  }

  private String check() throws Exception {
    String smcb = cards.card("KT-01", 2).orElseThrow().cardHandle();
    return pruefungsnachweis(
        bodyElement(readVsd(egk, smcb, true, true).statusCode(200).extract().asString()));
  }

  private void source(String expected) {
    given()
        .port(admin.port())
        .get("/admin/vsdm/online-checks")
        .then()
        .statusCode(200)
        .body("sources", contains("ufs", "fixed"))
        .body("checks.find { it.cardHandle == '" + egk + "' }.source", equalTo(expected));
  }

  @Test
  @DisplayName(
      "Tab_FM_VSDM_04 / Tab_FM_VSDM_05-01: Stub-UFS ohne Aktualisierungsauftrag → Ergebnis 2 mit dessen "
          + "Prüfziffer unverändert; GetUpdateFlags mit der ICCSN aus EF.GDO und der ProviderID im Header")
  void ufs() throws Exception {
    String pn = check();

    assertTrue(pn.contains("<E>2</E><PZ>" + RECEIPT + "</PZ>"), pn);
    String request = requests.getFirst();
    assertTrue(request.contains("<CM:Provider>109500969</CM:Provider>"), request);
    assertTrue(
        request.contains(
            "<CM:Iccsn>" + cards.card("KT-01", 1).orElseThrow().data().iccsn() + "</CM:Iccsn>"),
        request);
    source("ufs");
  }

  @Test
  @DisplayName(
      "VSDM-A_2597: Stub-UFS meldet ein Update, kein CCS → Ergebnis 3, kein Durchfallen zu fixed")
  void ausstehendesUpdate() throws Exception {
    answer = UPDATE_PENDING;

    String pn = check();

    assertTrue(pn.contains("<E>3</E>"), pn);
    assertFalse(pn.contains("<PZ>"), pn);
    source("ufs");
  }

  @Test
  @DisplayName(
      "LIANA-141: UFS nicht erreichbar → nächste Stufe fixed: Ergebnis 2, Prüfziffer im Testhub-Format, "
          + "Timestamp aktuell; Grund im Systemprotokoll")
  void nichtErreichbarFixed() throws Exception {
    ufs.stop(0);
    Instant before = Instant.now().minusSeconds(1);

    String pn = check();

    // vsdm-server-simservice ChecksumService.calculateChecksum("X110630769"), here as
    // xs:base64Binary
    assertTrue(
        pn.contains(
            "<E>2</E><PZ>LxZ54CsBMSQaFMP04r/v/SGEItJtsElbiHZ9ES4eCMlCR+CfHOCgJJbjXcQV84tY</PZ>"),
        pn);
    String ts = pn.replaceAll(".*<TS>(\\d{14})</TS>.*", "$1");
    Instant timestamp = Instant.from(TS.parse(ts));
    assertTrue(!timestamp.isBefore(before) && !timestamp.isAfter(Instant.now()), ts);
    source("fixed");
    given()
        .port(admin.port())
        .get("/admin/log")
        .then()
        .statusCode(200)
        .body(
            "findAll { it.topic == 'LIANA/VSDM/ONLINE_CHECK' }.last().parameters.Skipped",
            org.hamcrest.Matchers.containsString("nicht erreichbar"));
  }

  @Test
  @DisplayName(
      "VSDM-A_2998: UFS hängt → Abbruch nach MAXTIME_VSDM (3 s) mit Ergebnis 3, fixed nicht mehr gefragt")
  void maxtime() throws Exception {
    delayMillis = 6000;
    long start = System.nanoTime();

    String pn = check();

    long millis = (System.nanoTime() - start) / 1_000_000;
    assertTrue(pn.contains("<E>3</E>"), pn);
    assertTrue(millis < 5000, millis + " ms");
    source("spec");
    given()
        .port(admin.port())
        .get("/admin/log")
        .then()
        .statusCode(200)
        .body(
            "findAll { it.topic == 'LIANA/VSDM/ONLINE_CHECK' }.last().severity",
            equalTo("Warning"));
  }

  @Test
  @DisplayName(
      "LIANA-126 strict: UFS nicht erreichbar, kein Durchfallen zu fixed → Ergebnis 3 nach der Spec")
  void strict() throws Exception {
    ufs.stop(0);
    given()
        .port(admin.port())
        .contentType("application/json")
        .body("{\"strict\":true}")
        .put("/admin/vendor")
        .then()
        .statusCode(200);

    String pn = check();

    assertTrue(pn.contains("<E>3</E>"), pn);
    assertFalse(pn.contains("<PZ>"), pn);
    source("spec");
    given()
        .port(admin.port())
        .get("/admin/vsdm/online-checks")
        .then()
        .body(
            "checks.find { it.cardHandle == '" + egk + "' }.skipped",
            hasItem("fixed: abgeschaltet (strict)"));
    assertEquals(0, requests.size());
  }
}

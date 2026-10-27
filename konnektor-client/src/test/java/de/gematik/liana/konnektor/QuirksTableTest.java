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
package de.gematik.liana.konnektor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/** LIANA-134: product detection via the quirks table from liana-contract. */
class QuirksTableTest {

  private static final QuirksTable TABLE = QuirksTable.standard();

  private static Product product(String vendorId, String code) {
    return new Product(vendorId, code, null, null, null, null, null);
  }

  /** Test transport with LIANA's SDS, ProductVendorID replaced. */
  private static KonnektorTest.FakeTransport lianaAs(String vendorId) {
    return new KonnektorTest.FakeTransport() {
      @Override
      public Response send(Request request) throws IOException {
        if (!request.method().equals("GET")) {
          return super.send(request);
        }
        requests.add(request);
        try (InputStream in = QuirksTableTest.class.getResourceAsStream("/sds/liana.xml")) {
          String sds =
              new String(in.readAllBytes(), StandardCharsets.UTF_8)
                  .replace("<PI:ProductVendorID>LIANA<", "<PI:ProductVendorID>" + vendorId + "<");
          return new Response(200, "application/xml", sds.getBytes(StandardCharsets.UTF_8));
        }
      }
    };
  }

  @Test
  @DisplayName(
      "Jeder Eintrag hat eine Quelle; LIANA-Profile übernehmen die Abweichungen des Herstellers und die "
          + "eigenen Lücken (decision-12)")
  void tabelle() {
    for (QuirksTable.KnownProduct product : TABLE.products()) {
      product.quirks().forEach(q -> assertFalse(q.source().isBlank(), q.id()));
      product.gaps().forEach(g -> assertFalse(g.source().isBlank(), g.operation()));
    }
    QuirksTable.KnownProduct koco = TABLE.byId("LIANA-KOCO").orElseThrow();
    assertEquals("4005", koco.quirk("error.unknown-client-system").orElseThrow().actual());
    assertTrue(koco.gap(Operation.VERIFY_CERTIFICATE).isPresent());
    assertTrue(koco.gap(Operation.SIGN_DOCUMENT).orElseThrow().accessCheckOnly());
    assertTrue(
        TABLE.byId("KOCO").orElseThrow().gaps().isEmpty(), "reale KoCoBox ohne LIANA-Lücken");
  }

  @Test
  @DisplayName(
      "LIANA-134 AC 1: LIANA neutral und je Herstellerprofil (ProductCode LIANA) erkannt, reale Hersteller "
          + "ohne ProductCode LIANA")
  void erkennung() {
    assertEquals("LIANA", TABLE.match(product("LIANA", "LIANA")).orElseThrow().id());
    assertEquals("LIANA-KOCO", TABLE.match(product("KOCOC", "LIANA")).orElseThrow().id());
    assertEquals("LIANA-RISE", TABLE.match(product("RISEG", "LIANA")).orElseThrow().id());
    assertEquals("LIANA-SECUNET", TABLE.match(product("SECUN", "LIANA")).orElseThrow().id());
    assertEquals("KOCO", TABLE.match(product("KOCOC", "KoCoBox")).orElseThrow().id());
    assertEquals("SECUNET", TABLE.match(product("SECUN", "secu_kon")).orElseThrow().id());
  }

  @Test
  @DisplayName(
      "LIANA-134: Konnektor.info() und supports() aus SDS und Tabelle; nicht umgesetzte Operation scheitert "
          + "sofort, ohne Aufruf")
  void konnektor() throws Exception {
    KonnektorTest.FakeTransport transport = lianaAs("KOCOC");
    try (Konnektor kon =
        Konnektor.builder()
            .url("https://kon")
            .context("M1", "CS1", "WP1", null)
            .transport(transport)
            .build()) {
      KonnektorInfo info = kon.info();
      assertEquals("KOCOC", info.product().vendorId());
      assertEquals("LIANA-KOCO", info.known().orElseThrow().id());
      assertFalse(info.services().isEmpty());
      assertTrue(kon.supports(Operation.GET_CARDS));
      assertTrue(kon.supports(Operation.SIGN_DOCUMENT), "bis zur Zugriffsprüfung");
      assertFalse(kon.supports(Operation.VERIFY_CERTIFICATE));
      UnsupportedOperationException e =
          assertThrows(
              UnsupportedOperationException.class,
              () -> kon.invoke(Operation.VERIFY_CERTIFICATE, new Object(), Object.class));
      assertEquals(
          "CertificateService.VerifyCertificate: von LIANA, Herstellerprofil KOCO nicht umgesetzt "
              + "(decision-12, CertificateServiceResource (LIANA-136))",
          e.getMessage());
      assertEquals(1, transport.requests.size(), "nur connector.sds, kein SOAP-Aufruf");
    }
  }

  @Test
  @DisplayName(
      "LIANA-134 AC 2: unbekanntes Produkt – Rückfall auf das Dienstverzeichnis, kein Fehler")
  void unbekannt() throws Exception {
    try (Konnektor kon =
        Konnektor.builder()
            .url("https://kon")
            .context("M1", "CS1", "WP1", null)
            .transport(lianaAs("NEUER"))
            .build()) {
      assertEquals(Optional.empty(), kon.info().known());
      assertTrue(kon.supports(Operation.VERIFY_CERTIFICATE), "nur nach connector.sds");
    }
  }

  @Test
  @Tag("vendor-data")
  @DisplayName("Produkt fest vorgeben statt AUTO; secunet-Mitschnitt wird als SECUNET erkannt")
  void vorgegeben() throws Exception {
    try (Konnektor kon =
        Konnektor.builder()
            .url("https://kon")
            .context("M1", "CS1", "WP1", null)
            .product("RISE")
            .transport(lianaAs("NEUER"))
            .build()) {
      assertEquals("RISE", kon.info().known().orElseThrow().id());
    }
    try (Konnektor kon =
        Konnektor.builder()
            .url("http://localhost:11111")
            .context("M", "C", "W", null)
            .transport(
                new ReplayTransport(Path.of("support/vendor/traces/vsdm/vsdm-read-secunet.tgr")))
            .build()) {
      assertEquals("SECUNET", kon.info().known().orElseThrow().id());
    }
  }

  @Test
  @DisplayName("Ungültige Tabelle: Eintrag ohne Quelle, includes unbekannt oder im Kreis")
  void ungueltig() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            QuirksTable.parse(
                "{\"products\":[{\"id\":\"A\",\"vendorId\":\"A\",\"quirks\":[{\"id\":\"x\"}]}]}"));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            QuirksTable.parse(
                "{\"products\":[{\"id\":\"A\",\"vendorId\":\"A\",\"includes\":[\"B\"]}]}"));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            QuirksTable.parse(
                "{\"products\":[{\"id\":\"A\",\"includes\":[\"B\"]},{\"id\":\"B\",\"includes\":[\"A\"]}]}"));
  }
}

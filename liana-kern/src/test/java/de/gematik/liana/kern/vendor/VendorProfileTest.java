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
package de.gematik.liana.kern.vendor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import de.gematik.liana.kern.error.ConnectorError;
import java.util.EnumMap;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class VendorProfileTest {

  @Test
  @DisplayName(
      "decision-10: Herstellernamen unabhängig von Groß-/Kleinschreibung, neutral als eigener Wert")
  void of() {
    assertEquals(Vendor.NEUTRAL, Vendor.of("neutral"));
    assertEquals(Vendor.EHEX, Vendor.of("ehex"));
    assertEquals(Vendor.CGM, Vendor.of(" CGM "));
    assertEquals("neutral", Vendor.NEUTRAL.value());
    assertEquals("KOCO", Vendor.KOCO.value());
  }

  @Test
  @DisplayName("Unbekannter Hersteller nennt Wert und erlaubte Werte")
  void unknown() {
    IllegalArgumentException e =
        assertThrows(IllegalArgumentException.class, () -> Vendor.of("ACME"));
    assertEquals(
        "unbekannter Hersteller 'ACME', erlaubt: neutral, KOCO, RISE, SECUNET, EHEX, CGM",
        e.getMessage());
  }

  @Test
  @DisplayName("decision-4: Umschalten ist flüchtig, reset stellt den Boot-Stand her")
  void switchAndReset() {
    VendorProfile profile = new VendorProfile(Vendor.NEUTRAL);
    profile.switchTo(Vendor.EHEX);
    assertEquals(Vendor.EHEX, profile.vendor());
    profile.reset();
    assertEquals(Vendor.NEUTRAL, profile.vendor());
  }

  @Test
  @DisplayName("LIANA-55: EHEX-KMS bei EHEX und SECUNET, bei den übrigen Profilen keins")
  void ehexKms() {
    VendorProfile profile = new VendorProfile(Vendor.NEUTRAL);
    Map<Vendor, Boolean> kms = new EnumMap<>(Vendor.class);
    for (Vendor vendor : Vendor.values()) {
      profile.switchTo(vendor);
      kms.put(vendor, profile.ehexKms());
    }
    assertEquals(
        Map.of(
            Vendor.NEUTRAL,
            false,
            Vendor.KOCO,
            false,
            Vendor.RISE,
            false,
            Vendor.SECUNET,
            true,
            Vendor.EHEX,
            true,
            Vendor.CGM,
            false),
        kms);
  }

  @Test
  @DisplayName(
      "LIANA-96: KOCO-KMS bei KOCO und CGM (kms-client KmsKoco), bei den übrigen Profilen keins")
  void kocoKms() {
    VendorProfile profile = new VendorProfile(Vendor.NEUTRAL);
    Map<Vendor, Boolean> kms = new EnumMap<>(Vendor.class);
    for (Vendor vendor : Vendor.values()) {
      profile.switchTo(vendor);
      kms.put(vendor, profile.kocoKms());
    }
    assertEquals(
        Map.of(
            Vendor.NEUTRAL,
            false,
            Vendor.KOCO,
            true,
            Vendor.RISE,
            false,
            Vendor.SECUNET,
            false,
            Vendor.EHEX,
            false,
            Vendor.CGM,
            true),
        kms);
  }

  @Test
  @DisplayName(
      "LIANA-97: RISE-KMS nur bei RISE (konnektor-service-client RISEG, kms-client KmsRise)")
  void riseKms() {
    VendorProfile profile = new VendorProfile(Vendor.NEUTRAL);
    Map<Vendor, Boolean> kms = new EnumMap<>(Vendor.class);
    for (Vendor vendor : Vendor.values()) {
      profile.switchTo(vendor);
      kms.put(vendor, profile.riseKms());
    }
    assertEquals(
        Map.of(
            Vendor.NEUTRAL,
            false,
            Vendor.KOCO,
            false,
            Vendor.RISE,
            true,
            Vendor.SECUNET,
            false,
            Vendor.EHEX,
            false,
            Vendor.CGM,
            false),
        kms);
  }

  @Test
  @DisplayName(
      "LIANA-91: ProductVendorID in connector.sds wie die Konnektoren der Hersteller (KOCOC, SECUN, RISEG), "
          + "sonst LIANA")
  void productVendorId() {
    VendorProfile profile = new VendorProfile(Vendor.NEUTRAL);
    Map<Vendor, String> ids = new EnumMap<>(Vendor.class);
    for (Vendor vendor : Vendor.values()) {
      profile.switchTo(vendor);
      ids.put(vendor, profile.productVendorId());
    }
    assertEquals(
        Map.of(
            Vendor.NEUTRAL,
            "LIANA",
            Vendor.KOCO,
            "KOCOC",
            Vendor.RISE,
            "RISEG",
            Vendor.SECUNET,
            "SECUN",
            Vendor.EHEX,
            "LIANA",
            Vendor.CGM,
            "LIANA"),
        ids);
  }

  @Test
  @DisplayName(
      "LIANA-60 KUC_1702_007: nur KOCO meldet ein unbekanntes Clientsystem als 4005, ein unbekannter "
          + "Mandant bleibt bei allen 4021 (KUC_1603_008)")
  void protocolError() {
    VendorProfile profile = new VendorProfile(Vendor.NEUTRAL);
    Map<Vendor, Boolean> clientSystem = new EnumMap<>(Vendor.class);
    for (Vendor vendor : Vendor.values()) {
      profile.switchTo(vendor);
      clientSystem.put(vendor, profile.reportsProtocolError(ConnectorError.INVALID_CLIENT_SYSTEM));
      assertEquals(false, profile.reportsProtocolError(ConnectorError.INVALID_MANDANT));
    }
    assertEquals(
        Map.of(
            Vendor.NEUTRAL,
            false,
            Vendor.KOCO,
            true,
            Vendor.RISE,
            false,
            Vendor.SECUNET,
            false,
            Vendor.EHEX,
            false,
            Vendor.CGM,
            false),
        clientSystem);
  }

  @Test
  @DisplayName(
      "LIANA-60 KUC_1701_008: nur RISE wertet eine leere UserId als Syntaxfehler (4000); LIANA-167 "
          + "KUC_1701_031: als MTOM auch RISE nicht")
  void emptyUserId() {
    VendorProfile profile = new VendorProfile(Vendor.NEUTRAL);
    Map<Vendor, Boolean> syntax = new EnumMap<>(Vendor.class);
    for (Vendor vendor : Vendor.values()) {
      profile.switchTo(vendor);
      syntax.put(vendor, profile.emptyUserIdIsSyntaxError(false));
      assertEquals(false, profile.emptyUserIdIsSyntaxError(true), vendor.name());
    }
    assertEquals(
        Map.of(
            Vendor.NEUTRAL,
            false,
            Vendor.KOCO,
            false,
            Vendor.RISE,
            true,
            Vendor.SECUNET,
            false,
            Vendor.EHEX,
            false,
            Vendor.CGM,
            false),
        syntax);
  }
}

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
package de.gematik.liana.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.kern.error.ConnectorError;
import de.gematik.liana.kern.vendor.Vendor;
import de.gematik.liana.kern.vendor.VendorProfile;
import de.gematik.liana.konnektor.Product;
import de.gematik.liana.konnektor.QuirksTable;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * LIANA-134 AC 3: the quirks table from liana-contract and {@link VendorProfile} (decision-10)
 * agree. For each vendor profile, the client recognizes LIANA by the profile's {@code
 * ProductVendorID} and by the {@code ProductCode} LIANA, and every deviation that LIANA emulates
 * for the profile is listed as a quirk in the table, and vice versa.
 *
 * <p>Deviation from the ticket ("in der Konformitätssuite"): VendorProfile is only visible here;
 * the suite must not know LIANA's runtime (decision-016). The suite checks the recognition against
 * the running LIANA ({@code ProductIT}).
 */
class QuirksConsistencyTest {

  /** Quirk ID → emulated behavior in the profile. */
  private static final Map<String, Predicate<VendorProfile>> BEHAVIOUR =
      Map.of(
          "error.unknown-client-system",
              p -> p.reportsProtocolError(ConnectorError.INVALID_CLIENT_SYSTEM),
          "error.empty-user-id", p -> p.emptyUserIdIsSyntaxError(false),
          "sign.offline-warning", VendorProfile::warnsOfflineWithoutOcsp,
          "sign.smime-unsupported", VendorProfile::rejectsSmime,
          "sign.qes-format-first", VendorProfile::checksQesFormatFirst,
          "sign.qes-format-mismatch", VendorProfile::reportsQesFormatMismatch,
          "verify.malformed-xml", VendorProfile::reportsMalformedXmlAsSignatureType);

  @ParameterizedTest
  @EnumSource(Vendor.class)
  @DisplayName("Produkt der Tabelle je Herstellerprofil, Quirks wie das Profil")
  void profil(Vendor vendor) {
    VendorProfile profile = new VendorProfile(vendor);
    QuirksTable.KnownProduct product =
        QuirksTable.standard()
            .match(new Product(profile.productVendorId(), "LIANA", null, null, null, null, null))
            .orElseThrow();
    assertEquals("LIANA", product.productCode());
    assertTrue(product.id().startsWith("LIANA"), product.id());

    Set<String> expected = new HashSet<>();
    BEHAVIOUR.forEach(
        (id, behaviour) -> {
          if (behaviour.test(profile)) {
            expected.add(id);
          }
        });
    Set<String> inTable = new HashSet<>();
    product.quirks().forEach(q -> inTable.add(q.id()));
    // only quirks that LIANA can emulate; the others are listed for the real vendors (such as the
    // SDS
    // namespace)
    inTable.retainAll(BEHAVIOUR.keySet());
    assertEquals(expected, inTable, vendor + " → " + product.id());
  }

  @ParameterizedTest
  @EnumSource(Vendor.class)
  @DisplayName("Jeder Quirk eines LIANA-Produkts ist ein Verhalten von VendorProfile")
  void keineUnbekanntenQuirks(Vendor vendor) {
    VendorProfile profile = new VendorProfile(vendor);
    QuirksTable.standard()
        .match(new Product(profile.productVendorId(), "LIANA", null, null, null, null, null))
        .orElseThrow()
        .quirks()
        .forEach(
            q -> assertTrue(BEHAVIOUR.containsKey(q.id()), q.id() + " bildet LIANA nicht nach"));
  }
}

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
package de.gematik.liana;

import static com.tngtech.archunit.core.domain.JavaClass.Predicates.equivalentTo;
import static com.tngtech.archunit.core.domain.JavaFieldAccess.Predicates.target;
import static com.tngtech.archunit.core.domain.properties.HasOwner.Predicates.With.owner;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.lang.ArchRule;
import de.gematik.liana.kern.vendor.Vendor;
import de.gematik.liana.kern.vendor.VendorProfile;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * decision-10, LIANA-62: only {@code kern.vendor} ({@link VendorProfile}) branches on the vendor.
 * Outside of it, code may read and report the profile ({@link Vendor#value()}, {@link
 * Vendor#of(String)}), but must not refer to a vendor constant ({@code == Vendor.KOCO}, {@code
 * switch}) nor compare by name or ordinal.
 */
class VendorArchitectureTest {

  private static final ArchRule NO_VENDOR_BRANCHES =
      noClasses()
          .that()
          .resideOutsideOfPackage("de.gematik.liana.kern.vendor..")
          .should()
          .accessFieldWhere(target(owner(equivalentTo(Vendor.class))))
          .orShould()
          .callMethod(Vendor.class, "name")
          .orShould()
          .callMethod(Vendor.class, "ordinal")
          .orShould()
          .callMethod(Vendor.class, "values")
          .orShould()
          .callMethod(Vendor.class, "valueOf", String.class)
          .because("herstellerabhängiges Verhalten steht nur in VendorProfile (decision-10)");

  @Test
  @DisplayName("decision-10: Herstellerabfragen nur in kern.vendor, in allen LIANA-Modulen")
  void vendorBranchesOnlyInProfile() {
    NO_VENDOR_BRANCHES.check(
        new ClassFileImporter()
            .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
            .importPackages("de.gematik.liana"));
  }

  @Test
  @DisplayName(
      "Gegenprobe: Vergleich mit einer Herstellerkonstante und switch über Vendor verletzen die Regel")
  void ruleCatchesBranches() {
    assertTrue(
        NO_VENDOR_BRANCHES
            .evaluate(new ClassFileImporter().importClasses(CompareBranch.class))
            .hasViolation());
    assertTrue(
        NO_VENDOR_BRANCHES
            .evaluate(new ClassFileImporter().importClasses(SwitchBranch.class))
            .hasViolation());
  }

  static final class CompareBranch {
    String code(VendorProfile profile) {
      return profile.vendor() == Vendor.KOCO ? "4005" : "4021";
    }
  }

  static final class SwitchBranch {
    String code(Vendor vendor) {
      switch (vendor) {
        case KOCO:
          return "4005";
        default:
          return "4021";
      }
    }
  }
}

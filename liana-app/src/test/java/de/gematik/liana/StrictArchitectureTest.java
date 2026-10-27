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

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.lang.ArchRule;
import de.gematik.liana.kern.vendor.PeerDeviations;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * LIANA-126: only {@link PeerDeviations#tolerate} branches on {@code liana.strict}, so that every
 * tolerated deviation is named as a {@code Deviation} and appears in the Systemprotokoll. Apart
 * from {@code kern.vendor}, only the Admin API may read and set the switch.
 */
class StrictArchitectureTest {

  private static final ArchRule NO_STRICT_BRANCHES =
      noClasses()
          .that()
          .resideOutsideOfPackages("de.gematik.liana.kern.vendor..", "de.gematik.liana.admin..")
          .should()
          .callMethod(PeerDeviations.class, "strict")
          .orShould()
          .callMethod(PeerDeviations.class, "boot")
          .orShould()
          .callMethod(PeerDeviations.class, "setStrict", boolean.class)
          .because("tolerierte Abweichungen laufen über PeerDeviations.tolerate (LIANA-126)");

  @Test
  @DisplayName("LIANA-126: strict nur über PeerDeviations.tolerate, in allen LIANA-Modulen")
  void strictOnlyThroughTolerate() {
    NO_STRICT_BRANCHES.check(
        new ClassFileImporter()
            .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
            .importPackages("de.gematik.liana"));
  }

  @Test
  @DisplayName("Gegenprobe: eine Abfrage von strict() an der Gegenstelle verletzt die Regel")
  void ruleCatchesBranches() {
    assertTrue(
        NO_STRICT_BRANCHES
            .evaluate(new ClassFileImporter().importClasses(StrictBranch.class))
            .hasViolation());
  }

  static final class StrictBranch {
    byte ins(PeerDeviations deviations) {
      return deviations.strict() ? (byte) 0x19 : (byte) 0x1A;
    }
  }
}

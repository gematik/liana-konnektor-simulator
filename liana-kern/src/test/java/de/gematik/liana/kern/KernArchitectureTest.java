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
package de.gematik.liana.kern;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * decision-8: the core depends only on the JDK and on itself. From {@code javax.*} only the X.500
 * names the CardReader needs for the AUT certificate.
 */
class KernArchitectureTest {

  @Test
  @DisplayName(
      "de.gematik.liana.kern importiert nur java.*, X.500-Namen aus javax.* und sich selbst")
  void kernDependsOnlyOnJavaAndItself() {
    JavaClasses kern =
        new ClassFileImporter()
            .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
            .importPackages("de.gematik.liana.kern");
    classes()
        .should()
        .onlyDependOnClassesThat()
        .resideInAnyPackage(
            "java..", "javax.security.auth.x500..", "javax.naming..", "de.gematik.liana.kern..")
        .check(kern);
  }
}

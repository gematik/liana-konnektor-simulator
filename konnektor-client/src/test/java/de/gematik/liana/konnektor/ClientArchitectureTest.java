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

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import java.security.Provider;
import java.security.Security;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** LIANA-133 AC 4: the client registers no global security provider (decision-016). */
class ClientArchitectureTest {

  @Test
  @DisplayName(
      "konnektor-client ruft weder Security.addProvider noch insertProviderAt noch setProperty auf")
  void keineGlobalenProvider() {
    noClasses()
        .should()
        .callMethod(Security.class, "addProvider", Provider.class)
        .orShould()
        .callMethod(Security.class, "insertProviderAt", Provider.class, int.class)
        .orShould()
        .callMethod(Security.class, "setProperty", String.class, String.class)
        .orShould()
        .callMethod(System.class, "setProperty", String.class, String.class)
        .because("der Client verändert die JVM des Primärsystems nicht")
        .check(
            new ClassFileImporter()
                .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
                .importPackages("de.gematik.liana.konnektor"));
  }
}

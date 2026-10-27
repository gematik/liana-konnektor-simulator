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
package de.gematik.liana.kern.management;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.gematik.liana.kern.management.ClientSystemBinding.Authentication;
import de.gematik.liana.kern.management.ClientSystemBinding.State;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class ClientSystemBindingTest {

  private static final State BOOT = new State(false, Authentication.NONE, true, true, false);

  @ParameterizedTest(name = "TLS_MANDATORY {0}, DVD_OPEN {1}: SOAP {2}, connector.sds {3}")
  @DisplayName(
      "TIP1-A_4515, TAB_KON_852: Aufrufe ohne TLS je nach ANCL_TLS_MANDATORY und ANCL_DVD_OPEN")
  @CsvSource({
    "false, false, true,  true", // SOAP4, DVD3
    "false, true,  true,  true", // SOAP4, DVD1
    "true,  true,  false, true", // SOAP1-3, DVD1
    "true,  false, false, false"
  }) // SOAP1-3, DVD2
  void plainHttp(boolean tlsMandatory, boolean dvdOpen, boolean soap, boolean sds) {
    State state = BOOT.withTlsMandatory(tlsMandatory).withDvdOpen(dvdOpen);
    assertEquals(soap, state.allowsPlainHttp(false));
    assertEquals(sds, state.allowsPlainHttp(true));
  }

  @Test
  @DisplayName("decision-4: Änderungen sind flüchtig, reset stellt den Boot-Stand her")
  void reset() {
    ClientSystemBinding binding = new ClientSystemBinding(BOOT);
    binding.state(
        BOOT.withTlsMandatory(true)
            .withAuthentication(Authentication.CERTIFICATE)
            .withEccForClientSystems(false)
            .withServerSoftwareKey(true));
    assertEquals(new State(true, Authentication.CERTIFICATE, true, false, true), binding.state());
    binding.reset();
    assertEquals(BOOT, binding.state());
  }
}

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
package de.gematik.liana.sds;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.gematik.liana.adapter.sds.ServiceDirectoryResource;
import de.gematik.liana.kern.management.ClientSystemBinding;
import de.gematik.liana.kern.vendor.Vendor;
import de.gematik.liana.kern.vendor.VendorProfile;
import io.quarkus.qute.Location;
import io.quarkus.qute.Template;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.path.xml.XmlPath;
import jakarta.inject.Inject;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * LIANA-86 with a fixed clock. Separate class because {@link ServiceDirectoryResourceIT} inherits
 * from {@link ServiceDirectoryResourceTest} and integration tests do not allow {@code @Inject}.
 */
@QuarkusTest
class ServiceDirectoryInformationDateTest {

  @Inject
  @Location("connector.sds.xml")
  Template template;

  @Test
  @DisplayName(
      "TIP1-A_4529-02 InformationDate zur vollen Minute hat Sekunden (…T12:06:00Z) und ist valide gegen "
          + "conn/ServiceDirectory.xsd (LIANA-86)")
  void informationDateOnFullMinute() throws Exception {
    Clock fullMinute = Clock.fixed(Instant.parse("2026-10-09T12:06:00.400Z"), ZoneOffset.UTC);
    String sds =
        new ServiceDirectoryResource(
                template,
                "http://localhost:8080",
                "https://localhost:8443",
                new ClientSystemBinding(
                    new ClientSystemBinding.State(
                        false, ClientSystemBinding.Authentication.NONE, true, true, false)),
                "0.0.0",
                fullMinute,
                new VendorProfile(Vendor.NEUTRAL))
            .get();
    assertEquals(
        "2026-10-09T12:06:00Z",
        new XmlPath(sds).getString("ConnectorServices.ProductInformation.InformationDate"));
    XsdValidator.validate("conn/ServiceDirectory.xsd", sds);
  }
}

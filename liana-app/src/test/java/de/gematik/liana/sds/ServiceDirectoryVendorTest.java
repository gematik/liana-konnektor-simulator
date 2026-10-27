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

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.gematik.liana.kern.vendor.Vendor;
import de.gematik.liana.kern.vendor.VendorProfile;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.path.xml.XmlPath;
import jakarta.inject.Inject;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** {@code ProductVendorID} in {@code connector.sds} per vendor profile (LIANA-91). */
@QuarkusTest
class ServiceDirectoryVendorTest {

  @Inject VendorProfile vendor;

  private static String fromSds() {
    return new XmlPath(
            given().when().get("/connector.sds").then().statusCode(200).extract().asString())
        .getString("ConnectorServices.ProductInformation.ProductIdentification.ProductVendorID");
  }

  @Test
  @DisplayName(
      "LIANA-91 ProductVendorID folgt dem Herstellerprofil: SECUNET meldet SECUN (konnektor-service-client "
          + "wählt danach den KMS-Client), neutral LIANA")
  void productVendorId() {
    try {
      vendor.switchTo(Vendor.SECUNET);
      assertEquals("SECUN", fromSds());
    } finally {
      vendor.reset();
    }
    assertEquals("LIANA", fromSds());
  }
}

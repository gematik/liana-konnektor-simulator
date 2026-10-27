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

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.path.xml.XmlPath;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@QuarkusTest
@TestProfile(ServiceDirectoryUrlTest.DockerNetwork.class)
class ServiceDirectoryUrlTest {

  public static class DockerNetwork implements QuarkusTestProfile {
    @Override
    public Map<String, String> getConfigOverrides() {
      return Map.of(
          "liana.kon-export.url", "http://liana:8080/", "liana.tls.url", "https://liana:8443/");
    }
  }

  @Test
  @DisplayName(
      "Endpoint folgt liana.kon-export.url, EndpointTLS liana.tls.url (z. B. im Docker-Netz)")
  void endpointsFollowKonExportUrl() {
    XmlPath sds =
        new XmlPath(
            given().when().get("/connector.sds").then().statusCode(200).extract().asString());
    assertEquals(
        Services.endpoints("http://liana:8080"),
        sds
            .getList(
                "ConnectorServices.ServiceInformation.Service.Versions.Version.Endpoint.@Location")
            .stream()
            .distinct()
            .toList());
    assertEquals(
        Services.endpoints("https://liana:8443"),
        sds
            .getList(
                "ConnectorServices.ServiceInformation.Service.Versions.Version.EndpointTLS.@Location")
            .stream()
            .distinct()
            .toList());
  }
}

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
package de.gematik.liana.admin;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.gematik.liana.TestPorts;
import de.gematik.liana.sds.Services;
import de.gematik.liana.sds.XsdValidator;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.restassured.path.xml.XmlPath;
import java.net.URI;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * A client loads the exported {@code .kon} (§4 substitution, §3 JSON) and fetches {@code
 * <url>/connector.sds}. The URL points to the test port and ends with {@code /}, which the client
 * must tolerate (§5). Runs as {@link KonRoundTripTest} (JVM) and {@link KonRoundTripIT} (native
 * image).
 */
abstract class KonRoundTrip {

  public static class TestPort implements QuarkusTestProfile {
    @Override
    public Map<String, String> getConfigOverrides() {
      return TestPorts.config("liana.kon-export.url", "http://localhost:" + TestPorts.HTTP + "/");
    }
  }

  abstract int adminPort();

  @Test
  @DisplayName(
      "config.kon laden, <url>/connector.sds abrufen: valide gegen ServiceDirectory.xsd, Endpunkte umschreibbar")
  void roundTrip() throws Exception {
    String raw =
        given()
            .port(adminPort())
            .get("/admin/clients/CS1/config.kon")
            .then()
            .statusCode(200)
            .extract()
            .asString();
    var kon = KonFile.load(raw, Map.of());
    assertEquals(List.of(), KonValidator.errors(kon));

    String url = kon.get("url").asText().replaceFirst("/$", "");
    String sds =
        given().get(URI.create(url + "/connector.sds")).then().statusCode(200).extract().asString();
    XsdValidator.validate("conn/ServiceDirectory.xsd", sds);

    // rewriteServiceEndpoints (§5): only the path of the advertised endpoint remains, the base is
    // url
    assertEquals(true, kon.get("rewriteServiceEndpoints").asBoolean());
    List<String> rewritten =
        new XmlPath(sds)
                .<String>getList(
                    "ConnectorServices.ServiceInformation.Service.Versions.Version.Endpoint.@Location")
                .stream()
                .distinct()
                .map(location -> url + URI.create(location).getPath())
                .toList();
    assertEquals(Services.endpoints("http://localhost:" + TestPorts.HTTP), rewritten);
  }
}

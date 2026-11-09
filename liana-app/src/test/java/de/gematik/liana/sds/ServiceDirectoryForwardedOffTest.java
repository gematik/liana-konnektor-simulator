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
import io.restassured.specification.RequestSpecification;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** LIANA-217 with the switch off: only the {@code Host} header counts. */
@QuarkusTest
@TestProfile(ServiceDirectoryForwardedOffTest.ForwardedOff.class)
class ServiceDirectoryForwardedOffTest {

  public static class ForwardedOff implements QuarkusTestProfile {
    @Override
    public Map<String, String> getConfigOverrides() {
      return Map.of(
          "liana.endpoints.forwarded", "false", "liana.endpoints.public-tls-port", "28443");
    }
  }

  @Test
  @DisplayName("LIANA-217 liana.endpoints.forwarded=false: Forwarded und X-Forwarded-* ignoriert")
  void forwardedIgnored() {
    assertEquals(
        List.of("http://example.test:28080/ws/EventService"),
        ServiceDirectoryRequestTest.endpoints(request(), "Endpoint"));
    assertEquals(
        List.of("https://example.test:28443/ws/EventService"),
        ServiceDirectoryRequestTest.endpoints(request(), "EndpointTLS"));
  }

  private static RequestSpecification request() {
    return given()
        .header("Host", "example.test:28080")
        .header("Forwarded", "host=public.test;proto=https")
        .header("X-Forwarded-Host", "other.test");
  }
}

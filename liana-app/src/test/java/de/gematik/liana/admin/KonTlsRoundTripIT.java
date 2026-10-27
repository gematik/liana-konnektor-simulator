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

import de.gematik.liana.TestPorts;
import io.quarkus.test.junit.QuarkusIntegrationTest;
import io.quarkus.test.junit.TestProfile;

/**
 * mTLS round trip against the native image (prod profile, ports from TestPorts); runs with {@code
 * ./mvnw verify -Dnative}.
 */
@QuarkusIntegrationTest
@TestProfile(KonTlsRoundTrip.MutualTls.class)
class KonTlsRoundTripIT extends KonTlsRoundTrip {

  @Override
  int adminPort() {
    return TestPorts.ADMIN;
  }
}

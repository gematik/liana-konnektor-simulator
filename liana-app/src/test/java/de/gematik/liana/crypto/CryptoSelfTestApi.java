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
package de.gematik.liana.crypto;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;

import io.restassured.RestAssured;
import io.restassured.specification.RequestSpecification;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Crypto self-tests via the Admin API {@code GET /admin/selftest/crypto/{check}} (LIANA-149,
 * previously on the Konnektor port): {@link CryptoSelfTestApiTest} in JVM mode, {@link
 * CryptoSelfTestApiIT} against the native image.
 */
abstract class CryptoSelfTestApi {

  /** Management port. */
  abstract int port();

  private RequestSpecification given() {
    return RestAssured.given().port(port());
  }

  @Test
  @DisplayName("A_17207 ECDSA brainpoolP256r1/SHA-256 signieren und verifizieren")
  void brainpoolEcdsa() {
    given()
        .get("/admin/selftest/crypto/brainpool-ecdsa")
        .then()
        .statusCode(200)
        .body("ok", equalTo(true))
        .body("detail", containsString("brainpoolP256r1"));
  }

  @Test
  @DisplayName("ES256-JWS (P-256) mit x5c-Kette verifizieren, fremde Root ablehnen")
  void es256Jws() {
    given()
        .get("/admin/selftest/crypto/es256-jws")
        .then()
        .statusCode(200)
        .body("ok", equalTo(true))
        .body("detail", containsString("x5c mit 2 Zertifikaten"));
  }

  @Test
  @DisplayName(
      "A_17124-03 TLS-1.2-Loopback über BCJSSE mit brainpoolP256r1-Zertifikaten und -ECDHE")
  void brainpoolTls12() {
    given()
        .get("/admin/selftest/crypto/brainpool-tls12")
        .then()
        .statusCode(200)
        .body("ok", equalTo(true))
        .body("detail", containsString("TLSv1.2 TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"))
        .body("detail", containsString("CN=liana-server"))
        .body("detail", containsString("CN=liana-client"));
  }

  @Test
  @DisplayName(
      "LIANA-75 / TUC_KON_050 Schritt 3: KT-Client über BCJSSE mit ID.SAK.AUT, C.SMKT.AUT geprüft, SICCT "
          + "INIT CT SESSION; KT-Zertifikat ohne oid_smkt_aut abgelehnt")
  void sicctTls() {
    given()
        .get("/admin/selftest/crypto/sicct-tls")
        .then()
        .statusCode(200)
        .body("ok", equalTo(true))
        .body("detail", containsString("INIT CT SESSION → 9000"))
        .body("detail", containsString("Gegenprobe ohne oid_smkt_aut abgelehnt"));
  }

  @Test
  @DisplayName(
      "Unbekannter Check liefert 404 mit den bekannten; der Konnektor-Port kennt die Selbsttests nicht mehr")
  void unknownCheck() {
    given()
        .get("/admin/selftest/crypto/gibts-nicht")
        .then()
        .statusCode(404)
        .body("error", containsString("brainpool-ecdsa"));
    RestAssured.given().get("/selftest/crypto/brainpool-ecdsa").then().statusCode(404);
  }
}

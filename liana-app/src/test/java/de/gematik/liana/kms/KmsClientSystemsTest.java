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
package de.gematik.liana.kms;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.TlsProbe;
import de.gematik.liana.admin.AdminServer;
import de.gematik.liana.crypto.CryptoProviders;
import de.gematik.liana.crypto.TlsKeys;
import de.gematik.liana.tls.KonnektorTlsServer;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.specification.RequestSpecification;
import jakarta.inject.Inject;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * LIANA-65: binding of Clientsysteme via the EHEX KMS, each operation with its effect on the
 * Konnektor interface (HTTP port and {@link KonnektorTlsServer}), without process restart. Paths
 * and fields as in kms-client {@code KmsEhex} (see {@link EhexClientSystems}); the rejection cases
 * according to A_21811-05 are those of the CATS_CS scenarios of Konnektor-E2E (EE_KON_CS_*,
 * EE_HSK_CS_*).
 */
@QuarkusTest
class KmsClientSystemsTest {

  private static final String LOGIN_BODY = "{\"username\":\"super\",\"password\":\"33ee§§EE\"}";
  private static final String CS1 = "/rest/mgmt/ak/info/clientsysteme/cs-1/zertifikat";

  @Inject AdminServer admin;

  @Inject KonnektorTlsServer tls;

  @TempDir Path dir;

  @BeforeEach
  void ehex() {
    given()
        .port(admin.port())
        .contentType("application/json")
        .body(Map.of("vendor", "EHEX"))
        .put("/admin/vendor")
        .then()
        .statusCode(200);
  }

  @AfterEach
  void reset() {
    given().port(admin.port()).post("/admin/reset").then().statusCode(200);
  }

  private RequestSpecification kms() {
    return given().relaxedHTTPSValidation().baseUri("https://localhost").port(admin.port());
  }

  private String login() {
    return kms()
        .contentType("application/json")
        .body(LOGIN_BODY)
        .post(EhexKms.LOGIN)
        .then()
        .statusCode(204)
        .extract()
        .header("Authorization");
  }

  private RequestSpecification authorized() {
    return kms().header("Authorization", login()).contentType("application/json");
  }

  /**
   * PUT of the settings group like kms-client: GET, change field, send back the whole object;
   * confirmation at 300.
   */
  private void putBinding(String field, Object value) {
    Map<String, Object> group =
        authorized()
            .get(EhexClientSystems.BINDING)
            .then()
            .statusCode(200)
            .extract()
            .jsonPath()
            .getMap("");
    group.put(field, value);
    var response = authorized().body(group).put(EhexClientSystems.BINDING);
    if (response.statusCode() == 300) {
      String token = response.jsonPath().getString("confirmationToken");
      authorized()
          .body(group)
          .put(EhexClientSystems.BINDING + "?confirmation=" + token)
          .then()
          .statusCode(200);
    } else {
      assertEquals(200, response.statusCode(), response.asString());
    }
  }

  private Map<String, Object> generateBody(String cryptType, String eccCurve, String password) {
    var body =
        new java.util.HashMap<String, Object>(Map.of("generateNew", true, "password", password));
    if (cryptType != null) {
      body.put("cryptType", cryptType);
    }
    if (eccCurve != null) {
      body.put("eccCurve", eccCurve);
    }
    return body;
  }

  private static KeyPair keys(String algorithm) throws Exception {
    if (algorithm.startsWith("RSA-")) {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
      generator.initialize(Integer.parseInt(algorithm.substring(4)));
      return generator.generateKeyPair();
    }
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", CryptoProviders.BC);
    generator.initialize(new ECGenParameterSpec(algorithm));
    return generator.generateKeyPair();
  }

  private static String pem(X509Certificate certificate) throws Exception {
    return "Bag Attributes\n    friendlyName: import\n-----BEGIN CERTIFICATE-----\n"
        + Base64.getMimeEncoder().encodeToString(certificate.getEncoded())
        + "\n-----END CERTIFICATE-----\n";
  }

  // Informationsmodell and Clientsystem certificates

  @Test
  @DisplayName(
      "AK Info: Infomodell mit Clientsystemen (interne ID), ANCL_CCERT_LIST aus der YAML beim ersten Clientsystem")
  void info() {
    authorized()
        .get(EhexClientSystems.INFO)
        .then()
        .statusCode(200)
        .body("clientSystems[0].clientSystemId", equalTo("CS1"))
        .body("clientSystems[0].internalId", equalTo("cs-1"))
        .body("mandanten.mandantId", hasItem("M1"));
    authorized()
        .get(EhexClientSystems.CLIENT_SYSTEMS)
        .then()
        .statusCode(200)
        .body("[0].certificates", hasSize(2))
        .body("[0].certificates[0].internalId", equalTo("cert-1"));
  }

  @ParameterizedTest(name = "{0} {1} → {2}")
  @DisplayName(
      "TIP1-A_4517-04, A_21811-05: CS-Zertifikat erzeugen (RSA → RSA-3072, ECC NIST_P256), PKCS#12 mit dem "
          + "Passwort des Administrators, Dateiname <ClientSystemId>.p12, steht in ANCL_CCERT_LIST und trägt mTLS")
  @CsvSource({"RSA, , RSA-3072", "ECC, NIST_P256, ECC-256 NIST P-256"})
  void generateClientCertificate(String cryptType, String eccCurve, String algorithm)
      throws Exception {
    var created =
        authorized()
            .body(generateBody(cryptType, eccCurve, "pw-123456"))
            .post(CS1)
            .then()
            .statusCode(201)
            .body("data.filename", equalTo("CS1.p12"))
            .extract()
            .jsonPath();
    String certId = created.getString("data.internalId");
    byte[] p12 =
        authorized()
            .get(CS1 + "/" + certId)
            .then()
            .statusCode(200)
            .contentType("application/pkcs12")
            .extract()
            .asByteArray();
    Path file = Files.write(dir.resolve("CS1.p12"), p12);

    putBinding("authenticationMode", "CERTIFICATE");
    var result =
        TlsProbe.bc().clientCertificate(file, "pw-123456").get(tls.port(), "/connector.sds");
    assertEquals(200, result.status());
    X509Certificate client = (X509Certificate) result.session().getLocalCertificates()[0];
    assertEquals(algorithm, TlsKeys.describe(client.getPublicKey()));
    assertThrows(IOException.class, () -> TlsProbe.bc().get(tls.port(), "/connector.sds"));

    authorized().delete(CS1 + "/" + certId).then().statusCode(200);
    assertThrows(
        IOException.class,
        () -> TlsProbe.bc().clientCertificate(file, "pw-123456").get(tls.port(), "/connector.sds"));
  }

  @Test
  @DisplayName(
      "TIP1-A_4517-04: importiertes CS-Zertifikat (PEM mit „Bag Attributes“, ECC NIST) kommt in ANCL_CCERT_LIST")
  void importClientCertificate() throws Exception {
    KeyPair keys = keys("secp256r1");
    X509Certificate certificate =
        TlsKeys.selfSigned(keys, "import", List.of(), KeyPurposeId.id_kp_clientAuth);
    authorized()
        .body(
            Map.of(
                "generateNew",
                false,
                "filename",
                "cs.der",
                "certificate",
                Base64.getEncoder().encodeToString(pem(certificate).getBytes())))
        .post(CS1)
        .then()
        .statusCode(201)
        .body("data.filename", equalTo("cs.der"));
    Path file =
        Files.write(
            dir.resolve("import.p12"),
            TlsKeys.pkcs12(keys.getPrivate(), List.of(certificate), "import", "pw"));
    putBinding("authenticationMode", "CERTIFICATE");
    assertEquals(
        200,
        TlsProbe.bc().clientCertificate(file, "pw").get(tls.port(), "/connector.sds").status());
  }

  @ParameterizedTest(name = "{0}")
  @DisplayName(
      "A_21811-05 TAB_KON_866: Brainpool-CS-Zertifikat erzeugen → 400 (EE_KON_CS_ECC_001, EE_HSK_CS_ECC_001)")
  @CsvSource({"ECC, BRAINPOOL_P256", ", NIST_P256"})
  void generateClientCertificateRejected(String cryptType, String eccCurve) {
    authorized().body(generateBody(cryptType, eccCurve, "pw")).post(CS1).then().statusCode(400);
    authorized().get(EhexClientSystems.CLIENT_SYSTEMS).then().body("[0].certificates", hasSize(2));
  }

  @ParameterizedTest(name = "{0}")
  @DisplayName(
      "A_21811-05 TAB_KON_866: Import von RSA-2048 und Brainpool als CS-Zertifikat → 400 "
          + "(EE_KON_CS_RSA_004, EE_KON_CS_ECC_002, EE_HSK_CS_ECC_002)")
  @CsvSource({"RSA-2048", "brainpoolP256r1"})
  void importClientCertificateRejected(String algorithm) throws Exception {
    X509Certificate certificate =
        TlsKeys.selfSigned(keys(algorithm), "import", List.of(), KeyPurposeId.id_kp_clientAuth);
    authorized()
        .body(
            Map.of(
                "generateNew",
                false,
                "filename",
                "cs.pem",
                "certificate",
                Base64.getEncoder().encodeToString(pem(certificate).getBytes())))
        .post(CS1)
        .then()
        .statusCode(400)
        .body(containsString("A_21811-05"));
    authorized().get(EhexClientSystems.CLIENT_SYSTEMS).then().body("[0].certificates", hasSize(2));
  }

  // Settings

  @Test
  @DisplayName(
      "TIP1-A_4515, TIP1-A_4518-02: ANCL_TLS_MANDATORY sperrt den HTTP-Port, connector.sds nur bei "
          + "ANCL_DVD_OPEN; Abschalten braucht die Bestätigung (300 + confirmationToken); HTTPS bleibt offen")
  void tlsMandatory() throws Exception {
    given().get("/connector.sds").then().statusCode(200);
    putBinding("tlsMandatory", true);
    given().contentType("text/xml").body("<x/>").post("/ws/CardService").then().statusCode(403);
    given().get("/connector.sds").then().statusCode(200);
    putBinding("dvdTlsNotMandatory", "false"); // kms-client writes ANCL_DVD_OPEN as a string
    given().get("/connector.sds").then().statusCode(403);
    var https = TlsProbe.bc().get(tls.port(), "/connector.sds");
    assertEquals(200, https.status());
    assertTrue(https.body().contains("<CONN:TLSMandatory>true</CONN:TLSMandatory>"), https.body());

    var group = authorized().get(EhexClientSystems.BINDING).then().extract().jsonPath().getMap("");
    group.put("tlsMandatory", false);
    String token =
        authorized()
            .body(group)
            .put(EhexClientSystems.BINDING)
            .then()
            .statusCode(300)
            .extract()
            .jsonPath()
            .getString("confirmationToken");
    given().get("/connector.sds").then().statusCode(403); // unchanged without confirmation
    authorized()
        .body(group)
        .put(EhexClientSystems.BINDING + "?confirmation=falsch")
        .then()
        .statusCode(300);
    authorized()
        .body(group)
        .put(EhexClientSystems.BINDING + "?confirmation=" + token)
        .then()
        .statusCode(200)
        .body("tlsMandatory", equalTo(false));
    given().get("/connector.sds").then().statusCode(200);
  }

  @Test
  @DisplayName(
      "TLS_USE_ECC_FOR_CS (EHEX): aus → ID.AK.AUT RSA, an → ID.AK.AUT ECC, ab dem nächsten Handshake")
  void eccForClientSystems() throws Exception {
    assertTrue(
        TlsProbe.bc().get(tls.port(), "/connector.sds").serverCertificate().getPublicKey()
            instanceof ECPublicKey);
    var settings =
        authorized()
            .get(EhexClientSystems.TLS_SETTINGS)
            .then()
            .statusCode(200)
            .body("eccUseForClientSystemConnectionEnabled", equalTo(true))
            .extract()
            .jsonPath()
            .getMap("");
    settings.put("eccUseForClientSystemConnectionEnabled", "false");
    authorized().body(settings).put(EhexClientSystems.TLS_SETTINGS).then().statusCode(200);
    var rsa = TlsProbe.bc().get(tls.port(), "/connector.sds");
    assertTrue(rsa.serverCertificate().getPublicKey() instanceof RSAPublicKey);
    assertTrue(
        rsa.session().getCipherSuite().startsWith("TLS_ECDHE_RSA_"),
        rsa.session().getCipherSuite());
    settings.put("eccUseForClientSystemConnectionEnabled", true);
    authorized().body(settings).put(EhexClientSystems.TLS_SETTINGS).then().statusCode(200);
    assertTrue(
        TlsProbe.bc().get(tls.port(), "/connector.sds").serverCertificate().getPublicKey()
            instanceof ECPublicKey);
  }

  // Server certificate

  @ParameterizedTest(name = "{0} {1}")
  @DisplayName(
      "A_21811-05, A_21697-01: Serverzertifikat erzeugen (RSA-3072, ECC NIST), nach bestätigter Aktivierung "
          + "statt ID.AK.AUT; Löschen schaltet auf ID.AK.AUT zurück")
  @CsvSource({"RSA, , RSA-3072", "ECC, NIST_P256, ECC-256 NIST P-256"})
  void generateServerCertificate(String cryptType, String eccCurve, String algorithm)
      throws Exception {
    X509Certificate akAut = TlsProbe.bc().get(tls.port(), "/connector.sds").serverCertificate();
    var body = generateBody(cryptType, eccCurve, "pw");
    body.put("hostname", "example.org");
    body.put("alternativeHostnames", List.of("example.org"));
    authorized()
        .body(body)
        .post(EhexClientSystems.SERVER_CERTIFICATE)
        .then()
        .statusCode(200)
        .body("data.algorithm", equalTo(algorithm));
    assertEquals(
        akAut,
        TlsProbe.bc().get(tls.port(), "/connector.sds").serverCertificate(),
        "erst nach Aktivierung");

    putBinding("serverAuthenticationUseSoftwareKey", true);
    X509Certificate software = TlsProbe.bc().get(tls.port(), "/connector.sds").serverCertificate();
    assertEquals(algorithm, TlsKeys.describe(software.getPublicKey()));
    assertTrue(software.getSubjectX500Principal().getName().contains("CN=example.org"));

    authorized().delete(EhexClientSystems.SERVER_CERTIFICATE).then().statusCode(200);
    assertEquals(akAut, TlsProbe.bc().get(tls.port(), "/connector.sds").serverCertificate());
    authorized()
        .get(EhexClientSystems.BINDING)
        .then()
        .body("serverAuthenticationUseSoftwareKey", equalTo(false));
    authorized()
        .delete(EhexClientSystems.SERVER_CERTIFICATE)
        .then()
        .statusCode(200); // also without certificate
  }

  @Test
  @DisplayName(
      "A_21697-01: importiertes Serverzertifikat (PKCS#12 ECC NIST) wird nach Aktivierung genutzt")
  void importServerCertificate() throws Exception {
    KeyPair keys = keys("secp256r1");
    X509Certificate certificate =
        TlsKeys.selfSigned(keys, "server", List.of("server"), KeyPurposeId.id_kp_serverAuth);
    byte[] p12 = TlsKeys.pkcs12(keys.getPrivate(), List.of(certificate), "server", "123456");
    authorized()
        .body(
            Map.of(
                "generateNew",
                false,
                "keystore",
                Base64.getEncoder().encodeToString(p12),
                "password",
                "123456",
                "filename",
                "server.p12"))
        .post(EhexClientSystems.SERVER_CERTIFICATE)
        .then()
        .statusCode(200);
    putBinding("serverAuthenticationUseSoftwareKey", true);
    assertEquals(certificate, TlsProbe.bc().get(tls.port(), "/connector.sds").serverCertificate());
  }

  @ParameterizedTest(name = "{0}")
  @DisplayName(
      "A_21811-05 TAB_KON_866: Serverzertifikat RSA-2048 oder Brainpool importieren → 400 "
          + "(EE_KON_CS_RSA_006, EE_HSK_CS_ECC_006, EE_HSK_CS_RSA_006); falsches Passwort → 400")
  @CsvSource({
    "RSA-2048, 123456, 123456",
    "brainpoolP256r1, 123456, 123456",
    "secp256r1, 123456, falsch"
  })
  void importServerCertificateRejected(String algorithm, String password, String sent)
      throws Exception {
    KeyPair keys = keys(algorithm);
    X509Certificate certificate =
        TlsKeys.selfSigned(keys, "server", List.of(), KeyPurposeId.id_kp_serverAuth);
    byte[] p12 = TlsKeys.pkcs12(keys.getPrivate(), List.of(certificate), "server", password);
    authorized()
        .body(
            Map.of(
                "generateNew",
                false,
                "keystore",
                Base64.getEncoder().encodeToString(p12),
                "password",
                sent))
        .post(EhexClientSystems.SERVER_CERTIFICATE)
        .then()
        .statusCode(400);
    authorized()
        .body(
            Map.of(
                "tlsMandatory",
                false,
                "authenticationMode",
                "NONE",
                "dvdTlsNotMandatory",
                true,
                "serverAuthenticationUseSoftwareKey",
                true))
        .put(EhexClientSystems.BINDING)
        .then()
        .statusCode(400);
  }

  @Test
  @DisplayName(
      "A_21811-05: Brainpool-Serverzertifikat erzeugen → 400 (EE_KON_CS_ECC_005 lehnt schon kms-client ab)")
  void generateServerCertificateRejected() {
    var body = generateBody("ECC", "BRAINPOOL_P256", "pw");
    body.put("hostname", "example.org");
    authorized().body(body).post(EhexClientSystems.SERVER_CERTIFICATE).then().statusCode(400);
  }

  // Restart

  @Test
  @DisplayName(
      "NK: System - Neustart: 200, Anmeldungen verfallen, TLS-Kontext neu, Verbindungen getrennt, Prozess läuft "
          + "weiter; danach wieder Login 204 (kms-client wartet 5 s)")
  void reboot() throws Exception {
    String token = login();
    kms().header("Authorization", token).post(EhexKms.REBOOT).then().statusCode(200);
    kms().header("Authorization", token).get(EhexClientSystems.BINDING).then().statusCode(401);
    Instant until = Instant.now().plus(Duration.ofSeconds(5));
    int status = 0;
    while (Instant.now().isBefore(until)) {
      try {
        status = TlsProbe.bc().get(tls.port(), "/connector.sds").status();
        break;
      } catch (IOException e) {
        Thread.sleep(100);
      }
    }
    assertEquals(200, status);
    assertNotEquals(null, login());
  }

  // decision-12

  @ParameterizedTest(name = "{0}")
  @DisplayName(
      "decision-12: PASSWORD (Basic-Auth), TLS_USE_ECC_CIPHER aus und Export importierter Zertifikate → 501")
  @CsvSource(
      delimiter = '|',
      value = {
        "PUT | /rest/mgmt/ak/dienste/clientsystem-anbindung/einstellungen | {\"authenticationMode\":\"PASSWORD\"}",
        "PUT | /rest/mgmt/ak/dienste/tls/einstellungen | {\"eccCipherEnabled\":false}",
        "GET | /rest/mgmt/ak/info/clientsysteme/cs-1/zertifikat/cert-1 | "
      })
  void notImplemented(String method, String path, String body) {
    authorized()
        .body(body == null ? "{}" : body)
        .request(method, path)
        .then()
        .statusCode(501)
        .body("vendor", equalTo("EHEX"))
        .body("path", equalTo(path));
  }

  @Test
  @DisplayName(
      "decision-4: POST /admin/reset stellt Einstellungen, ANCL_CCERT_LIST und Serveridentität der YAML her")
  void adminReset() {
    putBinding("tlsMandatory", true);
    authorized().body(generateBody("ECC", "NIST_P256", "pw")).post(CS1).then().statusCode(201);
    given().port(admin.port()).post("/admin/reset").then().statusCode(200);
    ehex(); // the reset also restores the vendor profile from the YAML
    given().get("/connector.sds").then().statusCode(200);
    authorized().get(EhexClientSystems.CLIENT_SYSTEMS).then().body("[0].certificates", hasSize(2));
    given()
        .port(admin.port())
        .get("/admin/tls")
        .then()
        .statusCode(200)
        .body("tlsMandatory", equalTo(false));
  }
}

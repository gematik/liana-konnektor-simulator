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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import de.gematik.liana.TestPorts;
import de.gematik.liana.sds.XsdValidator;
import de.gematik.liana.tls.KonnektorTlsServerTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.restassured.path.xml.XmlPath;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * LIANA-58 AC3: a Java Clientsystem (SunJSSE, without BouncyCastle) builds its TLS connection
 * solely from the exported {@code .kon}: client certificate from {@code credentials} ({@code
 * pkcs12}), trust from {@code trustStore}, hostname verification against {@code url}. LIANA
 * requires client auth (ANCL_CAUT_MANDATORY). Runs as {@link KonTlsRoundTripTest} (JVM) and {@link
 * KonTlsRoundTripIT} (native image).
 */
abstract class KonTlsRoundTrip {

  public static class MutualTls implements QuarkusTestProfile {
    @Override
    public Map<String, String> getConfigOverrides() {
      return TestPorts.config(
          "liana.tls.url", "https://localhost:" + TestPorts.TLS,
          "liana.tls.client-auth", "true",
          "liana.kon-export.url", "https://localhost:" + TestPorts.TLS + "/",
          "liana.kon-export.credentials.type", "pkcs12",
          "liana.kon-export.credentials.username", "",
          "liana.kon-export.credentials.keystore", "./support/pki/clients/cs1-p256.p12",
          "liana.kon-export.credentials.password", "liana");
    }
  }

  abstract int adminPort();

  private JsonNode kon() throws Exception {
    String raw =
        given()
            .port(adminPort())
            .get("/admin/clients/CS1/config.kon")
            .then()
            .statusCode(200)
            .extract()
            .asString();
    JsonNode kon = KonFile.load(raw, Map.of());
    assertEquals(List.of(), KonValidator.errors(kon));
    return kon;
  }

  /**
   * SSLContext of a client that only knows the {@code .kon}; without client certificate if {@code
   * withCredentials} is false.
   */
  private static SSLContext context(JsonNode kon, boolean withCredentials) throws Exception {
    KeyManagerFactory keyManagers = null;
    if (withCredentials) {
      JsonNode credentials = kon.get("credentials");
      assertEquals("pkcs12", credentials.get("type").asText());
      char[] password = credentials.get("password").asText().toCharArray();
      // In the Quarkus test JVM, BC is registered and takes over PBES2, which the JDK PKCS12
      // KeyStore
      // then cannot decrypt; there via BC. Against the native image (IT), the client runs as plain
      // JDK.
      KeyStore p12 =
          Security.getProvider("BC") != null
              ? KeyStore.getInstance("PKCS12", "BC")
              : KeyStore.getInstance("PKCS12");
      p12.load(
          new ByteArrayInputStream(
              Base64.getMimeDecoder().decode(credentials.get("data").asText())),
          password);
      keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
      keyManagers.init(p12, password);
    }
    KeyStore trust = KeyStore.getInstance("PKCS12");
    trust.load(null, null);
    CertificateFactory certificates = CertificateFactory.getInstance("X.509");
    for (int i = 0; i < kon.get("trustStore").size(); i++) {
      trust.setCertificateEntry(
          "liana-" + i,
          certificates.generateCertificate(
              new ByteArrayInputStream(
                  Base64.getMimeDecoder().decode(kon.get("trustStore").get(i).asText()))));
    }
    TrustManagerFactory trustManagers =
        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    trustManagers.init(trust);
    SSLContext context = SSLContext.getInstance("TLS", "SunJSSE");
    context.init(
        keyManagers == null ? null : keyManagers.getKeyManagers(),
        trustManagers.getTrustManagers(),
        new SecureRandom());
    return context;
  }

  @Test
  @DisplayName(
      "config.kon mit pkcs12 und trustStore: connector.sds und GetCards über mTLS, Endpunkt aus EndpointTLS")
  void roundTrip() throws Exception {
    JsonNode kon = kon();
    String url = kon.get("url").asText().replaceFirst("/$", "");
    try (HttpClient client = HttpClient.newBuilder().sslContext(context(kon, true)).build()) {
      HttpResponse<String> sds =
          client.send(
              HttpRequest.newBuilder(URI.create(url + "/connector.sds")).build(),
              HttpResponse.BodyHandlers.ofString());
      assertEquals(200, sds.statusCode());
      XsdValidator.validate("conn/ServiceDirectory.xsd", sds.body());
      XmlPath directory = new XmlPath(sds.body());
      assertEquals("true", directory.getString("ConnectorServices.ClientAutMandatory"));

      String eventService =
          directory.getString(
              "ConnectorServices.ServiceInformation.Service.find { it.@Name == 'EventService' }"
                  + ".Versions.Version.EndpointTLS.@Location");
      assertTrue(eventService.startsWith("https://localhost:" + TestPorts.TLS + "/"), eventService);
      HttpResponse<String> cards =
          client.send(
              HttpRequest.newBuilder(URI.create(eventService))
                  .header("Content-Type", "text/xml; charset=UTF-8")
                  .header("SOAPAction", "\"" + KonnektorTlsServerTest.GET_CARDS_ACTION + "\"")
                  .POST(HttpRequest.BodyPublishers.ofString(KonnektorTlsServerTest.GET_CARDS))
                  .build(),
              HttpResponse.BodyHandlers.ofString());
      assertEquals(200, cards.statusCode(), cards.body());
      assertEquals(
          "OK",
          new XmlPath(cards.body()).getString("Envelope.Body.GetCardsResponse.Status.Result"));
    }
  }

  @Test
  @DisplayName("Ohne die Credentials aus config.kon lehnt LIANA die Verbindung ab")
  void withoutCredentials() throws Exception {
    JsonNode kon = kon();
    String url = kon.get("url").asText().replaceFirst("/$", "");
    try (HttpClient client = HttpClient.newBuilder().sslContext(context(kon, false)).build()) {
      assertThrows(
          IOException.class,
          () ->
              client.send(
                  HttpRequest.newBuilder(URI.create(url + "/connector.sds")).build(),
                  HttpResponse.BodyHandlers.ofString()));
    }
  }
}

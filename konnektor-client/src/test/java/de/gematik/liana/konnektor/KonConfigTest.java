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
package de.gematik.liana.konnektor;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * {@code .kon} v1.0.0 per {@code support/kon/kon-format.md} (decision-5), LIANA-133 AC 1 and AC 3.
 */
class KonConfigTest {

  private static KonConfig parse(String json) {
    return KonConfig.parse(json, name -> null);
  }

  @Test
  @DisplayName(
      "support/kon/examples/liana-phase0.kon: url, rewriteServiceEndpoints, Kontext, basic aus "
          + "${LIANA_BASIC_PASSWORD}, env")
  void lianaBeispiel() throws Exception {
    KonConfig kon =
        KonConfig.read(
            Path.of("support/kon/examples/liana-phase0.kon"),
            name -> name.equals("LIANA_BASIC_PASSWORD") ? "aus-der-umgebung" : null);
    assertEquals("aus-der-umgebung", ((Credentials.Basic) kon.credentials()).password());
    assertEquals(URI.create("http://localhost:8080"), kon.url());
    assertTrue(kon.rewriteServiceEndpoints());
    assertEquals(new Context("M1", "CS1", "WP1", null), kon.context());
    assertInstanceOf(Credentials.Basic.class, kon.credentials());
    assertEquals("liana", ((Credentials.Basic) kon.credentials()).username());
    assertEquals("ru", kon.env());
  }

  @Test
  @DisplayName(
      "§8 Beispiel mit pkcs12, trustStore (auch MIME-umbrochen) und expectedHost; abschließender / der url")
  void vollstaendig() throws Exception {
    // MIME-wrapped, as \n in the JSON
    String cert =
        Base64.getMimeEncoder()
            .encodeToString(
                HttpTransportTest.certificate(TlsServer.SERVER.resolve("komp-ca.pem")).getEncoded())
            .replace("\r\n", "\\n");
    KonConfig kon =
        parse(
            """
                {"version": "1.0.0", "url": "https://konnektor.example.com:8443/", "mandantId": "M1",
                 "workplaceId": "W1", "clientSystemId": "C1", "userId": "U1", "telematikId": "2-2134567890",
                 "credentials": {"type": "pkcs12", "data": "AQID", "password": "00"},
                 "env": "tu", "insecureSkipVerify": false, "expectedHost": "konnektor.example.com",
                 "trustStore": ["%s"]}"""
                .formatted(cert));
    assertEquals(URI.create("https://konnektor.example.com:8443"), kon.url());
    assertEquals(new Context("M1", "C1", "W1", "U1"), kon.context());
    assertEquals("2-2134567890", kon.telematikId());
    assertArrayEquals(new byte[] {1, 2, 3}, ((Credentials.Pkcs12) kon.credentials()).data());
    assertArrayEquals("00".toCharArray(), ((Credentials.Pkcs12) kon.credentials()).password());
    assertEquals("konnektor.example.com", kon.trust().expectedHost());
    assertEquals(
        HttpTransportTest.certificate(TlsServer.SERVER.resolve("komp-ca.pem")),
        kon.trust().certificates().get(0));
  }

  @Test
  @DisplayName(
      "§4: ${NAME} im Rohtext an jeder Stelle, unbekannt wird leer, $NAME und ${} bleiben stehen")
  void ersetzung() {
    Map<String, String> env = Map.of("HOST", "kon", "PORT", "443", "PW", "s3cret");
    assertEquals(
        "https://kon:443 $HOST ${} x",
        KonConfig.substitute("https://${HOST}:${PORT} $HOST ${} x${NIX}", env::get));
    KonConfig kon =
        KonConfig.parse(
            """
                {"url": "https://${HOST}:${PORT}", "mandantId": "M", "workplaceId": "W", "clientSystemId": "C",
                 "credentials": {"type": "basic", "username": "u", "password": "${PW}"}}""",
            env::get);
    assertEquals("s3cret", ((Credentials.Basic) kon.credentials()).password());
    IllegalArgumentException e =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                KonConfig.parse(
                    """
                {"url": "https://kon", "mandantId": "M", "workplaceId": "W", "clientSystemId": "C",
                 "credentials": {"type": "basic", "username": "u", "password": "${UNSET}"}}""",
                    env::get));
    assertEquals(".kon ungültig: credentials.password: leer", e.getMessage());
  }

  @Test
  @DisplayName("§7: alle Feldfehler auf einmal, Meldungen ohne Werte")
  void validierung() {
    IllegalArgumentException e =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                parse(
                    """
                {"url": "konnektor:8443", "mandantId": "", "clientSystemId": 7, "env": "prod",
                 "credentials": {"type": "pkcs12", "data": "kein base64!", "password": "geheim-1"},
                 "trustStore": ["%%%"], "insecureSkipVerify": "ja"}"""));
    assertEquals(
        ".kon ungültig: url: Schema (https:// oder http://) und Host erforderlich; mandantId: leer; "
            + "workplaceId: fehlt; clientSystemId: keine Zeichenkette; credentials.data: kein gültiges Base64; "
            + "env: nur ru, tu oder pu; insecureSkipVerify: kein Wahrheitswert; trustStore[0]: kein gültiges Base64",
        e.getMessage());
    assertFalse(e.getMessage().contains("geheim-1"));
    assertEquals(
        ".kon ungültig: credentials: fehlt",
        assertThrows(
                IllegalArgumentException.class,
                () ->
                    parse(
                        "{\"url\":\"https://k\",\"mandantId\":\"M\",\"workplaceId\":\"W\",\"clientSystemId\":"
                            + "\"C\"}"))
            .getMessage());
    assertEquals(
        ".kon ungültig: credentials.type: unbekannt, erlaubt sind basic, pkcs12, system",
        assertThrows(IllegalArgumentException.class, () -> parse(minimal("{\"type\":\"oauth\"}")))
            .getMessage());
    assertEquals(
        ".kon ungültig: credentials.name: fehlt",
        assertThrows(IllegalArgumentException.class, () -> parse(minimal("{\"type\":\"system\"}")))
            .getMessage());
    assertEquals(
        ".kon ungültig: credentials.username: fehlt; credentials.password: fehlt",
        assertThrows(IllegalArgumentException.class, () -> parse(minimal("{\"type\":\"basic\"}")))
            .getMessage());
    assertEquals(
        ".kon ungültig: trustStore[0]: kein X.509-Zertifikat",
        assertThrows(
                IllegalArgumentException.class,
                () ->
                    parse(
                        minimal("{\"type\":\"system\",\"name\":\"n\"}")
                            .replace("}}", "}, \"trustStore\": [\"AQID\"]}")))
            .getMessage());
  }

  @Test
  @DisplayName("system-Credentials werden gelesen; pkcs12 ohne Passwort; .kony wird abgelehnt")
  void weitere(@TempDir Path dir) throws Exception {
    assertEquals(
        new Credentials.SystemStore("kon1"),
        parse(minimal("{\"type\":\"system\",\"name\":\"kon1\"}")).credentials());
    assertArrayEquals(
        new char[0],
        ((Credentials.Pkcs12)
                parse(minimal("{\"type\":\"pkcs12\",\"data\":\"AQID\"}")).credentials())
            .password());
    Path kony = Files.writeString(dir.resolve("a.kony"), "url: https://k");
    assertThrows(IllegalArgumentException.class, () -> KonConfig.read(kony));
    assertNull(parse(minimal("{\"type\":\"system\",\"name\":\"n\"}")).env());
  }

  @Test
  @DisplayName("LIANA-133 AC 3: toString zeigt weder Passwort noch PKCS#12")
  void toStringOhneGeheimnisse() {
    KonConfig kon =
        parse(minimal("{\"type\":\"basic\",\"username\":\"u\",\"password\":\"geheim-2\"}"));
    assertFalse(kon.toString().contains("geheim-2"), kon.toString());
    assertTrue(kon.toString().contains("password=***"));
  }

  private static String minimal(String credentials) {
    return "{\"url\":\"https://k\",\"mandantId\":\"M\",\"workplaceId\":\"W\",\"clientSystemId\":\"C\","
        + "\"credentials\":"
        + credentials
        + "}";
  }
}

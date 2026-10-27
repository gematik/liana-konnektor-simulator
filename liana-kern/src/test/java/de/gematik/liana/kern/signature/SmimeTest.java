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
package de.gematik.liana.kern.signature;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.kern.error.ConnectorError;
import de.gematik.liana.kern.error.ConnectorException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class SmimeTest {

  private static final Path SMIME = Path.of("support/signatures/smime");

  private static byte[] ascii(String text) {
    return text.getBytes(StandardCharsets.ISO_8859_1);
  }

  @Test
  @DisplayName(
      "TUC_KON_080 (D) eMail10k.txt der Konnektor-QES (KUC_1601_001): Header mit Folgezeilen, Body unverändert")
  void parse() throws Exception {
    byte[] mail = Files.readAllBytes(SMIME.resolve("eMail10k.txt"));
    Smime.Message message = Smime.parse(mail);
    assertEquals("Example plain message", message.header("subject").orElseThrow());
    assertEquals("text/plain; charset=us-ascii;", message.header("Content-Type").orElseThrow());
    assertTrue(new String(message.body(), StandardCharsets.UTF_8).startsWith("Text mit 10 KB"));
    Smime.Message folded = Smime.parse(ascii("MIME-Version: 1.0\nSubject: a\n b\n\nx"));
    assertEquals("a b", folded.header("Subject").orElseThrow());
    assertArrayEquals(ascii("x"), folded.body());
  }

  @ParameterizedTest(name = "{0}")
  @ValueSource(
      strings = {
        "%PDF-1.4\n%âãÏÓ\n",
        "Subject: ohne MIME-Version\n\nText",
        " Folgezeile: zuerst\n",
        "MIME-Version: 1.0\nkein Feld\n\nText"
      })
  @DisplayName(
      "TUC_KON_080 (D): keine MIME-Nachricht → 4024 „Formatvalidierung fehlgeschlagen (MIME)“ (KUC_1601_009)")
  void keineMimeNachricht(String document) {
    ConnectorException e =
        assertThrows(ConnectorException.class, () -> Smime.parse(ascii(document)));
    assertEquals(ConnectorError.FORMAT_VALIDATION_FAILED, e.error());
    assertEquals("Formatvalidierung fehlgeschlagen (MIME)", e.text());
  }

  @Test
  @DisplayName(
      "RFC 5751 3.1/3.1.1: die MIME-Entität sind die Content-*-Felder und der Body, Zeilenenden CRLF")
  void entity() {
    Smime.Message message =
        Smime.parse(
            ascii(
                "From: a@b\nMIME-Version: 1.0\nContent-Type: text/plain\n"
                    + "Content-Transfer-Encoding: 8bit\n\nZeile 1\nZeile 2\r\nZeile 3\r"));
    assertEquals(
        "Content-Type: text/plain\r\nContent-Transfer-Encoding: 8bit\r\n\r\nZeile 1\r\nZeile 2\r\n"
            + "Zeile 3\r\n",
        new String(Smime.entity(message), StandardCharsets.ISO_8859_1));
    assertEquals(
        "\r\nText",
        new String(
            Smime.entity(Smime.parse(ascii("MIME-Version: 1.0\n\nText"))),
            StandardCharsets.ISO_8859_1),
        "ohne Content-Type: Default text/plain (RFC 2045 5.2)");
  }

  @Test
  @DisplayName(
      "TUC_KON_160 S/MIME-Nachbereitung: übrige Header übernommen, MIME-Version 1.0, application/pkcs7-mime; "
          + "smime-type=signed-data, base64, Content-Disposition attachment *.p7m; signedData liest es zurück")
  void message() {
    Smime.Message original =
        Smime.parse(
            ascii(
                "From: Tim <t@g.de>\r\nMIME-Version: 1.0\r\nSubject: S\r\n"
                    + "Content-Type: text/plain\r\n\r\nText"));
    byte[] signedData = new byte[200];
    for (int i = 0; i < signedData.length; i++) {
      signedData[i] = (byte) i;
    }
    byte[] smime = Smime.message(original, signedData);
    Smime.Message message = Smime.parse(smime);
    assertEquals(
        List.of(
            "From: Tim <t@g.de>",
            "Subject: S",
            "MIME-Version: 1.0",
            "Content-Type: application/pkcs7-mime; smime-type=signed-data; name=\"smime.p7m\"",
            "Content-Transfer-Encoding: base64",
            "Content-Disposition: attachment; filename=\"smime.p7m\""),
        message.headers());
    String body = new String(message.body(), StandardCharsets.US_ASCII);
    assertTrue(
        body.lines().allMatch(l -> l.length() <= 76), "Zeilen höchstens 76 Zeichen (RFC 2045 6.8)");
    assertArrayEquals(signedData, Smime.signedData(smime));
  }

  @Test
  @Tag("vendor-data")
  @DisplayName(
      "KUC_1603_010: S/MIME-Nachricht der Konnektor-QES ohne Content-Type → 4024 (MIME); mit Content-Type "
          + "die SignedData (ContentInfo, SEQUENCE)")
  void signedData() throws Exception {
    byte[] withoutType =
        Files.readAllBytes(
            Path.of("support/vendor/signatures/smime/SMimeMessage_without_ContentType.txt"));
    ConnectorException e =
        assertThrows(ConnectorException.class, () -> Smime.signedData(withoutType));
    assertEquals("Formatvalidierung fehlgeschlagen (MIME)", e.text());
    byte[] withType =
        new String(withoutType, StandardCharsets.ISO_8859_1)
            .replace(
                "MIME-Version: 1.0",
                "MIME-Version: 1.0\nContent-Type: application/pkcs7-mime; smime-type=signed-data")
            .getBytes(StandardCharsets.ISO_8859_1);
    byte[] cms = Smime.signedData(withType);
    assertEquals(0x30, cms[0]);
    ConnectorException text =
        assertThrows(
            ConnectorException.class,
            () ->
                Smime.signedData(
                    ascii(
                        "MIME-Version: 1.0\nContent-Type: text/plain\n\n"
                            + Base64.getEncoder().encodeToString(cms))));
    assertEquals(ConnectorError.FORMAT_VALIDATION_FAILED, text.error());
  }
}

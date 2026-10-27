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
package de.gematik.liana.kern.vsdm;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.liana.kern.vsdm.Pruefungsnachweis.Ergebnis;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Instant;
import java.util.zip.GZIPInputStream;
import javax.xml.XMLConstants;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.SchemaFactory;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class PruefungsnachweisTest {

  private static final Path XSD = Path.of("support/schemas/fa/vsds/Pruefungsnachweis.xsd");
  private static final Instant TS = Instant.parse("2026-10-17T08:09:10Z");

  private static void validate(byte[] xml) throws Exception {
    SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
    factory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
    factory.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "file");
    factory
        .newSchema(XSD.toFile())
        .newValidator()
        .validate(new StreamSource(new ByteArrayInputStream(xml)));
  }

  @Test
  @DisplayName(
      "Tab_FM_VSDM_04 / VSDM-A_2770: Ergebnis 2 mit Prüfziffer gegen Pruefungsnachweis.xsd, "
          + "Default-Namespace einmal, ohne Whitespace und schemaLocation, TS in UTC")
  void mitPruefziffer() throws Exception {
    byte[] pz = FixedSource.pruefziffer("X110630769");
    var pn = new Pruefungsnachweis(TS, Ergebnis.KEINE_AKTUALISIERUNG_ERFORDERLICH, null, pz);

    validate(pn.xml());
    assertEquals(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><PN xmlns=\"http://ws.gematik.de/fa/vsdm/pnw/v1.0\" "
            + "CDM_VERSION=\"1.0.0\"><TS>20261017080910</TS><E>2</E><PZ>"
            + "LxZ54CsBMSQaFMP04r/v/SGEItJtsElbiHZ9ES4eCMlCR+CfHOCgJJbjXcQV84tY</PZ></PN>",
        new String(pn.xml(), StandardCharsets.UTF_8));
  }

  @Test
  @DisplayName(
      "Tab_FM_VSDM_04: Ergebnis 3 mit ErrorCode, ohne Prüfziffer, gegen Pruefungsnachweis.xsd")
  void mitErrorCode() throws Exception {
    var pn =
        new Pruefungsnachweis(TS, Ergebnis.AKTUALISIERUNG_TECHNISCH_NICHT_MOEGLICH, 12105, null);

    validate(pn.xml());
    String xml = new String(pn.xml(), StandardCharsets.UTF_8);
    assertTrue(xml.endsWith("<E>3</E><EC>12105</EC></PN>"), xml);
  }

  @Test
  @DisplayName("VSDM-A_2652 / VSDM-A_2770: gzip des XML, höchstens 270 Byte")
  void gzip() throws Exception {
    var pn =
        new Pruefungsnachweis(
            TS,
            Ergebnis.KEINE_AKTUALISIERUNG_ERFORDERLICH,
            null,
            FixedSource.pruefziffer("X110630769"));

    byte[] gzip = pn.gzip();
    assertArrayEquals(pn.xml(), new GZIPInputStream(new ByteArrayInputStream(gzip)).readAllBytes());
    assertTrue(gzip.length <= 270, gzip.length + " Byte");
  }
}

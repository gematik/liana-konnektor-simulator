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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.zip.GZIPOutputStream;

/**
 * Prüfungsnachweis per Tab_FM_VSDM_04 (VSDM-A_2588, VSDM-A_2653) in the schema {@code
 * fa/vsds/Pruefungsnachweis.xsd}: CDM_VERSION 1.0.0, timestamp in UTC, result per
 * Tab_FM_VSDM_05-01, ErrorCode from a gematik fault of the Fachdienst, Prüfziffer of the UFS.
 * {@link #xml()} with the default namespace exactly once, without schemaLocation and whitespace
 * between the elements (VSDM-A_2770), {@link #gzip()} for the ReadVSD response (VSDM-A_2652).
 *
 * @param errorCode {@code null} if no Fachdienst answered with a gematik error code
 * @param pruefziffer {@code null} without Prüfziffer
 */
public record Pruefungsnachweis(
    Instant timestamp, Ergebnis ergebnis, Integer errorCode, byte[] pruefziffer) {

  static final String NAMESPACE = "http://ws.gematik.de/fa/vsdm/pnw/v1.0";

  /** Logical version of the business data structures (Tab_FM_VSDM_04). */
  static final String CDM_VERSION = "1.0.0";

  private static final DateTimeFormatter TS =
      DateTimeFormatter.ofPattern("yyyyMMddHHmmss").withZone(ZoneOffset.UTC);

  /**
   * The results from Tab_FM_VSDM_05-01 that LIANA produces; 1 and 4–6 only come with update and
   * OCSP.
   */
  public enum Ergebnis {
    /** There were no Aktualisierungsaufträge. */
    KEINE_AKTUALISIERUNG_ERFORDERLICH(2),
    /**
     * No online connection, Aktualisierungsaufträge not determinable (Fachdienst unreachable or
     * fault) or update not executable; also after abort by MAXTIME_VSDM (VSDM-A_2998).
     */
    AKTUALISIERUNG_TECHNISCH_NICHT_MOEGLICH(3);

    private final int code;

    Ergebnis(int code) {
      this.code = code;
    }

    public int code() {
      return code;
    }
  }

  /** The XML document, UTF-8. */
  public byte[] xml() {
    StringBuilder xml =
        new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\"?><PN xmlns=\"")
            .append(NAMESPACE)
            .append("\" CDM_VERSION=\"")
            .append(CDM_VERSION)
            .append("\"><TS>")
            .append(TS.format(timestamp))
            .append("</TS><E>")
            .append(ergebnis.code)
            .append("</E>");
    if (errorCode != null) {
      xml.append("<EC>").append(errorCode).append("</EC>");
    }
    if (pruefziffer != null) {
      xml.append("<PZ>").append(Base64.getEncoder().encodeToString(pruefziffer)).append("</PZ>");
    }
    return xml.append("</PN>").toString().getBytes(StandardCharsets.UTF_8);
  }

  /** {@link #xml()} gzip-compressed, as it appears Base64-encoded in ReadVSDResponse. */
  public byte[] gzip() {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    try (GZIPOutputStream gzip = new GZIPOutputStream(out)) {
      gzip.write(xml());
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
    return out.toByteArray();
  }
}

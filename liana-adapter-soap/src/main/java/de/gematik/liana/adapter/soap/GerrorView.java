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
package de.gematik.liana.adapter.soap;

import de.gematik.liana.kern.error.ConnectorError;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

/**
 * Content of {@code GERROR:Error} (TelematikError v2.0), in the SOAP fault and as a warning in
 * {@code CONN:Status}. For the Konnektor, {@code Instance} is always „Konnektor-Lokal“
 * (GS-A_3856-02, in the template).
 */
public record GerrorView(
    String messageId,
    String timestamp,
    String eventId,
    int code,
    String severity,
    String errorType,
    String text,
    String detail) {

  static GerrorView of(ConnectorError error, String text) {
    return of(error, text, null);
  }

  /** {@code detail} for {@code GERROR:Trace/Detail}, {@code null} if none. */
  static GerrorView of(ConnectorError error, String text, String detail) {
    return new GerrorView(
        UUID.randomUUID().toString(),
        DateTimeFormatter.ISO_INSTANT.format(Instant.now().truncatedTo(ChronoUnit.MILLIS)),
        UUID.randomUUID().toString(),
        error.code(),
        error.severity(),
        error.errorType(),
        text,
        detail);
  }
}

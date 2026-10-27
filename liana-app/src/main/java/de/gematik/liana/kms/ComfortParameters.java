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

import de.gematik.liana.kern.management.ComfortSettings;
import io.vertx.core.json.JsonObject;
import java.time.Duration;
import org.jboss.logging.Logger;

/**
 * SAK_COMFORT_SIGNATURE, _MAX and _TIMER (TAB_KON_596) via the KMS of the vendor profile
 * (LIANA-112.06), shared by KOCO, RISE and EHEX. The KMS accepts values outside 1–250 or 1–24 h and
 * keeps the old value: Konnektor-QES {@code KUC_1608_005} sets 0 and 251 or 0 and 25 hours, expects
 * no error (kms-client aborts on any status other than 200) and then reads the previous value.
 */
final class ComfortParameters {

  private static final Logger LOG = Logger.getLogger(ComfortParameters.class);

  private ComfortParameters() {}

  /**
   * Takes over the values that are set, {@code null} keeps a value.
   *
   * @return whether anything has changed
   * @throws IllegalStateException Enabled without TLS with client authentication and {@code
   *     liana.strict}
   */
  static boolean store(ComfortSettings settings, Boolean enabled, Integer max, Integer hours) {
    boolean changed = false;
    if (max != null && max != settings.max()) {
      try {
        settings.max(max);
        changed = true;
      } catch (IllegalArgumentException e) {
        LOG.warnf("KMS: %s, Wert bleibt %d", e.getMessage(), settings.max());
      }
    }
    if (hours != null && Duration.ofHours(hours).compareTo(settings.timer()) != 0) {
      try {
        settings.timer(Duration.ofHours(hours));
        changed = true;
      } catch (IllegalArgumentException e) {
        LOG.warnf("KMS: %s, Wert bleibt %s", e.getMessage(), settings.timer());
      }
    }
    if (enabled != null && enabled != settings.enabled()) {
      settings.enabled(enabled);
      changed = true;
    }
    return changed;
  }

  /**
   * SAK_COMFORT_SIGNATURE_TIMER in whole hours (kms-client: KOCO, RISE and EHEX count in hours).
   */
  static long hours(ComfortSettings settings) {
    return settings.timer().toHours();
  }

  /**
   * An integer field, as number or string (kms-client sends both); {@code null} if it is missing.
   */
  static Integer integer(JsonObject body, String field) {
    Object value = body.getValue(field);
    if (value == null) {
      return null;
    }
    try {
      return value instanceof Number n ? n.intValue() : Integer.parseInt(value.toString().strip());
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException(field + " '" + value + "' ist keine ganze Zahl");
    }
  }
}

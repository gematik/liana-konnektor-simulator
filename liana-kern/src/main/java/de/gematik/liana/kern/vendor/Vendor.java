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
package de.gematik.liana.kern.vendor;

import java.util.Arrays;
import java.util.Locale;
import java.util.stream.Collectors;

/**
 * Connector vendor whose behavior LIANA emulates (decision-10). {@link #NEUTRAL} is LIANA's reading
 * of the spec without vendor deviation. Branching happens only in {@link VendorProfile}.
 */
public enum Vendor {
  NEUTRAL,
  KOCO,
  RISE,
  SECUNET,
  EHEX,
  CGM;

  /** Spelling in YAML and Admin API: {@code neutral}, otherwise the vendor name in upper case. */
  public String value() {
    return this == NEUTRAL ? "neutral" : name();
  }

  /**
   * Vendor for {@code value}, case-insensitive.
   *
   * @throws IllegalArgumentException with the allowed values if {@code value} names no vendor
   */
  public static Vendor of(String value) {
    String name = value == null ? "" : value.strip().toUpperCase(Locale.ROOT);
    return Arrays.stream(values())
        .filter(vendor -> vendor.name().equals(name))
        .findFirst()
        .orElseThrow(
            () ->
                new IllegalArgumentException(
                    "unbekannter Hersteller '"
                        + value
                        + "', erlaubt: "
                        + Arrays.stream(values())
                            .map(Vendor::value)
                            .collect(Collectors.joining(", "))));
  }
}

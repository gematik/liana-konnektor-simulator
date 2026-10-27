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

/**
 * Product information from the Dienstverzeichnis ({@code PI:ProductInformation},
 * ProductInformation.xsd v1.1).
 *
 * @param vendorId {@code ProductVendorID}, such as {@code LIANA}, {@code KOCOC}
 * @param code {@code ProductCode}
 * @param typeVersion {@code ProductTypeVersion}, e.g. PTV {@code 6.0.4}
 * @param hwVersion {@code HWVersion}
 * @param fwVersion {@code FWVersion}
 * @param vendorName {@code ProductVendorName}, if given
 * @param name {@code ProductName}, if given
 */
public record Product(
    String vendorId,
    String code,
    String typeVersion,
    String hwVersion,
    String fwVersion,
    String vendorName,
    String name) {

  /**
   * For {@link Konnektor.Builder#product(String)}: determine the product from {@code connector.sds}
   * and the quirks table.
   */
  public static final String AUTO = "AUTO";
}

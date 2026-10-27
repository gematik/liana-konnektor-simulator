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
package de.gematik.liana.adapter.sds;

import java.util.List;

/**
 * Content of the Dienstverzeichnis {@code connector.sds} (TIP1-A_4529-02, TAB_KON_516–518),
 * rendered via the template {@code templates/connector.sds.xml}.
 *
 * @param informationDate time of the information as xsd:dateTime in UTC, always with seconds
 * @param productTypeVersion product type version of the Konnektor model (PTV6, gemProdT_Kon)
 * @param productVendorId vendor ID from the vendor profile ({@code
 *     VendorProfile.productVendorId()})
 * @param firmwareVersion LIANA version
 * @param tlsMandatory ANCL_TLS_MANDATORY
 * @param clientAuthMandatory ANCL_CAUT_MANDATORY
 */
public record ServiceDirectory(
    String informationDate,
    String productTypeVersion,
    String productVendorId,
    String firmwareVersion,
    boolean tlsMandatory,
    boolean clientAuthMandatory,
    List<Service> services) {

  /**
   * A service with all versions LIANA serves under the same endpoint (TAB_KON_518 {@code
   * Service/Versions}); LIANA builds the URLs itself (TIP1-A_4530): {@code location} over HTTP,
   * {@code tlsLocation} over the HTTPS port.
   */
  public record Service(
      String name,
      String description,
      List<Version> versions,
      String location,
      String tlsLocation) {}

  /**
   * A Konnektor service version (KDV, gemSpec_OM 7.2.1) in the target namespace {@code
   * targetNamespace}.
   */
  public record Version(String targetNamespace, String version) {}
}

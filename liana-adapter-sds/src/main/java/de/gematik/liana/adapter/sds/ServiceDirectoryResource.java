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

import de.gematik.liana.kern.management.ClientSystemBinding;
import de.gematik.liana.kern.vendor.VendorProfile;
import io.quarkus.qute.Location;
import io.quarkus.qute.Template;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import java.time.Clock;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.List;
import org.eclipse.microprofile.config.inject.ConfigProperty;

/**
 * Dienstverzeichnis service (TIP1-A_4528): {@code GET /connector.sds} on the Konnektor port.
 *
 * <p>Listed are the services the clients of the Testhub suites evaluate, each with all versions
 * LIANA serves (TIP1-A_4529-02, TAB_KON_518 {@code Service/Versions}; LIANA-120). TIP1-A_4586-04
 * also requires the older versions for the CardService (README.CardService.txt in api-telematik).
 * Clients choose their version according to gemILF_PS TIP1-A_4966: same major and minor version,
 * the revision may differ (gemILF_PS 9.2.2); the PoPP client takes the highest and builds the
 * SOAPAction from it. Announced per served namespace is every revision from the version histories
 * of the WSDLs in {@code support/schemas/conn/}, ascending, but not beyond the revision whose
 * behaviour LIANA reproduces (CertificateService 6.0.3, SignatureService from 7.5.6 on not). {@code
 * TargetNamespace} is the namespace of the schema, as the clients use it in the SOAPAction (the
 * secunet Konnektor puts the WSDL namespace there, {@code …/WSDL/v8.2}). The endpoints are derived
 * from {@code liana.kon-export.url} ({@code Endpoint}) and {@code liana.tls.url} ({@code
 * EndpointTLS}), the way clients reach LIANA; {@code ClientAutMandatory} follows {@code
 * liana.tls.client-auth} (LIANA-58).
 *
 * <p>LIANA implements SignatureService (7.4 and 7.5) and EncryptionService only up to the access
 * check (GetJobNumber complete, LIANA-60); the Konnektor PoPP Postman collections read their
 * endpoints from {@code connector.sds} and check them as present (LIANA-85).
 *
 * <p>VSDService is the Fachmodul VSDM with ReadVSD without Onlineprüfung (LIANA-119); name and
 * abstract are defined by Tab_FM_VSDM_23, the version by the schema {@code
 * conn/vsds/VSDService.xsd} (5.2.0, without version history).
 *
 * <p>KVKService is the VSDM module with ReadKVK (LIANA-113); Epikur requires it during pairing
 * (LIANA-189.01). Name and abstract are defined by VSDM-A_2793, the version by the schema {@code
 * conn/vsds/KvkService.xsd} (4.0.0).
 *
 * <p>{@code ProductVendorID} follows the vendor profile ({@link VendorProfile#productVendorId()},
 * LIANA-91).
 */
@Path("/connector.sds")
public class ServiceDirectoryResource {

  /** Product type version PTV6 (gemProdT_Kon_PTV6_6.0.4-1). */
  static final String PRODUCT_TYPE_VERSION = "6.0.4";

  private final Template template;
  private final String baseUrl;
  private final String tlsBaseUrl;
  private final ClientSystemBinding binding;
  private final String version;
  private final Clock clock;
  private final VendorProfile vendor;

  @SuppressWarnings("java:S5852") // trailing slashes of a configured URL
  public ServiceDirectoryResource(
      @Location("connector.sds.xml") Template template,
      @ConfigProperty(name = "liana.kon-export.url") String konExportUrl,
      @ConfigProperty(name = "liana.tls.url") String tlsUrl,
      ClientSystemBinding binding,
      @ConfigProperty(name = "quarkus.application.version") String version,
      Clock clock,
      VendorProfile vendor) {
    this.template = template;
    this.vendor = vendor;
    this.clock = clock;
    this.baseUrl = konExportUrl.replaceAll("/+$", "");
    this.tlsBaseUrl = tlsUrl.replaceAll("/+$", "");
    this.binding = binding;
    this.version = version;
  }

  @GET
  @Produces(MediaType.APPLICATION_XML)
  public String get() {
    return template.data("sds", directory()).render();
  }

  ServiceDirectory directory() {
    // ISO_INSTANT always writes seconds; OffsetDateTime.toString() omits :00, which is not an
    // xsd:dateTime
    ClientSystemBinding.State state = binding.state();
    String informationDate =
        DateTimeFormatter.ISO_INSTANT.format(clock.instant().truncatedTo(ChronoUnit.SECONDS));
    return new ServiceDirectory(
        informationDate,
        PRODUCT_TYPE_VERSION,
        vendor.productVendorId(),
        version,
        state.tlsMandatory(),
        state.authentication() != ClientSystemBinding.Authentication.NONE,
        List.of(
            service(
                "EventService",
                "Ereignisdienst",
                versions("http://ws.gematik.de/conn/EventService/v7.2", "7.2.0")),
            service(
                "CardTerminalService",
                "Kartenterminaldienst",
                versions("http://ws.gematik.de/conn/CardTerminalService/v1.1", "1.1.0")),
            service(
                "CardService",
                "Kartendienst",
                versions("http://ws.gematik.de/conn/CardService/v8.1", "8.1.0", "8.1.1", "8.1.2"),
                versions("http://ws.gematik.de/conn/CardService/v8.2", "8.2.0", "8.2.1")),
            service(
                "CertificateService",
                "Zertifikatsdienst",
                versions(
                    "http://ws.gematik.de/conn/CertificateService/v6.0",
                    "6.0.0",
                    "6.0.1",
                    "6.0.2")),
            service(
                "AuthSignatureService",
                "Authentifizierungsdienst",
                versions("http://ws.gematik.de/conn/SignatureService/v7.4", "7.4.0", "7.4.1")),
            service(
                "SignatureService",
                "Signaturdienst",
                versions(
                    "http://ws.gematik.de/conn/SignatureService/v7.4",
                    "7.4.0",
                    "7.4.1",
                    "7.4.2",
                    "7.4.3"),
                versions(
                    "http://ws.gematik.de/conn/SignatureService/v7.5",
                    "7.5.0",
                    "7.5.1",
                    "7.5.2",
                    "7.5.3",
                    "7.5.4",
                    "7.5.5")),
            service(
                "EncryptionService",
                "Verschlüsselungsdienst",
                versions("http://ws.gematik.de/conn/EncryptionService/v6.1", "6.1.0", "6.1.1")),
            service(
                "VSDService",
                "VSD von eGK lesen",
                versions("http://ws.gematik.de/conn/vsds/VSDService/v5.2", "5.2.0")),
            service(
                "KVKService",
                "Versichertendaten von KVK lesen",
                versions("http://ws.gematik.de/conn/vsds/KvkService/v4.0", "4.0.0"))));
  }

  @SafeVarargs
  private ServiceDirectory.Service service(
      String name, String description, List<ServiceDirectory.Version>... versions) {
    return new ServiceDirectory.Service(
        name,
        description,
        Arrays.stream(versions).flatMap(List::stream).toList(),
        baseUrl + "/ws/" + name,
        tlsBaseUrl + "/ws/" + name);
  }

  private static List<ServiceDirectory.Version> versions(String namespace, String... versions) {
    return Arrays.stream(versions).map(v -> new ServiceDirectory.Version(namespace, v)).toList();
  }
}

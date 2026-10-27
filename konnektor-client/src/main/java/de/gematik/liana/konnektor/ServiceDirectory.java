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

import de.gematik.liana.konnektor.ws.conn.servicedirectory.v3_1.ConnectorServices;
import de.gematik.liana.konnektor.ws.conn.serviceinformation.v2_0.EndpointType;
import de.gematik.liana.konnektor.ws.conn.serviceinformation.v2_0.ServiceType;
import de.gematik.liana.konnektor.ws.conn.serviceinformation.v2_0.VersionType;
import de.gematik.liana.konnektor.ws.tel.version.productinformation.v1_1.ProductInformation;
import de.gematik.liana.konnektor.ws.tel.version.productinformation.v1_1.ProductVersionLocal;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

/**
 * The Konnektor's Dienstverzeichnis ({@code connector.sds}, TIP1-A_4965) and the selection of the
 * service version per operation (TIP1-A_4966, LIANA-132): a version is offered if it is listed in
 * the directory; the highest one for which the client has a binding with this operation is used.
 * Major and minor version must match, the revision may differ.
 *
 * @param product product information ({@code PI:ProductInformation})
 * @param tlsMandatory {@code TLSMandatory}
 * @param clientAuthMandatory {@code ClientAutMandatory}
 * @param offered all offered service versions in document order
 */
public record ServiceDirectory(
    Product product, boolean tlsMandatory, boolean clientAuthMandatory, List<Offer> offered) {

  private static final JAXBContext CONTEXT = context();

  public ServiceDirectory {
    offered = List.copyOf(offered);
  }

  /**
   * An offered service version.
   *
   * @param service name in the directory ({@code SI:Service/@Name}), also for services without a
   *     binding
   * @param version {@code Version}
   * @param targetNamespace {@code TargetNamespace}; vendors enter the schema or the WSDL namespace
   * @param endpoint {@code Endpoint}, missing for some Konnektors
   * @param endpointTls {@code EndpointTLS}
   */
  public record Offer(
      String service,
      Version version,
      String targetNamespace,
      Optional<URI> endpoint,
      URI endpointTls) {}

  /**
   * The selected version for an operation.
   *
   * @param operation the operation
   * @param binding the client's binding
   * @param offer the offered version with its endpoints
   */
  public record Selection(Operation operation, Binding binding, Offer offer) {}

  /** Reads {@code connector.sds}; DTDs and external entities are disabled. */
  public static ServiceDirectory read(InputStream in) throws IOException {
    XMLInputFactory factory = XMLInputFactory.newFactory();
    factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
    factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
    ConnectorServices sds;
    try {
      XMLStreamReader reader = factory.createXMLStreamReader(in);
      Object root = CONTEXT.createUnmarshaller().unmarshal(reader);
      if (!(root instanceof ConnectorServices services)) {
        throw new IOException("connector.sds: Wurzelelement ist nicht CONN:ConnectorServices");
      }
      sds = services;
    } catch (JAXBException | XMLStreamException e) {
      throw new IOException("connector.sds nicht lesbar: " + e.getMessage(), e);
    }
    List<Offer> offers = new ArrayList<>();
    if (sds.getServiceInformation() != null) {
      for (ServiceType service : sds.getServiceInformation().getService()) {
        if (service.getVersions() == null) {
          continue;
        }
        for (VersionType version : service.getVersions().getVersion()) {
          Optional<URI> endpoint =
              Optional.ofNullable(version.getEndpoint()).map(ServiceDirectory::uri);
          offers.add(
              new Offer(
                  service.getName(),
                  Version.parse(version.getVersion()),
                  version.getTargetNamespace(),
                  endpoint,
                  uri(version.getEndpointTLS())));
        }
      }
    }
    return new ServiceDirectory(
        product(sds.getProductInformation()),
        sds.isTLSMandatory(),
        sds.isClientAutMandatory(),
        offers);
  }

  /** Offered versions of a service, in ascending order. */
  public List<Offer> offered(Service service) {
    return offered.stream()
        .filter(o -> o.service().equals(service.sdsName()))
        .sorted(Comparator.comparing(Offer::version))
        .toList();
  }

  /**
   * Selects the highest offered version for which the client has a binding with the operation.
   *
   * @throws UnsupportedOperationException if the Konnektor does not offer the service, or only in
   *     versions without a binding; the message names the service, the offered and the bound
   *     versions
   */
  public Selection select(Operation operation) {
    List<Offer> offers = offered(operation.service());
    for (int i = offers.size() - 1; i >= 0; i--) {
      Offer offer = offers.get(i);
      for (Binding binding : operation.bindings()) {
        if (binding.serves(offer.version())) {
          return new Selection(operation, binding, offer);
        }
      }
    }
    throw new UnsupportedOperationException(
        operation.service().sdsName()
            + "."
            + operation.wsdlName()
            + ": angeboten "
            + (offers.isEmpty()
                ? "keine Version"
                : offers.stream()
                    .map(o -> o.version().toString())
                    .collect(Collectors.joining(", ")))
            + ", Client-Bindings "
            + operation.bindings().stream()
                .map(Binding::version)
                .collect(Collectors.joining(", ")));
  }

  private static Product product(ProductInformation info) {
    if (info == null || info.getProductIdentification() == null) {
      return new Product(null, null, null, null, null, null, null);
    }
    var id = info.getProductIdentification();
    ProductVersionLocal local =
        id.getProductVersion() == null ? null : id.getProductVersion().getLocal();
    var misc = info.getProductMiscellaneous();
    var type = info.getProductTypeInformation();
    return new Product(
        id.getProductVendorID(),
        id.getProductCode(),
        type == null ? null : type.getProductTypeVersion(),
        local == null ? null : local.getHWVersion(),
        local == null ? null : local.getFWVersion(),
        misc == null ? null : misc.getProductVendorName(),
        misc == null ? null : misc.getProductName());
  }

  private static URI uri(EndpointType endpoint) {
    return endpoint == null ? null : URI.create(endpoint.getLocation().trim());
  }

  private static JAXBContext context() {
    try {
      return JAXBContext.newInstance(ConnectorServices.class);
    } catch (JAXBException e) {
      throw new ExceptionInInitializerError(e);
    }
  }
}

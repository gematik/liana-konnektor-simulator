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
package de.gematik.liana.wiring;

import de.gematik.liana.config.LianaConfig;
import de.gematik.liana.crypto.ClientCertificateList;
import de.gematik.liana.crypto.ClientCertificates;
import de.gematik.liana.crypto.ServerIdentities;
import de.gematik.liana.crypto.TlsIdentity;
import de.gematik.liana.kern.management.ClientSystemBinding;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;
import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Optional;

/**
 * Server identity ID.AK.AUT from {@code liana.infrastructure.konnektor.gsmc-k}: connector interface
 * and KMS (LIANA-58); plus the state that the KMS changes at runtime (LIANA-65): connection of the
 * Clientsysteme, ANCL_CCERT_LIST and server identities.
 */
@ApplicationScoped
public class TlsWiring {

  @Produces
  @Singleton
  TlsIdentity tlsIdentity(LianaConfig config) throws GeneralSecurityException, IOException {
    LianaConfig.GsmcK gsmcK = config.infrastructure().konnektor().gsmcK();
    return TlsIdentity.load(gsmcK.akAut(), gsmcK.password());
  }

  @Produces
  @Singleton
  ClientSystemBinding clientSystemBinding(LianaConfig config) {
    var tls = config.tls();
    return new ClientSystemBinding(
        new ClientSystemBinding.State(
            tls.mandatory(),
            tls.clientAuth()
                ? ClientSystemBinding.Authentication.CERTIFICATE
                : ClientSystemBinding.Authentication.NONE,
            tls.dvdOpen(),
            tls.eccForClientSystems(),
            false));
  }

  @Produces
  @Singleton
  ServerIdentities serverIdentities(
      LianaConfig config, TlsIdentity ecc, ClientSystemBinding binding)
      throws GeneralSecurityException, IOException {
    LianaConfig.GsmcK gsmcK = config.infrastructure().konnektor().gsmcK();
    Optional<Path> rsa = gsmcK.akAutRsa();
    return new ServerIdentities(
        ecc,
        rsa.isPresent()
            ? Optional.of(TlsIdentity.load(rsa.get(), gsmcK.password()))
            : Optional.empty(),
        binding);
  }

  /**
   * Boot certificates from {@code liana.tls.client-certs}, assigned to the first Clientsystem of
   * the Informationsmodell.
   */
  @Produces
  @Singleton
  ClientCertificates clientCertificates(LianaConfig config)
      throws GeneralSecurityException, IOException {
    List<String> clientSystems = config.infomodel().clientSystems();
    String owner = clientSystems.isEmpty() ? "" : clientSystems.getFirst();
    return new ClientCertificates(
        owner,
        ClientCertificateList.load(config.tls().clientCerts().orElse(List.of())).certificates());
  }
}

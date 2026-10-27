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

import de.gematik.liana.adapter.vsdm.UfsClient;
import de.gematik.liana.config.LianaConfig;
import de.gematik.liana.crypto.CardTls;
import de.gematik.liana.crypto.TrustSpace;
import de.gematik.liana.kern.access.Context;
import de.gematik.liana.kern.card.CardAccess;
import de.gematik.liana.kern.card.CardCertificates;
import de.gematik.liana.kern.card.CardLocks;
import de.gematik.liana.kern.card.CardObject;
import de.gematik.liana.kern.card.EgkFiles;
import de.gematik.liana.kern.card.ExternalAuthentication;
import de.gematik.liana.kern.card.KvkFiles;
import de.gematik.liana.kern.card.PinVerification;
import de.gematik.liana.kern.error.ConnectorException;
import de.gematik.liana.kern.event.SystemLog;
import de.gematik.liana.kern.management.ManagementSettings;
import de.gematik.liana.kern.terminal.TerminalRegistry;
import de.gematik.liana.kern.vendor.PeerDeviations;
import de.gematik.liana.kern.vsdm.FixedSource;
import de.gematik.liana.kern.vsdm.OnlineCheck;
import de.gematik.liana.kern.vsdm.ReadKvk;
import de.gematik.liana.kern.vsdm.ReadVsd;
import de.gematik.liana.kern.vsdm.UfsSource;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.util.List;

/**
 * the Fachmodul VSDM (LIANA-119, LIANA-141): ReadVSD with the Onlineprüfung from {@code
 * liana.vsdm}, ReadKVK (LIANA-113). The chain is built from {@code online.sources} in this order;
 * {@code ufs} queries the endpoints via {@link UfsClient}, with {@code https} via {@link CardTls}
 * (TUC_KON_110) with the SM-B of the call: C.HCI.AUT via ReadCardCertificate, the signature in the
 * handshake via TUC_KON_218 on the card.
 */
@ApplicationScoped
public class VsdmWiring {

  @Produces
  @Singleton
  OnlineCheck onlineCheck(
      LianaConfig config,
      UfsClient ufsClient,
      ManagementSettings settings,
      PeerDeviations deviations,
      SystemLog systemLog,
      Clock clock) {
    LianaConfig.Vsdm vsdm = config.vsdm();
    List<OnlineCheck.Source> sources =
        vsdm.online().sources().orElse(List.of()).stream()
            .map(
                name ->
                    switch (name) {
                      case UfsSource.CONFIG_NAME ->
                          (OnlineCheck.Source)
                              new UfsSource(
                                  vsdm.online().ufs().endpoints().orElse(List.of()).stream()
                                      .map(
                                          e ->
                                              new UfsSource.Endpoint(
                                                  e.url(), e.providerId().orElse(null)))
                                      .toList(),
                                  ufsClient,
                                  vsdm.online().ufs().connectTimeout(),
                                  vsdm.timeout(),
                                  vsdm.online().ufs().retryAfter(),
                                  clock);
                      case FixedSource.CONFIG_NAME -> new FixedSource();
                      default ->
                          throw new IllegalStateException(
                              "vsdm.online.sources: " + name + " (ConfigCheck)");
                    })
            .toList();
    return new OnlineCheck(
        sources, vsdm.maxTime(), settings::online, deviations::strict, systemLog, clock);
  }

  @Produces
  @Singleton
  UfsClient ufsClient(
      TrustSpace trustSpace,
      Clock clock,
      CardCertificates certificates,
      ExternalAuthentication authentication) {
    CardTls tls = CardTls.of(trustSpace, clock);
    return new UfsClient(
        (url, context, smb, timeout) ->
            "https".equals(url.getScheme())
                ? tls.connect(
                    url.getHost(),
                    port(url, 443),
                    smbKey(context, smb, certificates, authentication),
                    timeout)
                : plain(url, timeout),
        clock);
  }

  /** the Fachmodul VSDM: ReadVSD (LIANA-119), with Onlineprüfung (LIANA-141). */
  @Produces
  @Singleton
  ReadVsd readVsd(
      CardAccess access, CardLocks locks, EgkFiles files, PinVerification pins, OnlineCheck check) {
    return new ReadVsd(access, locks, files, pins, check);
  }

  /** the Fachmodul VSDM: ReadKVK with the KVK in the fake CT (LIANA-113). */
  @Produces
  @Singleton
  ReadKvk readKvk(CardAccess access, TerminalRegistry terminals, Clock clock) {
    return new ReadKvk(access, new KvkFiles(terminals), clock);
  }

  /**
   * ID.HCI.AUT of the SM-B: certificate and signature via the card; card errors as IOException
   * (4157).
   */
  private static CardTls.CardKey smbKey(
      Context context,
      CardObject smb,
      CardCertificates certificates,
      ExternalAuthentication authentication) {
    return new CardTls.CardKey() {
      @Override
      public byte[] certificate() throws IOException {
        try {
          return certificates
              .read(context, smb.cardHandle(), List.of("C.AUT"), "ECC")
              .getFirst()
              .der();
        } catch (ConnectorException e) {
          throw new IOException("C.HCI.AUT nicht lesbar: " + e.getMessage(), e);
        }
      }

      @Override
      public byte[] sign(byte[] sha256) throws IOException {
        try {
          return authentication.sign(context, smb.cardHandle(), sha256);
        } catch (ConnectorException e) {
          throw new IOException("Signatur mit PrK.HCI.AUT.E256: " + e.getMessage(), e);
        }
      }
    };
  }

  private static int port(URI url, int fallback) {
    return url.getPort() < 0 ? fallback : url.getPort();
  }

  private static Socket plain(URI url, Duration timeout) throws IOException {
    Socket socket = new Socket();
    try {
      socket.connect(
          new InetSocketAddress(url.getHost(), port(url, 80)), Math.toIntExact(timeout.toMillis()));
      return socket;
    } catch (IOException e) {
      socket.close();
      throw e;
    }
  }
}

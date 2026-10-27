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
import de.gematik.liana.kern.event.SystemLog;
import de.gematik.liana.kern.vendor.PeerDeviations;
import de.gematik.liana.kern.vendor.Vendor;
import de.gematik.liana.kern.vendor.VendorProfile;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;

/**
 * Vendor profile from {@code liana.vendor} (decision-10, {@code ConfigCheck} has checked the value
 * beforehand) and, alongside it, the switch {@code liana.strict} for deviations of the peers
 * (LIANA-126).
 */
@ApplicationScoped
public class VendorWiring {

  @Produces
  @Singleton
  VendorProfile vendorProfile(LianaConfig config) {
    return new VendorProfile(Vendor.of(config.vendor()));
  }

  @Produces
  @Singleton
  PeerDeviations peerDeviations(LianaConfig config, SystemLog systemLog) {
    return new PeerDeviations(config.strict(), systemLog);
  }
}

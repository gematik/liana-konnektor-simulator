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

import de.gematik.liana.kern.vendor.Deviation;
import de.gematik.liana.kern.vendor.PeerDeviations;
import jakarta.enterprise.inject.Instance;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.PreMatching;
import jakarta.ws.rs.ext.Provider;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Serves {@code /ws/<Service>/<Version>} like {@code /ws/<Service>} for clients with hard-wired
 * versioned paths (LIANA-218), for every version {@code connector.sds} offers for that service.
 * These clients deviate from gemILF_PS TIP1-A_4967, so this goes through {@link
 * Deviation#HARDCODED_VERSIONED_ENDPOINT}: with {@code liana.strict} the path answers 404. Any
 * other version stays unmatched and answers 404; {@code connector.sds} itself names only the
 * unversioned endpoints. The path version does not select anything: the SOAP version is the body
 * namespace.
 */
@Provider
@PreMatching
public class VersionedEndpointFilter implements ContainerRequestFilter {

  private static final Pattern VERSIONED = Pattern.compile("/ws/([^/]+)/([^/]+)");

  // Filters are created during static init, the resource needs the runtime configuration.
  private final Instance<ServiceDirectoryResource> directory;

  private final Instance<PeerDeviations> deviations;

  VersionedEndpointFilter(
      Instance<ServiceDirectoryResource> directory, Instance<PeerDeviations> deviations) {
    this.directory = directory;
    this.deviations = deviations;
  }

  @Override
  public void filter(ContainerRequestContext request) {
    String path = request.getUriInfo().getRequestUri().getPath();
    Matcher versioned = VERSIONED.matcher(path);
    if (versioned.matches()
        && directory.get().offers(versioned.group(1), versioned.group(2))
        && deviations
            .get()
            .tolerate(
                Deviation.HARDCODED_VERSIONED_ENDPOINT, "Clientsystem", Map.of("Pfad", path))) {
      request.setRequestUri(
          request
              .getUriInfo()
              .getRequestUriBuilder()
              .replacePath("/ws/" + versioned.group(1))
              .build());
    }
  }
}

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
package de.gematik.liana.admin;

import de.gematik.liana.adapter.sds.ServiceDirectoryResource;
import io.quarkus.runtime.ShutdownEvent;
import io.quarkus.runtime.StartupEvent;
import jakarta.annotation.Priority;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Singleton;
import jakarta.interceptor.Interceptor;

/**
 * Readiness of LIANA for {@code GET /admin/ready} (LIANA-107): ready as soon as all startup
 * observers have run (configuration checked, CTs with inserted card images, infrastructure, servers
 * on all ports) and {@code /connector.sds} can be rendered. No longer ready on shutdown.
 */
@Singleton
public class Readiness {

  private final ServiceDirectoryResource serviceDirectory;
  private volatile boolean ready;

  Readiness(ServiceDirectoryResource serviceDirectory) {
    this.serviceDirectory = serviceDirectory;
  }

  /** Runs after all other startup observers. */
  void onStart(@Observes @Priority(Interceptor.Priority.PLATFORM_AFTER + 1000) StartupEvent event) {
    serviceDirectory.get();
    ready = true;
  }

  void onStop(@Observes @Priority(Interceptor.Priority.PLATFORM_BEFORE) ShutdownEvent event) {
    ready = false;
  }

  public boolean ready() {
    return ready;
  }
}

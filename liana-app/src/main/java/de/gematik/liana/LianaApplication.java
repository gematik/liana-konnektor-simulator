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
package de.gematik.liana;

import de.gematik.liana.config.LianaConfig;
import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Singleton;
import org.jboss.logging.Logger;

/** Entry point of LIANA: logs the start with the environment from the boot configuration. */
@Singleton
public class LianaApplication {

  private static final Logger LOG = Logger.getLogger(LianaApplication.class);

  private final LianaConfig config;

  LianaApplication(LianaConfig config) {
    this.config = config;
  }

  void onStart(@Observes StartupEvent event) {
    LOG.infof("LIANA gestartet (env=%s)", env());
  }

  /** Environment from {@code liana.env} (ru | tu | pu). */
  public String env() {
    return config.env().value();
  }
}

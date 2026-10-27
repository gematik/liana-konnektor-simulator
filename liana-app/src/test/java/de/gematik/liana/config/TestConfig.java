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
package de.gematik.liana.config;

import io.quarkus.runtime.configuration.DurationConverter;
import io.smallrye.config.EnvConfigSource;
import io.smallrye.config.PropertiesConfigSource;
import io.smallrye.config.SmallRyeConfig;
import io.smallrye.config.SmallRyeConfigBuilder;
import io.smallrye.config.source.yaml.YamlConfigSource;
import java.io.IOException;
import java.time.Duration;
import java.util.Map;

/**
 * {@link LianaConfig} from the bundled {@code application.yaml} with overrides, without starting
 * Quarkus.
 */
public final class TestConfig {

  private TestConfig() {}

  public static LianaConfig load(Map<String, String> env, Map<String, String> overrides)
      throws IOException {
    SmallRyeConfig config =
        new SmallRyeConfigBuilder()
            .withSources(
                new YamlConfigSource(
                    TestConfig.class.getClassLoader().getResource("application.yaml"), 250))
            .withSources(new PropertiesConfigSource(overrides, "overrides", 260))
            .withSources(new EnvConfigSource(env, 300))
            // as in Quarkus: durations as 120s, 500ms …
            .withConverter(Duration.class, 100, new DurationConverter())
            .withInterceptors(new RetiredKeys())
            .withMapping(LianaConfig.class)
            .build();
    return config.getConfigMapping(LianaConfig.class);
  }

  public static LianaConfig load(Map<String, String> overrides) throws IOException {
    return load(Map.of(), overrides);
  }
}

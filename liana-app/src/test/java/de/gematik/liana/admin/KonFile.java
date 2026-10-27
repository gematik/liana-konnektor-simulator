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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Loads a {@code .kon} like a client: §4 substitution on the raw text, then JSON (kon-format §3).
 */
final class KonFile {

  /**
   * {@code ${NAME}}, NAME up to the first {@code }}, literally; {@code $NAME} without braces stays
   * as is.
   */
  private static final Pattern PLACEHOLDER = Pattern.compile("\\$\\{([^}]+)}");

  private KonFile() {}

  /**
   * Replaces every placeholder with the value from {@code env}, an undefined one with the empty
   * string.
   */
  static String substitute(String raw, Map<String, String> env) {
    return PLACEHOLDER
        .matcher(raw)
        .replaceAll(m -> Matcher.quoteReplacement(env.getOrDefault(m.group(1), "")));
  }

  static JsonNode load(String raw, Map<String, String> env) throws IOException {
    return new ObjectMapper().readTree(substitute(raw, env));
  }
}

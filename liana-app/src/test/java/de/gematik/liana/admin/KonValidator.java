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
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;

/**
 * Rules from kon-format §7, reports all field errors at once. Empty list: the configuration is
 * valid.
 */
final class KonValidator {

  private static final Set<String> ENVS = Set.of("ru", "tu", "pu");

  private KonValidator() {}

  static List<String> errors(JsonNode kon) {
    List<String> errors = new ArrayList<>();
    if (kon == null || !kon.isObject()) {
      errors.add("Konfiguration ist kein JSON-Objekt");
      return errors;
    }
    for (String field : List.of("url", "mandantId", "workplaceId", "clientSystemId")) {
      required(kon, field, field, errors);
    }
    if (kon.has("env") && !ENVS.contains(kon.get("env").asText())) {
      errors.add("env muss ru, tu oder pu sein, ist '" + kon.get("env").asText() + "'");
    }
    JsonNode credentials = kon.get("credentials");
    if (credentials == null || !credentials.isObject()) {
      errors.add("credentials is required");
    } else {
      switch (credentials.path("type").asText("")) {
        case "" -> errors.add("credentials.type is required");
        case "basic" -> {
          required(credentials, "username", "credentials.username", errors);
          required(credentials, "password", "credentials.password", errors);
        }
        case "pkcs12" -> {
          if (required(credentials, "data", "credentials.data", errors)) {
            base64(credentials.get("data").asText(), "credentials.data", errors);
          }
        }
        case "system" -> required(credentials, "name", "credentials.name", errors);
        default ->
            errors.add("credentials.type '" + credentials.get("type").asText() + "' ist unbekannt");
      }
    }
    JsonNode trustStore = kon.path("trustStore");
    for (int i = 0; i < trustStore.size(); i++) {
      base64(trustStore.get(i).asText(), "trustStore[" + i + "]", errors);
    }
    return errors;
  }

  private static boolean required(JsonNode node, String field, String name, List<String> errors) {
    if (node.path(field).asText("").isBlank()) {
      errors.add(name + " is required");
      return false;
    }
    return true;
  }

  /** Line breaks (MIME) allowed, otherwise only the Base64 alphabet. */
  private static void base64(String value, String name, List<String> errors) {
    try {
      Base64.getDecoder().decode(value.replaceAll("\\s", ""));
    } catch (IllegalArgumentException e) {
      errors.add(name + " ist kein gültiges Base64");
    }
  }
}

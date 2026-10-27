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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.UnaryOperator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A Konnektor configuration in {@code .kon} format v1.0.0 ({@code support/kon/kon-format.md},
 * decision-5: as it is). The input is JSON; {@code ${NAME}} is substituted in the raw text before
 * parsing (§4), anywhere in the document; an unknown variable becomes empty. Validation follows §7,
 * reporting all field errors at once; messages name fields, never values.
 *
 * @param version {@code version}, optional
 * @param url {@code url} without trailing {@code /}
 * @param rewriteServiceEndpoints {@code rewriteServiceEndpoints}
 * @param context {@code mandantId}, {@code clientSystemId}, {@code workplaceId}, {@code userId}
 * @param telematikId {@code telematikId}, optional
 * @param credentials {@code credentials}
 * @param env {@code env} ({@code ru}, {@code tu}, {@code pu}), optional
 * @param trust {@code trustStore}, {@code expectedHost}, {@code insecureSkipVerify}
 */
public record KonConfig(
    String version,
    URI url,
    boolean rewriteServiceEndpoints,
    Context context,
    String telematikId,
    Credentials credentials,
    String env,
    Trust trust) {

  private static final Pattern VARIABLE = Pattern.compile("\\$\\{([^}]+)}");
  private static final Set<String> ENVIRONMENTS = Set.of("ru", "tu", "pu");

  /** Reads a {@code .kon} file with the variables of the process environment. */
  public static KonConfig read(Path file) throws IOException {
    return read(file, System::getenv);
  }

  /** Reads a {@code .kon} file; {@code env} resolves {@code ${NAME}}. */
  public static KonConfig read(Path file, UnaryOperator<String> env) throws IOException {
    String name = file.getFileName().toString();
    if (name.endsWith(".kony")) {
      throw new IllegalArgumentException(
          ".kony (YAML) wird nicht unterstützt, nur .kon (JSON): " + name);
    }
    return parse(Files.readString(file, StandardCharsets.UTF_8), env);
  }

  /**
   * Reads a {@code .kon} document.
   *
   * @param env resolves {@code ${NAME}}; a {@code null} result means unknown and becomes empty (§4)
   * @throws IllegalArgumentException with all field errors
   */
  public static KonConfig parse(String text, UnaryOperator<String> env) {
    Object root = Json.parse(substitute(text, env));
    if (!(root instanceof Map<?, ?> map)) {
      throw new IllegalArgumentException(".kon: das Dokument ist kein JSON-Objekt");
    }
    return new Reader(map).config();
  }

  /** §4: {@code ${NAME}} in the raw text, unknown becomes empty, {@code $NAME} stays as is. */
  static String substitute(String text, UnaryOperator<String> env) {
    Matcher m = VARIABLE.matcher(text);
    StringBuilder out = new StringBuilder();
    while (m.find()) {
      String value = env.apply(m.group(1));
      m.appendReplacement(out, Matcher.quoteReplacement(value == null ? "" : value));
    }
    m.appendTail(out);
    return out.toString();
  }

  @Override
  public String toString() {
    return "KonConfig[url="
        + url
        + ", context="
        + context
        + ", credentials="
        + credentials
        + ", env="
        + env
        + "]";
  }

  private static final class Reader {

    private final Map<?, ?> map;
    private final List<String> errors = new ArrayList<>();

    Reader(Map<?, ?> map) {
      this.map = map;
    }

    KonConfig config() {
      String version = string(map, "version", false);
      URI url = url();
      boolean rewrite = bool(map, "rewriteServiceEndpoints");
      String mandant = string(map, "mandantId", true);
      String workplace = string(map, "workplaceId", true);
      String clientSystem = string(map, "clientSystemId", true);
      String user = string(map, "userId", false);
      String telematikId = string(map, "telematikId", false);
      Credentials credentials = credentials();
      String env = string(map, "env", false);
      if (env != null && !ENVIRONMENTS.contains(env)) {
        errors.add("env: nur ru, tu oder pu");
      }
      boolean insecure = bool(map, "insecureSkipVerify");
      String expectedHost = string(map, "expectedHost", false);
      List<X509Certificate> trustStore = trustStore();
      if (!errors.isEmpty()) {
        throw new IllegalArgumentException(".kon ungültig: " + String.join("; ", errors));
      }
      return new KonConfig(
          version,
          url,
          rewrite,
          new Context(mandant, clientSystem, workplace, user),
          telematikId,
          credentials,
          env,
          new Trust(trustStore, expectedHost, insecure));
    }

    @SuppressWarnings("java:S5852") // trailing slashes of a configured URL
    private URI url() {
      String url = string(map, "url", true);
      if (url == null) {
        return null;
      }
      try {
        URI uri = new URI(url.replaceAll("/+$", ""));
        if (uri.getScheme() == null
            || uri.getHost() == null
            || !Set.of("http", "https").contains(uri.getScheme())) {
          errors.add("url: Schema (https:// oder http://) und Host erforderlich");
          return null;
        }
        return uri;
      } catch (URISyntaxException e) {
        errors.add("url: keine gültige URL");
        return null;
      }
    }

    private Credentials credentials() {
      Object value = map.get("credentials");
      if (!(value instanceof Map<?, ?> c)) {
        errors.add(value == null ? "credentials: fehlt" : "credentials: kein Objekt");
        return null;
      }
      String type = string(c, "type", true, "credentials.type");
      if (type == null) {
        return null;
      }
      switch (type) {
        case "basic" -> {
          String username = string(c, "username", true, "credentials.username");
          String password = string(c, "password", true, "credentials.password");
          return username == null || password == null
              ? null
              : Credentials.basic(username, password);
        }
        case "pkcs12" -> {
          String data = string(c, "data", true, "credentials.data");
          String password = string(c, "password", false, "credentials.password");
          byte[] der = data == null ? null : base64(data, "credentials.data");
          return der == null
              ? null
              : Credentials.pkcs12(der, password == null ? new char[0] : password.toCharArray());
        }
        case "system" -> {
          String name = string(c, "name", true, "credentials.name");
          return name == null ? null : new Credentials.SystemStore(name);
        }
        default -> {
          errors.add("credentials.type: unbekannt, erlaubt sind basic, pkcs12, system");
          return null;
        }
      }
    }

    private List<X509Certificate> trustStore() {
      Object value = map.get("trustStore");
      if (value == null) {
        return List.of();
      }
      if (!(value instanceof List<?> list)) {
        errors.add("trustStore: kein Array");
        return List.of();
      }
      List<X509Certificate> certificates = new ArrayList<>();
      for (int i = 0; i < list.size(); i++) {
        String field = "trustStore[" + i + "]";
        if (!(list.get(i) instanceof String s)) {
          errors.add(field + ": keine Zeichenkette");
          continue;
        }
        byte[] der = base64(s, field);
        if (der == null) {
          continue;
        }
        try {
          certificates.add(
              (X509Certificate)
                  CertificateFactory.getInstance("X.509", Bc.PROVIDER)
                      .generateCertificate(new ByteArrayInputStream(der)));
        } catch (CertificateException e) {
          errors.add(field + ": kein X.509-Zertifikat");
        }
      }
      return certificates;
    }

    private byte[] base64(String value, String field) {
      try {
        // MIME-wrapped Base64 is allowed (§5, §6.2); but the JDK's MIME decoder also skips
        // invalid characters, so only strip whitespace and decode strictly
        return Base64.getDecoder().decode(value.replaceAll("\\s", ""));
      } catch (IllegalArgumentException e) {
        errors.add(field + ": kein gültiges Base64");
        return null;
      }
    }

    private String string(Map<?, ?> m, String key, boolean required) {
      return string(m, key, required, key);
    }

    private String string(Map<?, ?> m, String key, boolean required, String field) {
      Object value = m.get(key);
      if (value == null) {
        if (required) {
          errors.add(field + ": fehlt");
        }
        return null;
      }
      if (!(value instanceof String s)) {
        errors.add(field + ": keine Zeichenkette");
        return null;
      }
      if (required && s.isBlank()) {
        errors.add(field + ": leer");
        return null;
      }
      return s;
    }

    private boolean bool(Map<?, ?> m, String key) {
      Object value = m.get(key);
      if (value == null) {
        return false;
      }
      if (!(value instanceof Boolean b)) {
        errors.add(key + ": kein Wahrheitswert");
        return false;
      }
      return b;
    }
  }
}

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
package de.gematik.liana.control;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Client of LIANA's Admin API (control plane, LIANA-138; decision-4, docs/handbuch.md „Admin-API“):
 * insert and pull cards, faults, PIN script, vendor profile, Informationsmodell, {@code .kon},
 * reset; plus the views for the Control Center (LIANA-149): card list, images, subscriptions,
 * sessions, PKI, settings, deviations, self-tests, discovery, OpenAPI. Responses as JSON values
 * ({@code Map}, {@code List}, {@code String}, {@code Double}, {@code Boolean}); errors as {@link
 * LianaControlException} with LIANA's message. No relation to the Konnektor client (separate
 * planes).
 */
public final class LianaControl {

  private final URI base;
  private final HttpClient client;
  private final Duration timeout;

  @SuppressWarnings("java:S5852") // trailing slashes of a configured URL
  private LianaControl(URI base, Duration timeout) {
    this.base = URI.create(base.toString().replaceAll("/+$", ""));
    this.client =
        HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .connectTimeout(timeout)
            .build();
    this.timeout = timeout;
  }

  /** Admin API at {@code base}, such as {@code http://localhost:9090}. */
  public static LianaControl connect(URI base) {
    return new LianaControl(base, Duration.ofSeconds(10));
  }

  public static LianaControl connect(String base) {
    return connect(URI.create(base));
  }

  /** Like {@link #connect(URI)}, with a custom response timeout. */
  public static LianaControl connect(URI base, Duration timeout) {
    return new LianaControl(base, timeout);
  }

  /**
   * {@code GET /admin/ready}: true once LIANA has fully started; false on 503 or without a
   * connection.
   */
  public boolean ready() {
    try {
      HttpResponse<String> response =
          client.send(request("/admin/ready").GET().build(), HttpResponse.BodyHandlers.ofString());
      return response.statusCode() == 200
          && Boolean.TRUE.equals(asMap(Json.parse(response.body())).get("ready"));
    } catch (IOException e) {
      return false;
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      return false;
    }
  }

  /** Waits until {@link #ready()} or until {@code limit} has elapsed. */
  public boolean awaitReady(Duration limit) {
    long end = System.nanoTime() + limit.toNanos();
    while (System.nanoTime() < end) {
      if (ready()) {
        return true;
      }
      try {
        Thread.sleep(100);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        return false;
      }
    }
    return ready();
  }

  /** {@code GET /admin/info}: version, environment, vendor profile, ports, terminal mode. */
  public Map<String, Object> info() {
    return asMap(get("/admin/info"));
  }

  /** {@code GET /admin/terminals}: all card terminals with slots. */
  public List<Map<String, Object>> terminals() {
    return asList(get("/admin/terminals"));
  }

  /** {@code GET /admin/terminals/{id}}. */
  public Map<String, Object> terminal(String id) {
    return asMap(get("/admin/terminals/" + path(id)));
  }

  /** {@code GET /admin/ct-list}: CTM_CT_LIST, all eHealth card terminals with CT object. */
  public List<Map<String, Object>> ctList() {
    return asList(get("/admin/ct-list"));
  }

  /**
   * {@code POST /admin/terminals/{id}/pairing}: TUC_KON_053, optionally with an expected
   * fingerprint.
   */
  public Map<String, Object> pair(String terminal, String fingerprint) {
    Map<String, Object> body = new LinkedHashMap<>();
    if (fingerprint != null) {
      body.put("fingerprint", fingerprint);
    }
    return asMap(send("POST", "/admin/terminals/" + path(terminal) + "/pairing", body));
  }

  /**
   * {@code PUT /admin/terminals/{id}/pairing}: set CT.SHARED_SECRET transiently (32 hex digits).
   */
  public Map<String, Object> setSharedSecret(String terminal, String sharedSecret) {
    return asMap(
        send(
            "PUT",
            "/admin/terminals/" + path(terminal) + "/pairing",
            Map.of("sharedSecret", sharedSecret)));
  }

  /** {@code DELETE /admin/terminals/{id}/pairing}. */
  public Map<String, Object> deleteSharedSecret(String terminal) {
    return asMap(send("DELETE", "/admin/terminals/" + path(terminal) + "/pairing", null));
  }

  // Write calls on a card terminal respond with the terminal afterwards (like GET
  // /admin/terminals/{id}).

  /**
   * {@code PUT /admin/terminals/{id}/slots/{n}}: insert a card (file name, ICCSN or absolute path).
   */
  public Map<String, Object> insertCard(String terminal, int slot, String image) {
    return asMap(send("PUT", slot(terminal, slot), Map.of("image", image)));
  }

  /** {@code DELETE /admin/terminals/{id}/slots/{n}}: pull the card. */
  public Map<String, Object> ejectCard(String terminal, int slot) {
    return asMap(send("DELETE", slot(terminal, slot), null));
  }

  /** {@code PUT /admin/terminals/{id}/slots/{n}/fault}: set a fault, replaces an existing one. */
  public Map<String, Object> setFault(String terminal, int slot, Fault fault) {
    return asMap(send("PUT", slot(terminal, slot) + "/fault", fault.json()));
  }

  /** {@code DELETE /admin/terminals/{id}/slots/{n}/fault}. */
  public Map<String, Object> clearFault(String terminal, int slot) {
    return asMap(send("DELETE", slot(terminal, slot) + "/fault", null));
  }

  /** {@code POST /admin/terminals/{id}/pin-script}: append PIN entries. */
  public Map<String, Object> appendPinScript(String terminal, List<PinInput> inputs) {
    List<Object> body = new ArrayList<>();
    inputs.forEach(input -> body.add(input.json()));
    return asMap(send("POST", "/admin/terminals/" + path(terminal) + "/pin-script", body));
  }

  /** {@code DELETE /admin/terminals/{id}/pin-script}: clear the PIN script. */
  public Map<String, Object> clearPinScript(String terminal) {
    return asMap(send("DELETE", "/admin/terminals/" + path(terminal) + "/pin-script", null));
  }

  /** {@code GET /admin/infomodel}: mandants, Clientsysteme, workplaces. */
  public Map<String, Object> infomodel() {
    return asMap(get("/admin/infomodel"));
  }

  /**
   * {@code GET /admin/tls}: ANCL_TLS_MANDATORY, ANCL_CAUT_MANDATORY, port, server certificate,
   * ANCL_CCERT_LIST.
   */
  public Map<String, Object> tls() {
    return asMap(get("/admin/tls"));
  }

  /** {@code GET /admin/clients/{id}/config.kon}: client configuration as {@code .kon} text. */
  public String konConfig(String clientSystemId) {
    return text("GET", "/admin/clients/" + path(clientSystemId) + "/config.kon", null);
  }

  /**
   * {@code GET /admin/vendor}: {@code vendor}, {@code boot}, {@code strict}, {@code strictBoot}.
   */
  public Map<String, Object> vendor() {
    return asMap(get("/admin/vendor"));
  }

  /**
   * {@code PUT /admin/vendor}: switch the vendor profile and/or {@code strict}; {@code null} leaves
   * the field unchanged.
   */
  public Map<String, Object> setVendor(String vendor, Boolean strict) {
    Map<String, Object> body = new LinkedHashMap<>();
    if (vendor != null) {
      body.put("vendor", vendor);
    }
    if (strict != null) {
      body.put("strict", strict);
    }
    return asMap(send("PUT", "/admin/vendor", body));
  }

  /** {@code GET /admin/log}: Systemprotokoll (TUC_KON_271), bounds optional and inclusive. */
  public List<Map<String, Object>> log(Instant from, Instant to) {
    StringBuilder query = new StringBuilder();
    if (from != null) {
      query.append("from=").append(URLEncoder.encode(from.toString(), StandardCharsets.UTF_8));
    }
    if (to != null) {
      query
          .append(query.length() == 0 ? "" : "&")
          .append("to=")
          .append(URLEncoder.encode(to.toString(), StandardCharsets.UTF_8));
    }
    return asList(get("/admin/log" + (query.length() == 0 ? "" : "?" + query)));
  }

  /**
   * {@code GET /admin/cards}: CM_CARD_LIST with handle, ICCSN, holder, KVNR, version, insertion
   * time, certificate expiry.
   */
  public List<Map<String, Object>> cards() {
    return asList(get("/admin/cards"));
  }

  /**
   * {@code GET /admin/images}: folders from {@code liana.card-images} and the images in them with
   * ICCSN.
   */
  public Map<String, Object> images() {
    return asMap(get("/admin/images"));
  }

  /**
   * {@code GET /admin/subscriptions}: subscriptions with context, target, topic, expiry and last
   * delivery.
   */
  public List<Map<String, Object>> subscriptions() {
    return asList(get("/admin/subscriptions"));
  }

  /**
   * {@code GET /admin/sessions}: {@code cardSessions} (PoPP) and {@code verifiedPins} (PinRef
   * only).
   */
  public Map<String, Object> sessions() {
    return asMap(get("/admin/sessions"));
  }

  /** {@code GET /admin/pki}: TSL state ({@code tsl}) and number of imported CAs. */
  public Map<String, Object> pki() {
    return asMap(get("/admin/pki"));
  }

  /**
   * {@code GET /admin/settings}: {@code cardSessionTimeout} (s), {@code cardSessionTimeoutBoot},
   * {@code luOnline}.
   */
  public Map<String, Object> settings() {
    return asMap(get("/admin/settings"));
  }

  /**
   * {@code PUT /admin/settings}: set CARD_SESSION_TIMEOUT (10–180 s) and/or MGM_LU_ONLINE; {@code
   * null} leaves the field unchanged.
   */
  public Map<String, Object> setSettings(Duration cardSessionTimeout, Boolean luOnline) {
    Map<String, Object> body = new LinkedHashMap<>();
    if (cardSessionTimeout != null) {
      body.put("cardSessionTimeout", cardSessionTimeout.toSeconds());
    }
    if (luOnline != null) {
      body.put("luOnline", luOnline);
    }
    return asMap(send("PUT", "/admin/settings", body));
  }

  /** {@code GET /admin/deviations}: {@code strict} and the known deviations of the peers. */
  public Map<String, Object> deviations() {
    return asMap(get("/admin/deviations"));
  }

  /**
   * {@code GET /admin/selftest/crypto/{check}}: crypto self-test ({@code brainpool-ecdsa}, {@code
   * es256-jws}, {@code brainpool-tls12}, {@code sicct-tls}); a failed test is a {@link
   * LianaControlException} with status 500.
   */
  public Map<String, Object> cryptoSelfTest(String check) {
    return asMap(get("/admin/selftest/crypto/" + path(check)));
  }

  /**
   * {@code POST /admin/ct-discovery}: TUC_KON_054 again for the eHealth card terminal {@code
   * terminal}, with {@code null} for all configured ones; the response is CTM_CT_LIST.
   */
  public List<Map<String, Object>> ctDiscovery(String terminal) {
    Map<String, Object> body = new LinkedHashMap<>();
    if (terminal != null) {
      body.put("ctId", terminal);
    }
    return asList(send("POST", "/admin/ct-discovery", body));
  }

  /** {@code GET /admin/openapi.yaml}: description of the Admin API as OpenAPI 3.0. */
  public String openApi() {
    return text("GET", "/admin/openapi.yaml", null);
  }

  /**
   * {@code POST /admin/reset}: restore the YAML state; the response is the card terminals
   * afterwards.
   */
  public List<Map<String, Object>> reset() {
    return asList(send("POST", "/admin/reset", null));
  }

  private Object get(String path) {
    return send("GET", path, null);
  }

  private Object send(String method, String path, Object body) {
    String text = text(method, path, body);
    return text.isBlank() ? Map.of() : Json.parse(text);
  }

  private String text(String method, String path, Object body) {
    HttpRequest.Builder request = request(path);
    if (body == null) {
      request.method(method, HttpRequest.BodyPublishers.noBody());
    } else {
      request
          .header("Content-Type", "application/json")
          .method(method, HttpRequest.BodyPublishers.ofString(Json.write(body)));
    }
    String what = method + " " + path;
    HttpResponse<String> response;
    try {
      response =
          client.send(request.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    } catch (IOException e) {
      throw new UncheckedIOException(what + ": " + e.getMessage(), e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IllegalStateException(what + ": unterbrochen", e);
    }
    if (response.statusCode() / 100 != 2) {
      String error = null;
      String code = null;
      try {
        Map<String, Object> json = asMap(Json.parse(response.body()));
        error = json.get("error") == null ? null : String.valueOf(json.get("error"));
        code = json.get("code") == null ? null : codeText(json.get("code"));
      } catch (RuntimeException e) {
        error = response.body().isBlank() ? null : response.body().strip();
      }
      throw new LianaControlException(what, response.statusCode(), error, code);
    }
    return response.body();
  }

  private static String codeText(Object code) {
    return code instanceof Double d && d == Math.rint(d)
        ? String.valueOf(d.longValue())
        : String.valueOf(code);
  }

  private HttpRequest.Builder request(String path) {
    return HttpRequest.newBuilder(URI.create(base + path))
        .timeout(timeout)
        .header("Accept", "application/json");
  }

  private static String slot(String terminal, int slot) {
    return "/admin/terminals/" + path(terminal) + "/slots/" + slot;
  }

  private static String path(String segment) {
    return URLEncoder.encode(segment, StandardCharsets.UTF_8).replace("+", "%20");
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> asMap(Object value) {
    if (!(value instanceof Map)) {
      throw new IllegalStateException("Admin-API: JSON-Objekt erwartet");
    }
    return (Map<String, Object>) value;
  }

  @SuppressWarnings("unchecked")
  private static List<Map<String, Object>> asList(Object value) {
    if (!(value instanceof List)) {
      throw new IllegalStateException("Admin-API: JSON-Array erwartet");
    }
    return (List<Map<String, Object>>) value;
  }
}

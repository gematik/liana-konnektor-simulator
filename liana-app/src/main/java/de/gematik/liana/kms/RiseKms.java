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
package de.gematik.liana.kms;

import de.gematik.liana.config.LianaConfig;
import de.gematik.liana.kern.management.ComfortSettings;
import de.gematik.liana.kern.management.ManagementSettings;
import io.vertx.core.Handler;
import io.vertx.core.http.Cookie;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.BodyHandler;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The subset of the Managementschnittstelle of the RISE connector (RISE API v1.21) that
 * Konnektor-QES needs under RISE: read and set MGM_LU_ONLINE (LIANA-97) and the card service
 * (LIANA-112.05). Paths and flows as in {@code KmsRise} in kms-client 1.1.0 (in
 * konnektor-service-client 1.6.2 as {@code de.gematik.kms.java} 2.1.5, identical there); the paths
 * are under {@value #PREFIX} at the root:
 *
 * <ul>
 *   <li>{@code POST /api/v1/auth/login} (JSON {@code user}, {@code password}, schema LoginRequest):
 *       200 with the user (schema User) and cookie {@code JSESSIONID}; on wrong credentials 401.
 *   <li>Every other path needs the session (otherwise 401) and the header {@code X-Requested-With:
 *       RISEHttpRequest} (RISE API „HTTP-Headers für CSRF Schutz“, otherwise 403). kms-client
 *       always sends it after the login.
 *   <li>{@code GET}/{@code PUT /api/v1/mgm/config} (schema MGMConfig): {@code MGM_LU_ONLINE}
 *       true/false settable (TAB_KON_658, via {@link ManagementSettings}), {@code MGM_LU_SAK},
 *       {@code MGM_STANDALONE_KON} and {@code MGM_REMOTE_ALLOWED} only with the default values from
 *       gemSpec_Kon (TAB_KON_658, TAB_KON_659, TAB_KON_663). PUT responds with the written values.
 *   <li>{@code GET}/{@code PUT /api/v1/card/config} (schema CardServiceConfig): CARD_TIMEOUT_CARD
 *       (1–60 s, otherwise 400) and CARD_SESSION_TIMEOUT in seconds via {@link ManagementSettings}
 *       (TAB_KON_554); Konnektor-QES {@code KUC_1602_071} „TKQES setzt Karten Timeout auf 3
 *       Sekunden“ (RISE). PUT responds with the written values.
 *   <li>{@code POST /api/v1/auth/logout}: ends the session, 204 (kms-client expects exactly 204).
 * </ul>
 *
 * Errors as ErrorMessage of the RISE API ({@code code}, {@code type}, {@code severity}, {@code
 * text}); which status RISE sends for a missing session the API does not say, LIANA responds with
 * 401. {@link KmsServer} answers everything else under {@link #PATHS} with 501 (decision-12).
 */
final class RiseKms {

  static final String PREFIX = "/api/v1";
  static final String LOGIN = PREFIX + "/auth/login";
  static final String LOGOUT = PREFIX + "/auth/logout";
  static final String MGM_CONFIG = PREFIX + "/mgm/config";
  static final String CARD_CONFIG = PREFIX + "/card/config";
  static final String SAK_CONFIG = PREFIX + "/sak/config";

  /** All paths of the RISE interface (RISE API: {@code HTTPS://<HOST>:<PORT>/api}). */
  static final String PATHS = "^/api(/.*)?$";

  static final String SESSION_COOKIE = "JSESSIONID";
  static final String CSRF_HEADER = "X-Requested-With";
  static final String CSRF_VALUE = "RISEHttpRequest";
  private static final String ONLINE = "MGM_LU_ONLINE";
  private static final String CARD_TIMEOUT = "CARD_TIMEOUT_CARD";
  private static final String SESSION_TIMEOUT = "CARD_SESSION_TIMEOUT";
  private static final String SAK_COMFORT_SIGNATURE = "SAK_COMFORT_SIGNATURE";
  private static final String COMFORT_MAX = "SAK_COMFORT_SIGNATURE_MAX";
  private static final String COMFORT_TIMER = "SAK_COMFORT_SIGNATURE_TIMER";
  private static final String SIMPLE_MODE = "SAK_SIMPLE_SIGNATURE_MODE";

  /**
   * SAK_SIMPLE_SIGNATURE_MODE: LIANA always signs single documents in SE #1 (kms-client {@code
   * SE_1}).
   */
  private static final String SE_1 = "SE_1";

  /** Non-settable fields of MGMConfig known to kms-client, with their default values. */
  private static final Map<String, Boolean> FIXED =
      Map.of("MGM_LU_SAK", true, "MGM_STANDALONE_KON", false, "MGM_REMOTE_ALLOWED", false);

  private final ManagementSettings settings;
  private final ComfortSettings comfort;
  private final String username;
  private final String password;
  private final Set<String> sessions = ConcurrentHashMap.newKeySet();
  private final SecureRandom random = new SecureRandom();
  private final Handler<RoutingContext> notImplemented;

  RiseKms(
      LianaConfig config,
      ManagementSettings settings,
      ComfortSettings comfort,
      Handler<RoutingContext> notImplemented) {
    this.settings = settings;
    this.comfort = comfort;
    this.username = config.kms().username();
    this.password = config.kms().password();
    this.notImplemented = notImplemented;
  }

  /**
   * Attaches the routes to the root {@code root}, last the 501 for everything else under {@link
   * #PATHS}.
   */
  void routes(Router root) {
    root.route().pathRegex(PATHS).handler(BodyHandler.create());
    root.post(LOGIN).handler(this::login);
    root.route().pathRegex(PATHS).handler(this::session);
    root.post(LOGOUT).handler(this::logout);
    root.get(MGM_CONFIG).handler(ctx -> json(ctx, 200, mgmConfig()));
    root.put(MGM_CONFIG).handler(this::putMgmConfig);
    root.get(CARD_CONFIG).handler(ctx -> json(ctx, 200, cardConfig()));
    root.put(CARD_CONFIG).handler(this::putCardConfig);
    root.get(SAK_CONFIG).handler(ctx -> json(ctx, 200, sakConfig()));
    root.put(SAK_CONFIG).handler(this::putSakConfig);
    root.route().pathRegex(PATHS).handler(notImplemented);
  }

  private void login(RoutingContext ctx) {
    JsonObject body = EhexKms.body(ctx);
    if (body == null || !(body.getValue("user") instanceof String user)) {
      error(ctx, 400, "Body ist kein LoginRequest (user, password)");
      return;
    }
    if (!username.equals(user) || !password.equals(body.getValue("password"))) {
      error(ctx, 401, "Benutzername oder Passwort falsch");
      return;
    }
    String session = random();
    sessions.add(session);
    // header name exactly like this: kms-client compares it (TokenUtils.fetchAndStoreCookie),
    // Vert.x writes
    // set-cookie
    ctx.response()
        .headers()
        .add(
            "Set-Cookie",
            Cookie.cookie(SESSION_COOKIE, session).setPath("/").setHttpOnly(true).encode());
    json(
        ctx,
        200,
        new JsonObject()
            .put("username", user)
            .put("contact", new JsonObject())
            .put("permissions", new JsonObject()));
  }

  /** Session and CSRF header for everything except the login. */
  private void session(RoutingContext ctx) {
    Cookie cookie = ctx.request().getCookie(SESSION_COOKIE);
    if (cookie == null || !sessions.contains(cookie.getValue())) {
      error(ctx, 401, "Keine angemeldete Sitzung");
      return;
    }
    if (!CSRF_VALUE.equals(ctx.request().getHeader(CSRF_HEADER))) {
      error(ctx, 403, "Header " + CSRF_HEADER + ": " + CSRF_VALUE + " fehlt");
      return;
    }
    ctx.next();
  }

  private void logout(RoutingContext ctx) {
    sessions.remove(ctx.request().getCookie(SESSION_COOKIE).getValue());
    ctx.response().setStatusCode(204).end();
  }

  private JsonObject mgmConfig() {
    JsonObject config = new JsonObject().put(ONLINE, settings.online());
    FIXED.forEach(config::put);
    return config;
  }

  /** kms-client sends the whole group with the changed field. */
  private void putMgmConfig(RoutingContext ctx) {
    JsonObject body = EhexKms.body(ctx);
    if (body == null) {
      error(ctx, 400, "Body ist kein JSON-Objekt (MGMConfig)");
      return;
    }
    for (Map.Entry<String, Boolean> fixed : FIXED.entrySet()) {
      if (body.containsKey(fixed.getKey())
          && !fixed.getValue().equals(body.getValue(fixed.getKey()))) {
        notImplemented.handle(ctx);
        return;
      }
    }
    Object online = body.getValue(ONLINE);
    if (online != null && !(online instanceof Boolean)) {
      error(ctx, 400, ONLINE + " '" + online + "' ist kein boolean");
      return;
    }
    if (online != null && settings.online() != (Boolean) online) {
      settings.online((Boolean) online);
    }
    json(ctx, 200, mgmConfig());
  }

  private JsonObject cardConfig() {
    return new JsonObject()
        .put(CARD_TIMEOUT, settings.cardTimeout().toSeconds())
        .put(SESSION_TIMEOUT, settings.sessionTimeout().toSeconds());
  }

  /** kms-client sends the whole group with the changed field; RISE API: CARD_TIMEOUT_CARD 1–60. */
  private void putCardConfig(RoutingContext ctx) {
    JsonObject body = EhexKms.body(ctx);
    if (body == null) {
      error(ctx, 400, "Body ist kein JSON-Objekt (CardServiceConfig)");
      return;
    }
    try {
      Duration card = KocoKms.seconds(body, CARD_TIMEOUT, settings.cardTimeout());
      Duration session = KocoKms.seconds(body, SESSION_TIMEOUT, settings.sessionTimeout());
      if (card.toSeconds() < 1 || card.toSeconds() > 60) {
        throw new IllegalArgumentException(
            CARD_TIMEOUT + " " + card.toSeconds() + " außerhalb 1–60");
      }
      settings.sessionTimeout(session);
      settings.cardTimeout(card);
      json(ctx, 200, cardConfig());
    } catch (IllegalArgumentException e) {
      error(ctx, 400, e.getMessage());
    }
  }

  private JsonObject sakConfig() {
    return new JsonObject()
        .put(SAK_COMFORT_SIGNATURE, comfort.enabled())
        .put(COMFORT_MAX, comfort.max())
        .put(COMFORT_TIMER, ComfortParameters.hours(comfort))
        .put(SIMPLE_MODE, SE_1);
  }

  /** kms-client sends the whole group with the changed field. */
  private void putSakConfig(RoutingContext ctx) {
    JsonObject body = EhexKms.body(ctx);
    if (body == null) {
      error(ctx, 400, "Body ist kein JSON-Objekt (SAK-Konfiguration)");
      return;
    }
    if (body.containsKey(SIMPLE_MODE) && !SE_1.equals(body.getValue(SIMPLE_MODE))) {
      notImplemented.handle(ctx);
      return;
    }
    Object enabled = body.getValue(SAK_COMFORT_SIGNATURE);
    if (enabled != null && !(enabled instanceof Boolean)) {
      error(ctx, 400, SAK_COMFORT_SIGNATURE + " '" + enabled + "' ist kein boolean");
      return;
    }
    try {
      ComfortParameters.store(
          comfort,
          (Boolean) enabled,
          ComfortParameters.integer(body, COMFORT_MAX),
          ComfortParameters.integer(body, COMFORT_TIMER));
      json(ctx, 200, sakConfig());
    } catch (IllegalArgumentException | IllegalStateException e) {
      error(ctx, 400, e.getMessage());
    }
  }

  private String random() {
    byte[] bytes = new byte[16];
    random.nextBytes(bytes);
    return HexFormat.of().formatHex(bytes);
  }

  /**
   * ErrorMessage of the RISE API; the HTTP status as {@code code}, the API names none for these
   * cases.
   */
  private static void error(RoutingContext ctx, int status, String text) {
    json(
        ctx,
        status,
        new JsonObject()
            .put("code", status)
            .put("type", status == 400 ? "Technical" : "Security")
            .put("severity", "Error")
            .put("text", text)
            .put("compType", "Konnektor"));
  }

  private static void json(RoutingContext ctx, int status, JsonObject body) {
    EhexKms.json(ctx, status, body);
  }
}

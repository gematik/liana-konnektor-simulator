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
import de.gematik.liana.kern.management.ClientSystemBinding;
import de.gematik.liana.kern.management.ComfortSettings;
import de.gematik.liana.kern.management.ManagementSettings;
import io.vertx.core.Handler;
import io.vertx.core.http.Cookie;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.BodyHandler;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The subset of the JSON Managementschnittstelle of the KoCoBox MED+ (KOCO spec V2.20) that
 * Konnektor-QES needs under KOCO (LIANA-96): read and set MGM_LU_ONLINE, CARD_TIMEOUT_CARD and
 * CARD_SESSION_TIMEOUT (LIANA-112.04). Paths and flows as in {@code KmsKoco} in kms-client 1.1.0
 * (in konnektor-service-client 1.6.2 as {@code de.gematik.kms.java} 2.1.5, identical there); the
 * paths are at the root, not under {@link KmsServer#MOUNT}:
 *
 * <ul>
 *   <li>{@code POST /j_security_check} (form {@code j_username}, {@code j_password}): 303 to {@code
 *       start.htm} with cookie {@code JSESSIONID}, on wrong credentials 303 to {@code login.htm}
 *       without cookie (spec chap. 1). 303 because {@code KmsKoco} in de.gematik.kms.java 2.1.5
 *       with a port requires exactly 303 (kms-client 1.1.0: 302 or 303).
 *   <li>{@code GET /administration/start.htm}: on the first call of the session 302 to itself with
 *       cookie {@code X-TOKEN}, then 200 with the token in the field {@code textarea id='x-token'}
 *       (spec chap. 1; kms-client expects first 302, then 200). Without a valid session every path
 *       under {@code /administration} responds with 302 to {@code login.htm} and an empty body, so
 *       the login of kms-client fails at the second {@code start.htm}.
 *   <li>JSON calls need the header {@code X-Token} of the session (protection against CSRF, spec
 *       chap. 1), otherwise 403 with {@code KONNEKTOR-ERROR}.
 *   <li>{@code GET /administration/json-retrieve/management}, {@code POST
 *       /administration/json-store/management} (spec 15.1/15.2): {@code MGM_LU_ONLINE}
 *       ENABLE/DISABLE settable (TAB_KON_658, via {@link ManagementSettings}), {@code
 *       MGM_REMOTE_ALLOWED}, {@code MGM_STANDALONE_KON} and {@code MGM_LU_SAK} only with the
 *       default values from gemSpec_Kon (TAB_KON_663, TAB_KON_659, TAB_KON_658). Response {@code
 *       OK} on change, otherwise {@code NOP}.
 *   <li>{@code GET /administration/json-retrieve/cardservice}, {@code POST
 *       /administration/json-store/cardservice} (card service, kms-client {@code
 *       addGroupParameter(CARD_TIMEOUT_CARD, "/cardservice")}): CARD_TIMEOUT_CARD and
 *       CARD_SESSION_TIMEOUT in seconds as number ({@code
 *       {"CARD_TIMEOUT_CARD":2,"CARD_SESSION_TIMEOUT":40}}, kms-client {@code CmCardTest}), via
 *       {@link ManagementSettings} (TAB_KON_554); Konnektor-QES {@code KUC_1602_034} „TKQES setzt
 *       Karten Timeout auf 3 Sekunden“.
 *   <li>{@code GET /administration/json-retrieve/signservice}, {@code POST
 *       /administration/json-store/signservice} (signature service, kms-client {@code
 *       addGroupParameter(SAK_COMFORT_SIGNATURE, "/signservice")}, group as in {@code
 *       SignServiceTest}): SAK_COMFORT_SIGNATURE ENABLE/DISABLE, SAK_COMFORT_SIGNATURE_MAX and
 *       _TIMER (hours) via {@link ComfortSettings} (TAB_KON_596, {@link ComfortParameters});
 *       SAK_SIMPLE_SIGNATURE_MODE only SE#1, ANCL_TLS_MANDATORY and ANCL_CAUT_MANDATORY read-only.
 *       Konnektor-QES {@code KUC_1608_*} (LIANA-112.06).
 *   <li>{@code GET /administration/logout}: ends the session, 302 to {@code login.htm}.
 * </ul>
 *
 * {@link KmsServer} answers everything else under {@link #PATHS} with 501 (decision-12).
 */
final class KocoKms {

  static final String SECURITY_CHECK = "/j_security_check";
  static final String LOGIN_PAGE = "/login.htm";
  static final String START = "/administration/start.htm";
  static final String LOGOUT = "/administration/logout";
  static final String MANAGEMENT_RETRIEVE = "/administration/json-retrieve/management";
  static final String MANAGEMENT_STORE = "/administration/json-store/management";
  static final String CARDSERVICE_RETRIEVE = "/administration/json-retrieve/cardservice";
  static final String CARDSERVICE_STORE = "/administration/json-store/cardservice";
  static final String SIGNSERVICE_RETRIEVE = "/administration/json-retrieve/signservice";
  static final String SIGNSERVICE_STORE = "/administration/json-store/signservice";

  /** All paths of the KoCoBox interface (kms-client {@code KocoConstants}). */
  static final String PATHS = "^(/j_security_check|/login\\.htm|/administration(/.*)?)$";

  static final String SESSION_COOKIE = "JSESSIONID";
  static final String TOKEN_COOKIE = "X-TOKEN";
  private static final String TOKEN_HEADER = "X-Token";
  private static final String ENABLE = "ENABLE";
  private static final String DISABLE = "DISABLE";

  /**
   * SAK_SIMPLE_SIGNATURE_MODE: LIANA always signs single documents in SE #1 (TAB_KON_596 default).
   */
  private static final String SIMPLE_SIGNATURE_MODE = "SE#1";

  /** Non-settable fields of the management group with their default values. */
  private static final Map<String, String> FIXED =
      Map.of("MGM_REMOTE_ALLOWED", DISABLE, "MGM_STANDALONE_KON", DISABLE, "MGM_LU_SAK", ENABLE);

  private final ManagementSettings settings;
  private final ComfortSettings comfort;
  private final ClientSystemBinding binding;
  private final String username;
  private final String password;

  /** {@code JSESSIONID} → {@code X-TOKEN}, empty until the first {@code start.htm}. */
  private final Map<String, String> sessions = new ConcurrentHashMap<>();

  private final SecureRandom random = new SecureRandom();
  private final Handler<RoutingContext> notImplemented;

  KocoKms(
      LianaConfig config,
      ManagementSettings settings,
      ComfortSettings comfort,
      ClientSystemBinding binding,
      Handler<RoutingContext> notImplemented) {
    this.settings = settings;
    this.comfort = comfort;
    this.binding = binding;
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
    root.post(SECURITY_CHECK).handler(this::securityCheck);
    root.get(LOGIN_PAGE)
        .handler(
            ctx ->
                html(
                    ctx,
                    """
                <form method="post" action="j_security_check"><input name="j_username"/>\
                <input name="j_password" type="password"/><input name="login" type="submit" value="Anmelden"/></form>"""));
    root.route().pathRegex("^/administration(/.*)?$").handler(this::session);
    root.get(START).handler(this::start);
    root.get(LOGOUT).handler(this::logout);
    root.route().pathRegex("^/administration(/.*)?$").handler(this::xToken);
    root.get(MANAGEMENT_RETRIEVE).handler(ctx -> json(ctx, 200, management()));
    root.post(MANAGEMENT_STORE).handler(this::storeManagement);
    root.get(CARDSERVICE_RETRIEVE).handler(ctx -> json(ctx, 200, cardservice()));
    root.post(CARDSERVICE_STORE).handler(this::storeCardservice);
    root.get(SIGNSERVICE_RETRIEVE).handler(ctx -> json(ctx, 200, signservice()));
    root.post(SIGNSERVICE_STORE).handler(this::storeSignservice);
    root.route().pathRegex(PATHS).handler(notImplemented);
  }

  private void securityCheck(RoutingContext ctx) {
    Map<String, String> form = form(ctx);
    if (!username.equals(form.get("j_username")) || !password.equals(form.get("j_password"))) {
      redirect(ctx, 303, LOGIN_PAGE + "?login_error=1");
      return;
    }
    String session = random();
    sessions.put(session, "");
    setCookie(ctx, Cookie.cookie(SESSION_COOKIE, session).setPath("/").setHttpOnly(true));
    redirect(ctx, 303, START);
  }

  /** Protected resource: without a valid session to the login page. */
  private void session(RoutingContext ctx) {
    if (session(ctx.request().getCookie(SESSION_COOKIE)) == null) {
      redirect(ctx, LOGIN_PAGE);
      return;
    }
    ctx.next();
  }

  private void start(RoutingContext ctx) {
    String session = ctx.request().getCookie(SESSION_COOKIE).getValue();
    String token = sessions.get(session);
    Cookie sent = ctx.request().getCookie(TOKEN_COOKIE);
    if (token.isEmpty() || sent == null || !token.equals(sent.getValue())) {
      String fresh = token.isEmpty() ? random() : token;
      sessions.put(session, fresh);
      setCookie(ctx, Cookie.cookie(TOKEN_COOKIE, fresh).setPath("/"));
      redirect(ctx, START);
      return;
    }
    html(ctx, "<textarea id='x-token' style='display:none'>" + token + "</textarea>");
  }

  private void logout(RoutingContext ctx) {
    sessions.remove(ctx.request().getCookie(SESSION_COOKIE).getValue());
    redirect(ctx, LOGIN_PAGE);
  }

  private void xToken(RoutingContext ctx) {
    String token = sessions.get(ctx.request().getCookie(SESSION_COOKIE).getValue());
    if (token.isEmpty() || !token.equals(ctx.request().getHeader(TOKEN_HEADER))) {
      error(ctx, 403, "X-Token fehlt oder passt nicht zur Sitzung");
      return;
    }
    ctx.next();
  }

  /** Management (Verwaltung, spec 15.1). */
  private JsonObject management() {
    JsonObject group = new JsonObject().put("MGM_LU_ONLINE", settings.online() ? ENABLE : DISABLE);
    FIXED.forEach(group::put);
    return group;
  }

  /** Change management (spec 15.2); kms-client sends the whole group with the changed field. */
  private void storeManagement(RoutingContext ctx) {
    JsonObject body = EhexKms.body(ctx);
    if (body == null) {
      error(ctx, 400, "Body ist kein JSON-Objekt (Verwaltung)");
      return;
    }
    for (Map.Entry<String, String> fixed : FIXED.entrySet()) {
      if (body.containsKey(fixed.getKey())
          && !fixed.getValue().equals(body.getValue(fixed.getKey()))) {
        notImplemented.handle(ctx);
        return;
      }
    }
    Object online = body.getValue("MGM_LU_ONLINE");
    if (online != null && !ENABLE.equals(online) && !DISABLE.equals(online)) {
      error(ctx, 400, "MGM_LU_ONLINE '" + online + "', erlaubt: ENABLE, DISABLE");
      return;
    }
    boolean changed = online != null && settings.online() != ENABLE.equals(online);
    if (changed) {
      settings.online(ENABLE.equals(online));
    }
    json(ctx, 200, new JsonObject().put(changed ? "OK" : "NOP", true));
  }

  /** Card service: times in whole seconds. */
  private JsonObject cardservice() {
    return new JsonObject()
        .put("CARD_TIMEOUT_CARD", settings.cardTimeout().toSeconds())
        .put("CARD_SESSION_TIMEOUT", settings.sessionTimeout().toSeconds());
  }

  /** Change card service; kms-client sends the whole group with the changed field. */
  private void storeCardservice(RoutingContext ctx) {
    JsonObject body = EhexKms.body(ctx);
    if (body == null) {
      error(ctx, 400, "Body ist kein JSON-Objekt (Kartendienst)");
      return;
    }
    Duration card;
    Duration session;
    try {
      card = seconds(body, "CARD_TIMEOUT_CARD", settings.cardTimeout());
      session = seconds(body, "CARD_SESSION_TIMEOUT", settings.sessionTimeout());
      if (card.isNegative() || card.isZero()) {
        throw new IllegalArgumentException(
            "CARD_TIMEOUT_CARD muss positiv sein, ist " + card.toSeconds());
      }
      boolean changed =
          !card.equals(settings.cardTimeout()) || !session.equals(settings.sessionTimeout());
      settings.sessionTimeout(session);
      settings.cardTimeout(card);
      json(ctx, 200, new JsonObject().put(changed ? "OK" : "NOP", true));
    } catch (IllegalArgumentException | ClassCastException e) {
      error(ctx, 400, e.getMessage());
    }
  }

  /** Signature service; ANCL_* from the connection of the Clientsysteme. */
  private JsonObject signservice() {
    ClientSystemBinding.State state = binding.state();
    return new JsonObject()
        .put("SAK_SIMPLE_SIGNATURE_MODE", SIMPLE_SIGNATURE_MODE)
        .put("SAK_COMFORT_SIGNATURE", comfort.enabled() ? ENABLE : DISABLE)
        .put("SAK_COMFORT_SIGNATURE_MAX", comfort.max())
        .put("SAK_COMFORT_SIGNATURE_TIMER", ComfortParameters.hours(comfort))
        .put("ANCL_TLS_MANDATORY", state.tlsMandatory())
        .put(
            "ANCL_CAUT_MANDATORY",
            state.authentication() != ClientSystemBinding.Authentication.NONE);
  }

  /** Change signature service; kms-client sends the whole group with the changed field. */
  private void storeSignservice(RoutingContext ctx) {
    JsonObject body = EhexKms.body(ctx);
    if (body == null) {
      error(ctx, 400, "Body ist kein JSON-Objekt (Signaturdienst)");
      return;
    }
    JsonObject current = signservice();
    for (String fixed :
        List.of("SAK_SIMPLE_SIGNATURE_MODE", "ANCL_TLS_MANDATORY", "ANCL_CAUT_MANDATORY")) {
      if (body.containsKey(fixed) && !current.getValue(fixed).equals(body.getValue(fixed))) {
        notImplemented.handle(ctx);
        return;
      }
    }
    Object enabled = body.getValue("SAK_COMFORT_SIGNATURE");
    if (enabled != null && !ENABLE.equals(enabled) && !DISABLE.equals(enabled)) {
      error(ctx, 400, "SAK_COMFORT_SIGNATURE '" + enabled + "', erlaubt: ENABLE, DISABLE");
      return;
    }
    try {
      boolean changed =
          ComfortParameters.store(
              comfort,
              enabled == null ? null : ENABLE.equals(enabled),
              ComfortParameters.integer(body, "SAK_COMFORT_SIGNATURE_MAX"),
              ComfortParameters.integer(body, "SAK_COMFORT_SIGNATURE_TIMER"));
      json(ctx, 200, new JsonObject().put(changed ? "OK" : "NOP", true));
    } catch (IllegalArgumentException | IllegalStateException e) {
      error(ctx, 400, e.getMessage());
    }
  }

  /** A field in seconds, as number or string; if missing, {@code current} stays. */
  static Duration seconds(JsonObject body, String field, Duration current) {
    Object value = body.getValue(field);
    if (value == null) {
      return current;
    }
    try {
      return Duration.ofSeconds(
          value instanceof Number n ? n.longValue() : Long.parseLong(value.toString().strip()));
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException(field + " '" + value + "' ist keine Zahl von Sekunden");
    }
  }

  /**
   * Login form. kms-client encodes it like a browser without specifying the charset in ISO-8859-1
   * ({@code Request.bodyForm}), which is how a servlet container reads it too; a {@code charset} in
   * the Content-Type applies.
   */
  private static Map<String, String> form(RoutingContext ctx) {
    Charset charset = StandardCharsets.ISO_8859_1;
    String contentType = ctx.request().getHeader("Content-Type");
    int at = contentType == null ? -1 : contentType.toLowerCase(Locale.ROOT).indexOf("charset=");
    if (at >= 0) {
      try {
        charset =
            Charset.forName(contentType.substring(at + 8).split(";")[0].trim().replace("\"", ""));
      } catch (IllegalArgumentException e) {
        return Map.of();
      }
    }
    Map<String, String> form = new HashMap<>();
    String body =
        ctx.body().buffer() == null
            ? ""
            : ctx.body().buffer().toString(StandardCharsets.ISO_8859_1);
    for (String pair : body.split("&")) {
      int eq = pair.indexOf('=');
      if (eq > 0) {
        form.put(
            URLDecoder.decode(pair.substring(0, eq), charset),
            URLDecoder.decode(pair.substring(eq + 1), charset));
      }
    }
    return form;
  }

  private String session(Cookie cookie) {
    return cookie == null ? null : sessions.get(cookie.getValue());
  }

  private String random() {
    byte[] bytes = new byte[16];
    random.nextBytes(bytes);
    return HexFormat.of().formatHex(bytes);
  }

  /**
   * Error according to spec chap. 1: {@code KONNEKTOR-ERROR}, {@code MESSAGEID}, {@code TRACES}
   * with {@code msg}.
   */
  private static void error(RoutingContext ctx, int status, String message) {
    json(
        ctx,
        status,
        new JsonObject()
            .put("KONNEKTOR-ERROR", true)
            .put("MESSAGEID", "")
            .put(
                "TRACES",
                new JsonArray()
                    .add(new JsonObject().put("msg", message).put("detailMsg", message))));
  }

  /**
   * Cookie with the header name {@code Set-Cookie} in exactly this spelling: kms-client compares it
   * exactly ({@code TokenUtils.fetchAndStoreCookie}), Vert.x writes {@code set-cookie} on {@code
   * addCookie}.
   */
  private static void setCookie(RoutingContext ctx, Cookie cookie) {
    ctx.response().headers().add("Set-Cookie", cookie.encode());
  }

  /** Redirect with an empty body: kms-client reads every body as JSON. */
  private static void redirect(RoutingContext ctx, String location) {
    redirect(ctx, 302, location);
  }

  private static void redirect(RoutingContext ctx, int status, String location) {
    ctx.response().setStatusCode(status).putHeader("Location", location).end();
  }

  private static void html(RoutingContext ctx, String body) {
    ctx.response()
        .setStatusCode(200)
        .putHeader("Content-Type", "text/html; charset=UTF-8")
        .end("<html><body>" + body + "</body></html>");
  }

  private static void json(RoutingContext ctx, int status, JsonObject body) {
    EhexKms.json(ctx, status, body);
  }
}

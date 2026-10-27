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
import de.gematik.liana.kern.event.SystemLog;
import de.gematik.liana.kern.management.ComfortSettings;
import de.gematik.liana.kern.management.ManagementSettings;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.BodyHandler;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * The subset of the EHEX Managementschnittstelle that the Konnektor-PoPP suite (LIANA-55) and the
 * CATS_CS scenarios of Konnektor-E2E (LIANA-65) need via kms-client. Paths and flows as in {@code
 * KmsEhex} in kms-client 1.1.0, schemas from the EHEX spec 0.9.9 ({@code Kartendienst}, {@code
 * Dauer}, {@code Leistungsumfang}); where the two differ, kms-client wins (doc-2):
 *
 * <ul>
 *   <li>{@code POST /rest/mgmt/ak/konten/login}: 204 with token in the header {@code
 *       Authorization}, 400 on wrong credentials; {@code DELETE
 *       /rest/mgmt/ak/konten/profil/logout}: 204. Every other request needs a valid token,
 *       otherwise 401.
 *   <li>{@code GET/PUT /rest/mgmt/ak/dienste/karten/einstellungen}: {@code cardSessionTimeout}
 *       (CARD_SESSION_TIMEOUT, missing in spec 0.9.9) settable, {@code cardCommunicationTimeout}
 *       (CARD_TIMEOUT_CARD) read-only.
 *   <li>{@code GET/PUT /rest/mgmt/nk/leistungsumfang/einstellungen}: {@code online} (MGM_LU_ONLINE,
 *       ENABLED/DISABLED) settable, {@code logicalSeparation} and {@code standalone} read-only.
 *   <li>{@code GET/PUT /rest/mgmt/ak/dienste/signatur/einstellungen} (kms-client {@code
 *       SignServiceTest}): {@code sakComfortSignatureActive} (SAK_COMFORT_SIGNATURE), {@code
 *       sakComfortSignatureMax} and {@code sakComfortSignatureTimer} (duration, kms-client in
 *       HOURS) via {@link ComfortSettings} (TAB_KON_596, {@link ComfortParameters}); {@code
 *       sakActive} (MGM_LU_SAK) and {@code simpleSignatureMode} (SE #1) read-only. Konnektor-QES
 *       {@code KUC_1608_*} for SECUNET (LIANA-112.06).
 *   <li>{@code GET /rest/mgmt/ak/dienste/protokoll/download/system/OP/{from}/{to}} (milliseconds,
 *       kms-client instead of the POST+ZIP of the spec): the Systemprotokoll as text, one line per
 *       entry as in the kms-client fixture {@code AkLogDownloadTest}: {@code timestamp=dd.MM.yyyy
 *       HH:mm:ss.SSS;type=op;severity=info;topic=…;Name=Wert…} (UTC). The search of the popp-bridge
 *       ({@code type=op@@severity=info@@topic=…@@Timer=PoPP}) checks every part as a substring of a
 *       line.
 *   <li>{@code POST /rest/mgmt/nk/system}: restart (LIANA-65).
 *   <li>Connection of the Clientsysteme, certificates and TLS: {@link EhexClientSystems}
 *       (LIANA-65).
 * </ul>
 *
 * {@link KmsServer} answers everything else with 501 (decision-12).
 */
final class EhexKms {

  static final String LOGIN = "/rest/mgmt/ak/konten/login";
  static final String LOGOUT = "/rest/mgmt/ak/konten/profil/logout";
  static final String CARD_SETTINGS = "/rest/mgmt/ak/dienste/karten/einstellungen";
  static final String SCOPE_SETTINGS = "/rest/mgmt/nk/leistungsumfang/einstellungen";
  static final String SIGNATURE_SETTINGS = "/rest/mgmt/ak/dienste/signatur/einstellungen";
  static final String LOG_DOWNLOAD =
      "/rest/mgmt/ak/dienste/protokoll/download/:name/:type/:from/:to";
  static final String REBOOT = "/rest/mgmt/nk/system";

  private static final DateTimeFormatter TIMESTAMP =
      DateTimeFormatter.ofPattern("dd.MM.yyyy HH:mm:ss.SSS").withZone(ZoneOffset.UTC);
  private static final String ENABLED = "ENABLED";
  private static final String DISABLED = "DISABLED";

  private final ManagementSettings settings;
  private final ComfortSettings comfort;
  private final SystemLog systemLog;
  private final String username;
  private final String password;
  private final Set<String> tokens = ConcurrentHashMap.newKeySet();
  private final SecureRandom random = new SecureRandom();
  private final EhexClientSystems clientSystems;
  private final Runnable restart;
  private final Handler<RoutingContext> notImplemented;

  EhexKms(
      LianaConfig config,
      ManagementSettings settings,
      ComfortSettings comfort,
      SystemLog systemLog,
      EhexClientSystems clientSystems,
      Runnable reboot,
      Handler<RoutingContext> notImplemented) {
    this.settings = settings;
    this.comfort = comfort;
    this.systemLog = systemLog;
    this.username = config.kms().username();
    this.password = config.kms().password();
    this.clientSystems = clientSystems;
    this.restart = reboot;
    this.notImplemented = notImplemented;
  }

  /**
   * Attaches the routes relative to {@link KmsServer#MOUNT} to {@code router}, last the 501 for
   * everything else.
   */
  void routes(Router router) {
    router.route().handler(BodyHandler.create());
    router.post(KmsServer.relative(LOGIN)).handler(this::login);
    router.route().handler(this::authorized);
    router.delete(KmsServer.relative(LOGOUT)).handler(this::logout);
    router.get(KmsServer.relative(CARD_SETTINGS)).handler(ctx -> json(ctx, 200, cardSettings()));
    router.put(KmsServer.relative(CARD_SETTINGS)).handler(this::putCardSettings);
    router.get(KmsServer.relative(SCOPE_SETTINGS)).handler(ctx -> json(ctx, 200, scopeSettings()));
    router.put(KmsServer.relative(SCOPE_SETTINGS)).handler(this::putScopeSettings);
    router
        .get(KmsServer.relative(SIGNATURE_SETTINGS))
        .handler(ctx -> json(ctx, 200, signatureSettings()));
    router.put(KmsServer.relative(SIGNATURE_SETTINGS)).handler(this::putSignatureSettings);
    router.get(KmsServer.relative(LOG_DOWNLOAD)).handler(this::downloadLog);
    router.post(KmsServer.relative(REBOOT)).handler(ctx -> reboot(ctx, restart));
    clientSystems.routes(router);
    router.route().handler(notImplemented);
  }

  /**
   * MGMT: user - login. Body {@code Anmeldedaten}; 400 „Anmeldung fehlgeschlagen, ohne Angabe von
   * Gründen“.
   */
  private void login(RoutingContext ctx) {
    JsonObject body = body(ctx);
    if (body == null
        || !username.equals(body.getString("username"))
        || !password.equals(body.getString("password"))) {
      json(
          ctx,
          400,
          new JsonObject()
              .put(
                  "generalErrors",
                  new JsonArray()
                      .add(new JsonObject().put("message", "Anmeldung fehlgeschlagen"))));
      return;
    }
    byte[] bytes = new byte[16];
    random.nextBytes(bytes);
    String token = "Bearer " + HexFormat.of().formatHex(bytes);
    tokens.add(token);
    ctx.response().putHeader("Authorization", token).setStatusCode(204).end();
  }

  /**
   * NK: system - restart. Responds 200 and then restarts: all logins expire, {@code reboot}
   * rebuilds the TLS context of the connector interface (LIANA-65). The process keeps running;
   * kms-client logs in again after its wait time (5 s).
   */
  private void reboot(RoutingContext ctx, Runnable reboot) {
    json(ctx, 200, new JsonObject());
    tokens.clear();
    ctx.vertx()
        .executeBlocking(
            () -> {
              reboot.run();
              return null;
            },
            false);
  }

  private void logout(RoutingContext ctx) {
    tokens.remove(ctx.request().getHeader("Authorization"));
    ctx.response().setStatusCode(204).end();
  }

  private void authorized(RoutingContext ctx) {
    String token = ctx.request().getHeader("Authorization");
    if (token == null || !tokens.contains(token)) {
      json(
          ctx,
          401,
          new JsonObject()
              .put(
                  "generalErrors",
                  new JsonArray().add(new JsonObject().put("message", "nicht angemeldet"))));
      return;
    }
    ctx.next();
  }

  /** Card service (Kartendienst): durations each in seconds. */
  private JsonObject cardSettings() {
    return new JsonObject()
        .put("cardCommunicationTimeout", dauer(settings.cardTimeout()))
        .put("cardSessionTimeout", dauer(settings.sessionTimeout()));
  }

  private void putCardSettings(RoutingContext ctx) {
    JsonObject body = body(ctx);
    if (body == null) {
      validation(ctx, null, "Body ist kein JSON-Objekt (Kartendienst)");
      return;
    }
    Duration timeout;
    try {
      if (body.containsKey("cardCommunicationTimeout")
          && !duration(body.getJsonObject("cardCommunicationTimeout"))
              .equals(settings.cardTimeout())) {
        ctx.next();
        return;
      }
      timeout =
          body.containsKey("cardSessionTimeout")
              ? duration(body.getJsonObject("cardSessionTimeout"))
              : settings.sessionTimeout();
      settings.sessionTimeout(timeout);
    } catch (IllegalArgumentException | ClassCastException | NullPointerException e) {
      validation(ctx, "cardSessionTimeout", e.getMessage());
      return;
    }
    json(ctx, 200, cardSettings());
  }

  /**
   * Scope of services (Leistungsumfang): MGM_LOGICAL_SEPARATION, MGM_LU_ONLINE, MGM_STANDALONE_KON
   * with the spec defaults.
   */
  private JsonObject scopeSettings() {
    return new JsonObject()
        .put("logicalSeparation", ENABLED)
        .put("online", settings.online() ? ENABLED : DISABLED)
        .put("standalone", ENABLED);
  }

  private void putScopeSettings(RoutingContext ctx) {
    JsonObject body = body(ctx);
    if (body == null) {
      validation(ctx, null, "Body ist kein JSON-Objekt (Leistungsumfang)");
      return;
    }
    if (!ENABLED.equals(body.getString("logicalSeparation", ENABLED))
        || !ENABLED.equals(body.getString("standalone", ENABLED))) {
      ctx.next();
      return;
    }
    String online = body.getString("online");
    if (online != null && !online.equals(ENABLED) && !online.equals(DISABLED)) {
      validation(ctx, "online", "erlaubt: ENABLED, DISABLED");
      return;
    }
    if (online != null) {
      settings.online(online.equals(ENABLED));
    }
    json(ctx, 200, scopeSettings());
  }

  /**
   * Signature service: scope of services SAK and simple signature mode (SE #1) fixed, comfort
   * signature settable.
   */
  private JsonObject signatureSettings() {
    return new JsonObject()
        .put("sakActive", true)
        .put("simpleSignatureMode", true)
        .put("sakComfortSignatureActive", comfort.enabled())
        .put("sakComfortSignatureMax", comfort.max())
        .put(
            "sakComfortSignatureTimer",
            new JsonObject().put("amount", ComfortParameters.hours(comfort)).put("unit", "HOURS"));
  }

  private void putSignatureSettings(RoutingContext ctx) {
    JsonObject body = body(ctx);
    if (body == null) {
      validation(ctx, null, "Body ist kein JSON-Objekt (Signaturdienst)");
      return;
    }
    if (!Boolean.TRUE.equals(body.getValue("sakActive", true))
        || !Boolean.TRUE.equals(body.getValue("simpleSignatureMode", true))) {
      ctx.next();
      return;
    }
    Object enabled = body.getValue("sakComfortSignatureActive");
    if (enabled != null && !(enabled instanceof Boolean)) {
      validation(ctx, "sakComfortSignatureActive", "kein boolean");
      return;
    }
    try {
      Integer hours = null;
      if (body.containsKey("sakComfortSignatureTimer")) {
        Duration timer = duration(body.getJsonObject("sakComfortSignatureTimer"));
        if (timer.toSeconds() % 3600 != 0 || timer.toNanosPart() != 0) {
          throw new IllegalArgumentException("nur ganze Stunden");
        }
        hours = (int) timer.toHours();
      }
      ComfortParameters.store(
          comfort,
          (Boolean) enabled,
          ComfortParameters.integer(body, "sakComfortSignatureMax"),
          hours);
    } catch (IllegalArgumentException
        | IllegalStateException
        | ClassCastException
        | NullPointerException e) {
      validation(ctx, null, e.getMessage());
      return;
    }
    json(ctx, 200, signatureSettings());
  }

  /** Log download; Systemprotokoll only, type OP (SYSTEM_OP), bounds in milliseconds inclusive. */
  private void downloadLog(RoutingContext ctx) {
    if (!ctx.pathParam("name").equals("system") || !ctx.pathParam("type").equals("OP")) {
      ctx.next();
      return;
    }
    Instant from;
    Instant to;
    try {
      from = Instant.ofEpochMilli(Long.parseLong(ctx.pathParam("from")));
      to = Instant.ofEpochMilli(Long.parseLong(ctx.pathParam("to")));
    } catch (NumberFormatException e) {
      validation(ctx, "timestamp", "Zeitgrenzen in Millisekunden erwartet");
      return;
    }
    // from = to = 0: kms-client then queries everything; otherwise the whole millisecond of to
    // counts as well
    Instant until = to.toEpochMilli() == 0 ? null : to.plusMillis(1).minusNanos(1);
    String text =
        systemLog.entries(from, until).stream()
            .map(EhexKms::line)
            .collect(Collectors.joining("\n", "", ""));
    ctx.response()
        .setStatusCode(200)
        .putHeader("Content-Type", "text/plain; charset=UTF-8")
        .putHeader("Content-Disposition", "attachment; filename=\"system_op.log\"")
        .end(text);
  }

  static String line(SystemLog.Entry entry) {
    StringBuilder line =
        new StringBuilder()
            .append("timestamp=")
            .append(TIMESTAMP.format(entry.time()))
            .append(";type=")
            .append(entry.type().value().toLowerCase(Locale.ROOT))
            .append(";severity=")
            .append(entry.severity().value().toLowerCase(Locale.ROOT))
            .append(";topic=")
            .append(entry.topic());
    entry
        .parameters()
        .forEach((name, value) -> line.append(';').append(name).append('=').append(value));
    return line.toString();
  }

  private static JsonObject dauer(Duration duration) {
    return duration.toMillis() % 1000 == 0
        ? new JsonObject().put("amount", duration.toSeconds()).put("unit", "SECONDS")
        : new JsonObject().put("amount", duration.toMillis()).put("unit", "MILLIS");
  }

  /**
   * {@code Dauer}: {@code amount} (kms-client sends it as a string) and {@code unit} MILLIS to
   * DAYS.
   */
  private static Duration duration(JsonObject dauer) {
    Objects.requireNonNull(dauer, "Dauer fehlt");
    long amount =
        Long.parseLong(
            String.valueOf(Objects.requireNonNull(dauer.getValue("amount"), "amount fehlt")));
    ChronoUnit unit =
        Map.of(
                "MILLIS",
                ChronoUnit.MILLIS,
                "SECONDS",
                ChronoUnit.SECONDS,
                "MINUTES",
                ChronoUnit.MINUTES,
                "HOURS",
                ChronoUnit.HOURS,
                "DAYS",
                ChronoUnit.DAYS)
            .get(dauer.getString("unit"));
    if (unit == null) {
      throw new IllegalArgumentException(
          "unit '" + dauer.getString("unit") + "', erlaubt: MILLIS, SECONDS, MINUTES, HOURS, DAYS");
    }
    return Duration.of(amount, unit);
  }

  static JsonObject body(RoutingContext ctx) {
    try {
      return ctx.body().asJsonObject();
    } catch (RuntimeException e) {
      return null;
    }
  }

  /** 400 with {@code Validierung} (fieldErrors or generalErrors). */
  static void validation(RoutingContext ctx, String field, String message) {
    JsonObject error = new JsonObject().put("message", message);
    JsonObject body =
        field == null
            ? new JsonObject().put("generalErrors", new JsonArray().add(error))
            : new JsonObject()
                .put("fieldErrors", new JsonObject().put(field, new JsonArray().add(error)));
    json(ctx, 400, body);
  }

  static void json(RoutingContext ctx, int status, JsonObject body) {
    ctx.response()
        .setStatusCode(status)
        .putHeader("Content-Type", "application/json")
        .end(body.encode());
  }
}

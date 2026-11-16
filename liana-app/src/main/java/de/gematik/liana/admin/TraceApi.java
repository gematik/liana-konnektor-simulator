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

import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.liana.config.LianaConfig;
import de.gematik.liana.kern.trace.Traffic;
import de.gematik.liana.trace.TigerWebUi;
import de.gematik.liana.trace.TraceChannels;
import de.gematik.liana.trace.TrafficPush;
import io.quarkus.runtime.annotations.RegisterForReflection;
import io.vertx.core.json.Json;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.OptionalInt;
import java.util.function.IntSupplier;
import java.util.function.Supplier;

/**
 * Page Verkehr of the Control Center (LIANA-195.03): {@code GET /admin/trace} shows which channel
 * reports which parts of its messages where (from the configuration of this start), {@code PUT
 * /admin/trace/channels/{id}} switches a channel on or off (LIANA-195.05), {@code GET
 * /admin/trace/messages} hands the message list of the Tiger proxy at {@code liana.trace.push-url}
 * through, so that the browser needs neither CORS nor access to the proxy. Without {@code push-url}
 * the messages respond with 404.
 */
final class TraceApi {

  static final String PATH = "/admin/trace";

  /**
   * Tiger evaluates a filter over every message: with a few thousand messages that takes several
   * seconds (3646 messages, 8 s in the Testhub).
   */
  private static final Duration TIMEOUT = Duration.ofSeconds(30);

  private final LianaConfig config;
  private final Traffic traffic;
  private final TraceChannels channels;
  private final Runnable changed;
  private final ObjectMapper json;
  private final TigerWebUi tiger;
  private final String name;
  private final IntSupplier konnektorPort;
  private final IntSupplier adminPort;
  private final Supplier<OptionalInt> kmsPort;

  TraceApi(
      LianaConfig config,
      Traffic traffic,
      TraceChannels channels,
      Runnable changed,
      ObjectMapper json,
      IntSupplier konnektorPort,
      IntSupplier adminPort,
      Supplier<OptionalInt> kmsPort) {
    this.config = config;
    this.traffic = traffic;
    this.channels = channels;
    this.changed = changed;
    this.json = json;
    this.konnektorPort = konnektorPort;
    this.adminPort = adminPort;
    this.kmsPort = kmsPort;
    this.name = de.gematik.liana.wiring.TraceWiring.name(config);
    this.tiger = config.trace().pushUrl().map(url -> new TigerWebUi(url, TIMEOUT)).orElse(null);
  }

  /**
   * Where the traffic goes: {@code name} the symbolic name of this connector in the trace
   * (LIANA-195.04), {@code push} the Traffic-Push with its counters, {@code webUi} the link for the
   * browser, {@code routes} one entry per channel.
   */
  @RegisterForReflection
  record Overview(String name, Push push, String webUi, List<Route> routes) {}

  /**
   * {@code state}: {@code off} without {@code push-url}, {@code ok}, or {@code failing} since the
   * last failed push; counters since the start.
   */
  @RegisterForReflection
  record Push(
      String url,
      String target,
      String timeout,
      String state,
      long delivered,
      long failed,
      long dropped,
      String lastError) {}

  /**
   * One channel: {@code id} for {@code PUT /admin/trace/channels/{id}}, {@code null} if it cannot
   * be switched (never reported); {@code endpoint} where it runs on the wire, {@code parts} which
   * parts of its messages LIANA reports, {@code trace} sender and receiver as they appear in the
   * Tiger log, {@code on} whether the channel is switched on, {@code pushed} whether its messages
   * go to the proxy (switched on and a proxy linked), {@code note} configuration that changes the
   * route.
   */
  @RegisterForReflection
  record Route(
      String id,
      String channel,
      String endpoint,
      String parts,
      String trace,
      boolean on,
      boolean pushed,
      String note) {}

  /** Body of {@code PUT /admin/trace/channels/{id}}. */
  @RegisterForReflection
  record Switch(Boolean on) {}

  /**
   * Unordered blocking handlers: Vert.x runs the ordered ones of a router one after the other, so a
   * filter Tiger evaluates for seconds would hold up the overview, the switches and every other
   * blocking route of the Admin API behind it.
   */
  void routes(Router router) {
    router.get(PATH).blockingHandler(ctx -> respond(ctx, 200, overview()), false);
    router.put(PATH + "/channels/:id").handler(this::switchChannel);
    router
        .get(PATH + "/messages")
        .blockingHandler(
            ctx -> {
              try {
                String body =
                    tiger()
                        .messages(
                            ctx.request().getParam("filter"),
                            instant(ctx, "from"),
                            instant(ctx, "to"));
                ctx.response().putHeader("Content-Type", "application/json").end(body);
              } catch (IOException e) {
                failed(ctx, e);
              }
            },
            false);
  }

  /** {@code {"on": false}} switches the channel off, {@code true} on again; 404 if unknown. */
  private void switchChannel(RoutingContext ctx) {
    String id = ctx.pathParam("id");
    Switch body;
    try {
      body = json.readValue(ctx.body().asString(), Switch.class);
    } catch (IOException | RuntimeException e) {
      body = null;
    }
    if (body == null || body.on() == null) {
      respond(ctx, 400, Map.of("error", "Body {\"on\": true|false} erwartet"));
      return;
    }
    boolean known = routes(true).stream().anyMatch(r -> id.equals(r.id()));
    if (!known) {
      respond(ctx, 404, Map.of("error", "kein schaltbarer Kanal " + id));
      return;
    }
    channels.set(id, body.on());
    changed.run();
    respond(ctx, 200, overview());
  }

  Overview overview() {
    LianaConfig.Trace trace = config.trace();
    boolean on = traffic.active();
    Push push =
        new Push(
            trace.pushUrl().map(URI::toString).orElse(null),
            traffic instanceof TrafficPush p ? p.target().toString() : null,
            trace.pushTimeout().toString(),
            "off",
            0,
            0,
            0,
            null);
    if (traffic instanceof TrafficPush p) {
      TrafficPush.Stats stats = p.stats();
      push =
          new Push(
              push.url(),
              push.target(),
              push.timeout(),
              stats.failing() ? "failing" : "ok",
              stats.delivered(),
              stats.failed(),
              stats.dropped(),
              stats.lastError());
    }
    String webUi =
        trace.webuiUrl().map(URI::toString).orElse(tiger == null ? null : tiger.webui().toString());
    return new Overview(name, push, webUi, routes(on));
  }

  /** The channels of this start, in the order of the connector interface outwards. */
  private List<Route> routes(boolean on) {
    List<Route> routes = new ArrayList<>();
    String http = "HTTP-Anfrage und -Antwort als Klartext nach TLS, Body dekodiert";
    routes.add(
        route(
            on,
            TraceChannels.KONNEKTOR,
            "Konnektor-Schnittstelle (SOAP /ws/*, /connector.sds, RISE-KMS /api/*)",
            "HTTP :" + konnektorPort.getAsInt() + ", HTTPS :" + config.tls().port(),
            http,
            server(konnektorPort.getAsInt(), config.tls().port()),
            null));
    routes.add(
        route(
            on,
            TraceChannels.MANAGEMENT,
            "Management-Port: KMS, CATS",
            "HTTP und HTTPS :" + adminPort.getAsInt(),
            http,
            server(adminPort.getAsInt()),
            "ohne /admin/* und Control Center"));
    routes.add(
        new Route(
            null,
            "Admin-API und Control Center",
            ":" + adminPort.getAsInt() + " /admin/*, /",
            "nichts",
            null,
            false,
            false,
            "nie gemeldet: sie zeigen den Verkehr selbst"));
    kmsPort
        .get()
        .ifPresent(
            port ->
                routes.add(
                    route(
                        on,
                        TraceChannels.KMS_PORT,
                        "KMS, Kompatibilitäts-Port",
                        "HTTPS :" + port + " (liana.kms.port)",
                        http,
                        server(port),
                        null)));
    config.cats().terminals().orElse(List.of()).stream()
        .filter(cats -> cats.port().isPresent())
        .forEach(
            cats ->
                routes.add(
                    route(
                        on,
                        TraceChannels.cats(cats.terminal()),
                        "CATS " + cats.terminal(),
                        "HTTP :" + cats.port().get() + " (liana.cats.terminals[].port)",
                        http,
                        server(cats.port().get()),
                        null)));
    config
        .robot()
        .port()
        .ifPresent(
            port ->
                routes.add(
                    route(
                        on,
                        TraceChannels.ROBOT,
                        "Robot-Schnittstelle",
                        "HTTP :" + port + " (liana.robot.port)",
                        http,
                        server(port),
                        null)));
    routes.add(
        route(
            on,
            TraceChannels.CETP,
            "CETP-Ereignisse an Clientsysteme",
            config
                .events()
                .redirect()
                .map(target -> "TCP/TLS an " + target + " (liana.events.redirect)")
                .orElse("TCP/TLS an EventTo der Anmeldung"),
            "CETP-Rahmen mit Event-XML, LIANA → Ereignissenke; keine Antwort",
            name + "/<IP>:<Port> → Host aus EventTo/<IP>:<Port>",
            config
                .events()
                .redirect()
                .map(target -> "auf der Leitung an " + target + ", im Tiger-Log weiter das EventTo")
                .orElse(null)));
    if (config.vsdm().online().sources().orElse(List.of()).contains("ufs")) {
      config.vsdm().online().ufs().endpoints().orElse(List.of()).stream()
          .forEach(
              ufs ->
                  routes.add(
                      route(
                          on,
                          TraceChannels.UFS,
                          "VSDM-Onlineprüfung: UFS",
                          ufs.url().toString(),
                          "GetUpdateFlags: HTTP-Anfrage und -Antwort, Klartext nach TLS",
                          name
                              + "/<IP>:<Port> → "
                              + ufs.url().getHost()
                              + "/<IP>:"
                              + port(ufs.url())
                              + ", zurück",
                          null)));
    }
    if (config.pki().tslOnline().mode() != de.gematik.liana.crypto.OnlineTsl.Mode.OFF) {
      URI url = config.pki().tslOnline().url();
      routes.add(
          route(
              on,
              TraceChannels.TSL,
              "Online-TSL",
              url.toString(),
              "GET und Antwort, als HTTP/1.1 nachgebaut, Body dekodiert",
              name + " → " + url.getHost() + ":" + port(url) + ", zurück",
              "liana.pki.tsl-online.mode " + config.pki().tslOnline().mode()));
    }
    boolean sm = config.card().terminateSecureMessaging();
    new java.util.TreeMap<>(config.infrastructure().terminals())
        .forEach(
            (id, kt) -> {
              if (kt.type() == LianaConfig.Type.FAKE) {
                routes.add(
                    route(
                        on,
                        TraceChannels.terminal(id),
                        "Fake-KT " + id,
                        "im Prozess (kartos pipe)",
                        "Kommando- und Antwort-APDU, je in einem SICCT-Umschlag (10 Byte)"
                            + (sm
                                ? "; mit terminiertem Trusted Channel zusätzlich der Klartext"
                                : ""),
                        name
                            + " → "
                            + name
                            + "-"
                            + id
                            + ":<Slot>, zurück"
                            + (sm
                                ? "; Klartext "
                                    + name
                                    + "-sm-klartext → "
                                    + name
                                    + "-"
                                    + id
                                    + "-sm-klartext:<Slot>"
                                : ""),
                        sm ? "liana.card.terminate-secure-messaging" : null));
              } else {
                routes.add(
                    route(
                        on,
                        TraceChannels.terminal(id),
                        "eHealth-KT " + id,
                        kt.host().map(host -> host + ", SICCT über TLS").orElse("SICCT über TLS"),
                        "SICCT-Umschläge wie auf der Leitung, Klartext nach TLS",
                        name + "/<IP>:<Port> → <CT.HOSTNAME oder " + id + ">/<IP>:<Port>, zurück",
                        null));
                kt.control()
                    .ifPresent(
                        control ->
                            routes.add(
                                new Route(
                                    null,
                                    "KT-Steuerschnittstelle " + id,
                                    control.toString(),
                                    "nichts",
                                    null,
                                    false,
                                    false,
                                    "Testwerkzeug (Robot), nicht Teil der Strecke")));
              }
            });
    return routes;
  }

  /** A channel that can be switched; its messages go to the proxy if it is on and {@code push}. */
  private Route route(
      boolean push,
      String id,
      String channel,
      String endpoint,
      String parts,
      String trace,
      String note) {
    boolean on = channels.on(id);
    return new Route(id, channel, endpoint, parts, trace, on, push && on, note);
  }

  private TigerWebUi tiger() throws TigerWebUi.NotFound {
    if (tiger == null) {
      throw new TigerWebUi.NotFound(
          "kein Tiger-Proxy verknüpft: liana.trace.push-url ist nicht gesetzt");
    }
    return tiger;
  }

  private static void failed(RoutingContext ctx, IOException e) {
    int status =
        switch (e) {
          case TigerWebUi.NotFound n -> 404;
          case TigerWebUi.Rejected r -> 400;
          default -> 502;
        };
    ctx.response()
        .setStatusCode(status)
        .putHeader("Content-Type", "application/json")
        .end(Json.encode(Map.of("error", e.getMessage())));
  }

  private void respond(RoutingContext ctx, int status, Object body) {
    try {
      ctx.response()
          .setStatusCode(status)
          .putHeader("Content-Type", "application/json")
          .end(json.writeValueAsString(body));
    } catch (IOException e) {
      ctx.fail(e);
    }
  }

  private static Instant instant(RoutingContext ctx, String name) throws IOException {
    String value = ctx.request().getParam(name);
    if (value == null || value.isBlank()) {
      return null;
    }
    try {
      return Instant.parse(value);
    } catch (DateTimeParseException e) {
      throw new TigerWebUi.Rejected(name + ": ISO-8601 erwartet, nicht " + value);
    }
  }

  /** Sender and receiver of a request to LIANA, as {@code HttpTrace} names them. */
  private String server(int... ports) {
    return "Client-IP:Port → "
        + String.join(
            " bzw. ",
            java.util.Arrays.stream(ports).mapToObj(port -> name + "/<IP>:" + port).toList())
        + ", Antwort zurück";
  }

  private static int port(URI url) {
    if (url.getPort() >= 0) {
      return url.getPort();
    }
    return "https".equals(url.getScheme()) ? 443 : 80;
  }
}

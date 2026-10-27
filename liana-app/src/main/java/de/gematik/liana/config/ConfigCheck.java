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

import de.gematik.liana.adapter.fake.CardImages;
import de.gematik.liana.kern.vendor.Vendor;
import de.gematik.liana.sm.Cvc;
import de.gematik.liana.sm.TerminalIdentity;
import io.quarkus.runtime.StartupEvent;
import jakarta.annotation.Priority;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Singleton;
import jakarta.interceptor.Interceptor;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import org.eclipse.microprofile.config.Config;

/**
 * Checks the cross-references of the boot configuration at startup that the mapping alone does not
 * cover: known vendor profile, CARD_SESSION_TIMEOUT within the allowed range, per CT in the
 * infrastructure object the fields of its type (fake: slot-count; sicct: host, shared-secret), CTM
 * parameters within the allowed range, workplaces name only configured CTs, every inserted image
 * sits in an existing slot and is unique among the card images, every gSMC-KT is unique among the
 * card images and present and complete per CT with {@code card.terminate-secure-messaging}
 * (LIANA-99), every CATS terminal points to a configured CT, once and with a URL-safe ID, an
 * additional port only once (LIANA-147), no retired keys ({@link RetiredKeys}). Fields of a fake CT
 * on an eHealth CT (from an overlaid configuration) are not an error; LIANA ignores them. Every
 * error aborts the startup.
 */
@Singleton
public class ConfigCheck {

  /** Sources of the Onlineprüfung (UfsSource.CONFIG_NAME, FixedSource.CONFIG_NAME). */
  private static final List<String> VSDM_SOURCES = List.of("ufs", "fixed");

  private final LianaConfig config;
  private final Config raw;

  ConfigCheck(LianaConfig config, Config raw) {
    this.config = config;
    this.raw = raw;
  }

  /** Runs before all other startup observers. */
  void onStart(@Observes @Priority(Interceptor.Priority.PLATFORM_BEFORE) StartupEvent event) {
    List<String> names = new ArrayList<>();
    raw.getConfigSources().forEach(source -> names.addAll(source.getPropertyNames()));
    List<String> errors = errors(config, names);
    if (!errors.isEmpty()) {
      throw new IllegalStateException(
          "Ungültige Konfiguration liana.*:\n  " + String.join("\n  ", errors));
    }
  }

  /** All errors of the configuration, empty if it is valid. */
  static List<String> errors(LianaConfig config) {
    return errors(config, List.of());
  }

  /**
   * Like {@link #errors(LianaConfig)}, plus per retired key under {@code names} its successor
   * (LIANA-98).
   */
  static List<String> errors(LianaConfig config, Iterable<String> names) {
    List<String> errors = new ArrayList<>(RetiredKeys.errors(names));
    try {
      Vendor.of(config.vendor());
    } catch (IllegalArgumentException e) {
      errors.add("vendor: " + e.getMessage() + " (decision-10)");
    }
    Duration sessionTimeout = config.card().sessionTimeout();
    if (sessionTimeout.compareTo(Duration.ofSeconds(10)) < 0
        || sessionTimeout.compareTo(Duration.ofSeconds(180)) > 0) {
      errors.add(
          "card.session-timeout "
              + sessionTimeout.toSeconds()
              + " s außerhalb 10..180 s (TAB_KON_554)");
    }
    Duration cardTimeout = config.card().cardTimeout();
    if (cardTimeout.isNegative() || cardTimeout.isZero()) {
      errors.add(
          "card.card-timeout "
              + cardTimeout
              + " muss positiv sein (CARD_TIMEOUT_CARD, TAB_KON_554)");
    }
    Map<String, LianaConfig.Terminal> terminalConfig =
        new TreeMap<>(config.infrastructure().terminals());
    LianaConfig.Mode mode = LianaConfig.Mode.of(terminalConfig);
    Set<String> terminals = new java.util.TreeSet<>(terminalConfig.keySet());
    terminalConfig.forEach(
        (id, kt) -> {
          String where = "infrastructure.terminals." + id;
          if (kt.type() == LianaConfig.Type.FAKE) {
            if (kt.slotCount().isEmpty() || kt.slotCount().get() < 1) {
              errors.add(where + ": slot-count fehlt oder ist kleiner als 1 (fake)");
            }
            if (kt.host().isPresent() || kt.sharedSecret().isPresent()) {
              errors.add(where + ": host und shared-secret gibt es nur bei type: sicct");
            }
          } else {
            if (kt.host().filter(host -> !host.isBlank()).isEmpty()) {
              errors.add(where + ": host fehlt (sicct)");
            }
            kt.sharedSecret()
                .filter(secret -> !secret.matches("[0-9A-Fa-f]{32}"))
                .ifPresent(
                    secret ->
                        errors.add(where + ": shared-secret ist nicht 16 Byte hex (DO_KT_0003)"));
          }
        });
    LianaConfig.Ctm ctm = config.ctm();
    Duration handshake = ctm.tlsHandshakeTimeout();
    if (handshake.compareTo(Duration.ofSeconds(1)) < 0
        || handshake.compareTo(Duration.ofSeconds(60)) > 0) {
      errors.add(
          "ctm.tls-handshake-timeout "
              + handshake.toSeconds()
              + " s außerhalb 1..60 s (CTM_TLS_HS_TIMEOUT, "
              + "TAB_KON_527)");
    }
    Duration keepAlive = ctm.keepAliveInterval();
    if (keepAlive.compareTo(Duration.ofSeconds(1)) < 0
        || keepAlive.compareTo(Duration.ofSeconds(10)) > 0) {
      errors.add(
          "ctm.keep-alive-interval "
              + keepAlive.toMillis()
              + " ms außerhalb 1..10 s (CTM_KEEP_ALIVE_INTERVAL, "
              + "TAB_KON_527)");
    }
    if (ctm.keepAliveTryCount() < 3 || ctm.keepAliveTryCount() > 10) {
      errors.add(
          "ctm.keep-alive-try-count "
              + ctm.keepAliveTryCount()
              + " außerhalb 3..10 "
              + "(CTM_KEEP_ALIVE_TRY_COUNT, TAB_KON_527)");
    }
    if (ctm.serviceDiscoveryCycle().isNegative()) {
      errors.add(
          "ctm.service-discovery-cycle darf nicht negativ sein (CTM_SERVICE_DISCOVERY_CYCLE, 0 = aus)");
    }
    if (!ctm.serviceDiscoveryTimeout().isPositive()) {
      errors.add("ctm.service-discovery-timeout muss positiv sein (CTM_SERVICE_DISCOVERY_TIMEOUT)");
    }
    for (int port : new int[] {ctm.serviceDiscoveryPort(), ctm.serviceAnnouncementPort()}) {
      if (port < 0 || port > 65535) {
        errors.add("ctm: UDP-Port " + port + " außerhalb 0..65535");
      }
    }
    for (LianaConfig.Workplace workplace : config.infomodel().workplaces()) {
      for (String terminal : workplace.terminals()) {
        if (!terminals.contains(terminal)) {
          errors.add(
              "Arbeitsplatz "
                  + workplace.id()
                  + ": unbekanntes KT '"
                  + terminal
                  + "' (infrastructure.terminals: "
                  + terminals
                  + ")");
        }
      }
    }
    Set<String> iccsns = new java.util.HashSet<>();
    for (LianaConfig.SmbVerwaltet smb : config.infomodel().smbVerwaltet().orElse(List.of())) {
      if (!iccsns.add(smb.iccsn())) {
        errors.add("infomodel.smb-verwaltet: ICCSN " + smb.iccsn() + " mehrfach");
      }
      for (String mandant : smb.mandants()) {
        if (!config.infomodel().mandants().contains(mandant)) {
          errors.add(
              "infomodel.smb-verwaltet " + smb.iccsn() + ": unbekannter Mandant '" + mandant + "'");
        }
      }
    }
    Set<Integer> catsPorts = new java.util.HashSet<>();
    Set<String> catsTerminals = new java.util.HashSet<>();
    for (LianaConfig.CatsTerminal cats : config.cats().terminals().orElse(List.of())) {
      if (!terminals.contains(cats.terminal())) {
        errors.add(
            "cats: unbekanntes KT '"
                + cats.terminal()
                + "' (infrastructure.terminals: "
                + terminals
                + ")");
      }
      // path segment in /cats/<terminal> (LIANA-147): only unreserved characters per RFC 3986, 2.3
      if (!cats.terminal().matches("[A-Za-z0-9._~-]+")) {
        errors.add(
            "cats: KT '"
                + cats.terminal()
                + "' nicht als Pfad /cats/<KT> nutzbar (erlaubt: A-Z a-z 0-9 . _ ~ -)");
      }
      if (!catsTerminals.add(cats.terminal())) {
        errors.add("cats: KT '" + cats.terminal() + "' mehrfach (je KT ein CATS-Terminal)");
      }
      cats.port()
          .ifPresent(
              port -> {
                if (port < 0 || port > 65535) {
                  errors.add("cats " + cats.terminal() + ": Port " + port + " außerhalb 0..65535");
                } else if (port != 0 && !catsPorts.add(port)) {
                  errors.add(
                      "cats: Port " + port + " mehrfach vergeben (je CATS-Terminal ein Port)");
                }
              });
    }
    if (config.events().maxTry() < 1) {
      errors.add("events.max-try muss mindestens 1 sein (EVT_MAX_TRY)");
    }
    if (!config.events().connectTimeout().isPositive()) {
      errors.add("events.connect-timeout muss positiv sein");
    }
    vsdm(config.vsdm(), errors);
    CardImages images = new CardImages(config.cardImages());
    terminalConfig.forEach(
        (id, kt) -> {
          if (kt.type() != LianaConfig.Type.FAKE) {
            return;
          }
          int slotCount = kt.slotCount().orElse(0);
          new TreeMap<>(kt.slots())
              .forEach(
                  (slot, image) -> {
                    if (slot < 1 || slot > slotCount) {
                      errors.add(id + "/" + slot + ": Slot außerhalb 1.." + slotCount);
                    } else {
                      try {
                        images.resolve(image);
                      } catch (IllegalArgumentException e) {
                        errors.add(id + "/" + slot + ": " + e.getMessage());
                      }
                    }
                  });
        });
    if (config.robot().port().isPresent()) {
      robot(config.robot(), terminalConfig, images, errors);
    }
    boolean terminate = config.card().terminateSecureMessaging();
    List<Cvc> links = TerminalIdentity.links(config.pki().tsl());
    terminalConfig.forEach(
        (id, kt) -> {
          String where = "infrastructure.terminals." + id + ".gsmc-kt";
          if (kt.gsmcKt().isEmpty()) {
            if (terminate) {
              errors.add(
                  where
                      + " fehlt (card.terminate-secure-messaging: Identität als Terminal, LIANA-28)");
            }
            return;
          }
          try {
            // Hop B (LIANA-28) and remote PIN procedure in SE #2 (LIANA-112.13)
            TerminalIdentity.of(images.resolve(kt.gsmcKt().get()), links);
          } catch (IllegalArgumentException e) {
            errors.add(where + ": " + e.getMessage());
          }
        });
    config
        .infrastructure()
        .konnektor()
        .gsmcK()
        .image()
        .ifPresent(
            image -> {
              try {
                // Trusted channel gSMC-K↔HBA (TUC_KON_154/158, LIANA-112.13)
                TerminalIdentity.of(TerminalIdentity.Kind.GSMC_K, images.resolve(image), links);
              } catch (IllegalArgumentException e) {
                errors.add("infrastructure.konnektor.gsmc-k.image: " + e.getMessage());
              }
            });
    if (mode == LianaConfig.Mode.MIXED || mode == LianaConfig.Mode.SICCT) {
      Path sakAut = config.infrastructure().konnektor().gsmcK().sakAut();
      if (!java.nio.file.Files.isRegularFile(sakAut)) {
        errors.add(
            "infrastructure.konnektor.gsmc-k.sak-aut "
                + sakAut
                + " nicht gefunden (ID.SAK.AUT für die "
                + "eHealth-KTs)");
      }
    }
    return errors;
  }

  /**
   * the Fachmodul VSDM (LIANA-141): times positive, sources known and unique, ufs only with
   * endpoints.
   */
  private static void vsdm(LianaConfig.Vsdm vsdm, List<String> errors) {
    if (!vsdm.timeout().isPositive()) {
      errors.add("vsdm.timeout muss positiv sein (TIMEOUT_VSDM)");
    }
    if (!vsdm.maxTime().isPositive()) {
      errors.add("vsdm.max-time muss positiv sein (MAXTIME_VSDM)");
    }
    List<String> sources = vsdm.online().sources().orElse(List.of());
    for (String source : sources) {
      if (!VSDM_SOURCES.contains(source)) {
        errors.add(
            "vsdm.online.sources: unbekannte Quelle '"
                + source
                + "' (erlaubt: "
                + VSDM_SOURCES
                + ")");
      }
    }
    if (sources.stream().distinct().count() < sources.size()) {
      errors.add("vsdm.online.sources: Quelle mehrfach " + sources);
    }
    List<LianaConfig.UfsEndpoint> endpoints = vsdm.online().ufs().endpoints().orElse(List.of());
    if (sources.contains("ufs") && endpoints.isEmpty()) {
      errors.add("vsdm.online.sources enthält ufs, aber vsdm.online.ufs.endpoints ist leer");
    }
    for (LianaConfig.UfsEndpoint endpoint : endpoints) {
      String scheme = endpoint.url().getScheme();
      if (!"http".equals(scheme) && !"https".equals(scheme) || endpoint.url().getHost() == null) {
        errors.add(
            "vsdm.online.ufs.endpoints: " + endpoint.url() + " ist keine http- oder https-URL");
      }
      endpoint
          .providerId()
          .filter(id -> !id.matches("[0-9]{9}"))
          .ifPresent(
              id ->
                  errors.add(
                      "vsdm.online.ufs.endpoints "
                          + endpoint.url()
                          + ": provider-id '"
                          + id
                          + "' hat nicht neun Ziffern"));
    }
    if (!vsdm.online().ufs().connectTimeout().isPositive()) {
      errors.add("vsdm.online.ufs.connect-timeout muss positiv sein");
    }
    if (vsdm.online().ufs().retryAfter().isNegative()) {
      errors.add("vsdm.online.ufs.retry-after darf nicht negativ sein");
    }
  }

  /**
   * Robot interface (LIANA-106): fake CTs with slot 1 and 2 or eHealth CTs with the control
   * interface of kartos terminal (LIANA-112.15), compartments SC1…SCn with images that can be
   * found.
   */
  private static void robot(
      LianaConfig.Robot robot,
      Map<String, LianaConfig.Terminal> terminalConfig,
      CardImages images,
      List<String> errors) {
    int port = robot.port().orElseThrow();
    if (port < 0 || port > 65535) {
      errors.add("robot: Port " + port + " außerhalb 0..65535");
    }
    if (robot.terminals().isEmpty()) {
      errors.add("robot.terminals: mindestens ein KT (Robot-Terminal 1)");
    }
    for (String id : robot.terminals()) {
      LianaConfig.Terminal kt = terminalConfig.get(id);
      if (kt == null) {
        errors.add(
            "robot.terminals: '"
                + id
                + "' ist kein KT (infrastructure.terminals: "
                + terminalConfig.keySet()
                + ")");
      } else if (kt.type() == LianaConfig.Type.SICCT) {
        if (kt.control().isEmpty()) {
          errors.add(
              "robot.terminals: "
                  + id
                  + " ist ein eHealth-KT ohne infrastructure.terminals."
                  + id
                  + ".control (Steuerschnittstelle von kartos terminal)");
        }
      } else if (kt.slotCount().orElse(0) < 2) {
        errors.add("robot.terminals: " + id + " braucht Slot 1 (eGK) und 2 (Berechtigtenkarte)");
      }
    }
    Map<String, Map<String, String>> sides =
        Map.of("egk", robot.egk(), "berechtigt", robot.berechtigt());
    new TreeMap<>(sides)
        .forEach(
            (side, cards) ->
                new TreeMap<>(cards)
                    .forEach(
                        (fach, image) -> {
                          if (!fach.matches("SC[1-9]")) {
                            errors.add("robot." + side + ": Fach '" + fach + "' ist nicht SC1…SC9");
                          }
                          try {
                            images.resolve(image);
                          } catch (IllegalArgumentException e) {
                            errors.add("robot." + side + "." + fach + ": " + e.getMessage());
                          }
                        }));
  }
}

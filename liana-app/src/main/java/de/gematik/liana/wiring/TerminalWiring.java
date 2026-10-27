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
package de.gematik.liana.wiring;

import de.gematik.liana.adapter.fake.CardEngine;
import de.gematik.liana.adapter.fake.CardImages;
import de.gematik.liana.adapter.fake.FakeTerminals;
import de.gematik.liana.adapter.fake.KartosEngine;
import de.gematik.liana.adapter.fake.KartosLocator;
import de.gematik.liana.adapter.fake.TrafficPush;
import de.gematik.liana.adapter.fake.TrafficPushingTerminal;
import de.gematik.liana.adapter.sicct.DiscoveryChannel;
import de.gematik.liana.adapter.sicct.SicctTerminals;
import de.gematik.liana.config.LianaConfig;
import de.gematik.liana.crypto.EgkCertificateCheck;
import de.gematik.liana.crypto.KtTls;
import de.gematik.liana.crypto.ScenarioSignerCheck;
import de.gematik.liana.crypto.SignedScenarios;
import de.gematik.liana.crypto.SmktCertificateCheck;
import de.gematik.liana.crypto.TlsIdentity;
import de.gematik.liana.crypto.TrustSpace;
import de.gematik.liana.kern.access.Infomodel;
import de.gematik.liana.kern.card.AuthState;
import de.gematik.liana.kern.card.CardAccess;
import de.gematik.liana.kern.card.CardCertificates;
import de.gematik.liana.kern.card.CardEvent;
import de.gematik.liana.kern.card.CardList;
import de.gematik.liana.kern.card.CardLocks;
import de.gematik.liana.kern.card.CardObject;
import de.gematik.liana.kern.card.CardSessions;
import de.gematik.liana.kern.card.CertificateExpiration;
import de.gematik.liana.kern.card.EgkFiles;
import de.gematik.liana.kern.card.ExternalAuthentication;
import de.gematik.liana.kern.card.GsmcK;
import de.gematik.liana.kern.card.PinVerification;
import de.gematik.liana.kern.card.ScenarioDecoder;
import de.gematik.liana.kern.cardterminal.CardTerminalService;
import de.gematik.liana.kern.event.Event;
import de.gematik.liana.kern.event.GetCardTerminals;
import de.gematik.liana.kern.event.GetCards;
import de.gematik.liana.kern.event.GetResourceInformation;
import de.gematik.liana.kern.event.Subscriptions;
import de.gematik.liana.kern.event.SystemLog;
import de.gematik.liana.kern.management.ManagementSettings;
import de.gematik.liana.kern.management.OperatingState;
import de.gematik.liana.kern.terminal.CardTerminal;
import de.gematik.liana.kern.terminal.TerminalRegistry;
import de.gematik.liana.kern.terminal.TimeLimitedTerminal;
import de.gematik.liana.kern.vendor.PeerDeviations;
import de.gematik.liana.robot.KartosRobots;
import de.gematik.liana.sm.ImageGsmcK;
import de.gematik.liana.sm.ImageObjects;
import de.gematik.liana.sm.TerminalIdentity;
import de.gematik.liana.sm.TrustedChannelTerminal;
import io.quarkus.runtime.Startup;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Disposes;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Provider;
import jakarta.inject.Singleton;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.TreeMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import org.jboss.logging.Logger;

/**
 * Wires card terminals from {@code liana.infrastructure.terminals}: fake terminals with kartos
 * (decision-3, decision-7) and eHealth CTs via SICCT (decision-11), depending on {@code mode}
 * (fake, sicct, mixed) side by side in the terminal registry of the core, on top of that the card
 * list CM_CARD_LIST, the Informationsmodell, the card sessions and the operations.
 */
@ApplicationScoped
public class TerminalWiring {

  private static final Logger LOG = Logger.getLogger(TerminalWiring.class);

  private TrafficPush push;
  private DiscoveryChannel discovery;

  private final ScheduledExecutorService expiry =
      Executors.newSingleThreadScheduledExecutor(
          runnable -> {
            Thread thread = new Thread(runnable, "liana-card-session-timer");
            thread.setDaemon(true);
            return thread;
          });

  /**
   * kartos as card engine of the fake CTs (LIANA-121): {@code card.kartos-bin}, otherwise the
   * checked-in one from {@code tools/kartos/} under the working directory ({@link KartosLocator}).
   * If there is a fake CT but no runnable kartos, the startup aborts; otherwise TUC_KON_001 would
   * silently yield UNKNOWN for every card.
   */
  @Produces
  @Singleton
  CardEngine cardEngine(LianaConfig config) {
    return cardEngineOf(config, java.nio.file.Path.of(""));
  }

  static CardEngine cardEngineOf(LianaConfig config, java.nio.file.Path root) {
    boolean fake =
        config.infrastructure().terminals().values().stream()
            .anyMatch(kt -> kt.type() == LianaConfig.Type.FAKE);
    if (!fake) {
      return new KartosEngine(config.card().kartosBin());
    }
    KartosLocator.Kartos kartos = KartosLocator.resolve(config.card().kartosBin(), root);
    LOG.infof("Card-Engine %s (%s)", kartos.path(), kartos.version());
    return new KartosEngine(kartos.path());
  }

  @Produces
  @Singleton
  @Startup
  FakeTerminals fakeTerminals(LianaConfig config, CardEngine engine) {
    return fakeTerminalsOf(config, engine);
  }

  /**
   * The CTs with {@code type: fake} from {@code infrastructure.terminals}, cards from {@code
   * card-images} (LIANA-98); order of the CT.CTIDs.
   */
  static FakeTerminals fakeTerminalsOf(LianaConfig config, CardEngine engine) {
    List<FakeTerminals.Spec> specs =
        new TreeMap<>(config.infrastructure().terminals())
            .entrySet().stream()
                .filter(e -> e.getValue().type() == LianaConfig.Type.FAKE)
                .map(
                    e ->
                        new FakeTerminals.Spec(
                            e.getKey(),
                            e.getValue().slotCount().orElseThrow(),
                            e.getValue().slots(),
                            e.getValue().pin(),
                            e.getValue().puk(),
                            e.getValue().transportPin(),
                            e.getValue().signatureTime().orElse(Duration.ZERO)))
                .toList();
    return new FakeTerminals(specs, new CardImages(config.cardImages()), engine);
  }

  /**
   * Terminal registry of the core: every card access at most CARD_TIMEOUT_CARD long ({@link
   * TimeLimitedTerminal}, 4094); with {@code liana.trace.push-url} every CT additionally reports
   * its APDUs to a Tiger proxy (LIANA-27). eHealth CTs among the robot terminals wait for the robot
   * before the PIN command with {@code liana.robot.await-pin} (LIANA-112.15).
   */
  @Produces
  @Singleton
  TerminalRegistry terminalRegistry(
      FakeTerminals fakeTerminals,
      SicctTerminals sicctTerminals,
      LianaConfig config,
      Provider<CardList> cards,
      ManagementSettings settings,
      KartosRobots robots) {
    return terminalRegistry(fakeTerminals, sicctTerminals, config, cards, settings, robots::wrap);
  }

  /** Without robot terminals via kartos. */
  TerminalRegistry terminalRegistry(
      FakeTerminals fakeTerminals,
      SicctTerminals sicctTerminals,
      LianaConfig config,
      Provider<CardList> cards,
      ManagementSettings settings) {
    return terminalRegistry(
        fakeTerminals,
        sicctTerminals,
        config,
        cards,
        settings,
        java.util.function.UnaryOperator.identity());
  }

  private TerminalRegistry terminalRegistry(
      FakeTerminals fakeTerminals,
      SicctTerminals sicctTerminals,
      LianaConfig config,
      Provider<CardList> cards,
      ManagementSettings settings,
      java.util.function.UnaryOperator<CardTerminal> robots) {
    List<CardTerminal> terminals = new ArrayList<>();
    fakeTerminals.terminals().forEach(terminal -> terminals.add(terminal));
    sicctTerminals.terminals().forEach(terminal -> terminals.add(robots.apply(terminal)));
    terminals.replaceAll(terminal -> new TimeLimitedTerminal(terminal, settings::cardTimeout));
    config
        .trace()
        .pushUrl()
        .ifPresent(
            url -> {
              push = new TrafficPush(url, config.trace().pushTimeout());
              LOG.infof("Karten-APDUs gehen per Traffic-Push an %s", push.target());
              terminals.replaceAll(terminal -> new TrafficPushingTerminal(terminal, push));
            });
    if (config.card().terminateSecureMessaging()) {
      terminals.replaceAll(terminal -> trustedChannel(terminal, config, cards));
    }
    return new TerminalRegistry(terminals);
  }

  /**
   * LIANA-28: terminate the trusted channel, wrapped around the CT so that the traffic push sees
   * what goes to the card (hop B); the plaintext follows as a separate message. LIANA finds the
   * twin via the ICCSN of the card in CM_CARD_LIST; if the same card is in several folders of
   * {@code card-images}, the first one in their order applies, as with the file name. The gSMC-KT
   * is configured at the CT ({@code gsmc-kt}, LIANA-99), cross CVCs come from the TSL.
   */
  private CardTerminal trustedChannel(
      CardTerminal terminal, LianaConfig config, Provider<CardList> cards) {
    CardImages images = new CardImages(config.cardImages());
    TerminalIdentity identity =
        TerminalIdentity.of(
            images.resolve(
                config.infrastructure().terminals().get(terminal.id()).gsmcKt().orElseThrow()),
            TerminalIdentity.links(config.pki().tsl()));
    LOG.infof(
        "%s: Trusted Channel wird terminiert, LIANA als Terminal mit %s", terminal.id(), identity);
    TrustedChannelTerminal.Twins twins =
        (ctId, slot) ->
            cards
                .get()
                .card(ctId, slot)
                .map(card -> card.data().iccsn())
                .flatMap(
                    iccsn ->
                        twin(images, iccsn)
                            .or(
                                () -> {
                                  LOG.infof(
                                      "%s/%d: kein Zwilling zur ICCSN %s in %s",
                                      ctId, slot, iccsn, images.directories());
                                  return java.util.Optional.empty();
                                }))
                .map(ImageObjects::load);
    TrustedChannelTerminal.Listener plaintext =
        push != null
            ? push::plaintext
            : (kt, slot, command, sent, response, received) ->
                LOG.debugf(
                    "%s/%d SM-Klartext %s -> %s",
                    kt,
                    slot,
                    java.util.HexFormat.of().formatHex(command),
                    java.util.HexFormat.of().formatHex(response));
    return new TrustedChannelTerminal(terminal, identity, twins, plaintext);
  }

  /**
   * First image with this ICCSN; without a hit in the index {@link CardImages#resolve} searches
   * once more.
   */
  private static java.util.Optional<java.nio.file.Path> twin(CardImages images, String iccsn) {
    java.util.Optional<java.nio.file.Path> indexed =
        images.images().stream()
            .filter(image -> image.iccsn().filter(iccsn::equals).isPresent())
            .map(CardImages.Image::file)
            .findFirst();
    if (indexed.isPresent()) {
      return indexed;
    }
    try {
      return java.util.Optional.of(images.resolve(iccsn));
    } catch (IllegalArgumentException e) {
      return java.util.Optional.empty();
    }
  }

  /**
   * eHealth CTs from {@code terminals.sicct} (decision-11, LIANA-76): CTM_CT_LIST with
   * TUC_KON_054/055 via service discovery (UDP on CTM_SERVICE_ANNOUNCEMENT_PORT) and TLS with
   * ID.SAK.AUT ({@link KtTls}, C.SMKT.AUT against the TSL). The configured CTs are added and
   * populated in the background after startup; without {@code sicct} in the mode the UDP port stays
   * closed.
   */
  @Produces
  @Singleton
  SicctTerminals sicctTerminals(
      LianaConfig config,
      TrustSpace trustSpace,
      Clock clock,
      SystemLog systemLog,
      PeerDeviations deviations)
      throws GeneralSecurityException, IOException {
    LianaConfig.Ctm ctm = config.ctm();
    List<SicctTerminals.Spec> specs =
        new TreeMap<>(config.infrastructure().terminals())
            .entrySet().stream()
                .filter(e -> e.getValue().type() == LianaConfig.Type.SICCT)
                .map(
                    e -> {
                      LianaConfig.Terminal kt = e.getValue();
                      if (kt.slotCount().isPresent() || !kt.slots().isEmpty()) {
                        LOG.infof(
                            "%s ist ein eHealth-KT: slot-count und slots gelten nur für Fake-KTs und bleiben "
                                + "unbeachtet",
                            e.getKey());
                      }
                      return new SicctTerminals.Spec(
                          e.getKey(),
                          kt.host().orElseThrow(),
                          kt.sharedSecret().map(java.util.HexFormat.of()::parseHex).orElse(null));
                    })
                .toList();
    if (specs.isEmpty()) {
      return new SicctTerminals(
          List.of(),
          (host, port) -> {
            throw new IOException("keine eHealth-KTs konfiguriert");
          },
          new SicctTerminals.Settings(
              ctm.serviceDiscoveryPort(),
              ctm.serviceDiscoveryTimeout(),
              config.card().cardTimeout(),
              ctm.supportedKtVersions()),
          systemLog);
    }
    LianaConfig.GsmcK gsmcK = config.infrastructure().konnektor().gsmcK();
    KtTls tls =
        new KtTls(
            TlsIdentity.load(gsmcK.sakAut(), gsmcK.password()),
            SmktCertificateCheck.of(trustSpace, clock));
    SicctTerminals terminals =
        new SicctTerminals(
            specs,
            (host, port) -> tls.connect(host, port, ctm.tlsHandshakeTimeout()),
            new SicctTerminals.Settings(
                ctm.serviceDiscoveryPort(),
                ctm.serviceDiscoveryTimeout(),
                config.card().cardTimeout(),
                ctm.supportedKtVersions(),
                ctm.konnektorHostname(),
                ctm.keepAliveInterval(),
                ctm.keepAliveTryCount(),
                ctm.serviceDiscoveryCycle()),
            systemLog,
            SmktCertificateCheck::verifyPlainEcdsa,
            deviations);
    discovery =
        new DiscoveryChannel(
            new InetSocketAddress(ctm.serviceAnnouncementPort()), terminals::announced);
    LOG.infof(
        "Dienstsuche auf UDP %d (CTM_SERVICE_ANNOUNCEMENT_PORT), eHealth-KTs %s",
        discovery.port(), specs.stream().map(SicctTerminals.Spec::ctId).toList());
    Thread start = new Thread(() -> terminals.start(discovery), "liana-ctm-start");
    start.setDaemon(true);
    start.start();
    return terminals;
  }

  void close(@Disposes SicctTerminals terminals) {
    if (discovery != null) {
      discovery.close();
    }
    terminals.close();
  }

  void close(@Disposes TerminalRegistry registry) {
    if (push != null) {
      push.close();
    }
  }

  @Produces
  @Singleton
  Clock clock() {
    return Clock.systemUTC();
  }

  /** Systemprotokoll (TIP1-A_4715, TUC_KON_271) for the events from card list and card sessions. */
  @Produces
  @Singleton
  SystemLog systemLog(Clock clock) {
    return new SystemLog(clock, SystemLog.DEFAULT_CAPACITY);
  }

  /**
   * Parameters changeable via the KMS (LIANA-55); CARD_SESSION_TIMEOUT and CARD_TIMEOUT_CARD start
   * with the values from the YAML.
   */
  @Produces
  @Singleton
  ManagementSettings managementSettings(LianaConfig config, SystemLog systemLog) {
    return new ManagementSettings(
        config.card().sessionTimeout(), config.card().cardTimeout(), systemLog);
  }

  /**
   * TUC_KON_025: at startup the card list opens the cards from the YAML and then follows the slot
   * events; every event goes into the Systemprotokoll, including those at startup (TUC_KON_256 step
   * 2), and to the subscriptions of the Clientsysteme (steps 5 and 6, LIANA-59; at startup the list
   * is empty, TIP1-A_4613).
   */
  @Produces
  @Singleton
  @Startup
  CardList cardList(
      TerminalRegistry registry,
      Clock clock,
      SystemLog systemLog,
      Subscriptions subscriptions,
      FakeTerminals fakeTerminals) {
    CardList cards = new CardList(registry, clock);
    cards.addListener(systemLog::cardEvent);
    cards.addListener(event -> subscriptions.publish(Event.of(event)));
    cards.addListener(
        event ->
            LOG.infof(
                "%s %s/%d %s %s",
                event.topic().topic(),
                event.card().ctId(),
                event.card().slotNo(),
                event.card().data().type().value(),
                event.card().cardHandle()));
    cards.addListener(event -> unknown(event, fakeTerminals));
    cards.start();
    return cards;
  }

  /**
   * LIANA-121: an inserted card that TUC_KON_001 lists as UNKNOWN is a warning with reason and, on
   * the fake CT, the image; otherwise it would remain invisible why GetCards yields neither ICCSN
   * nor holder.
   */
  private static void unknown(CardEvent event, FakeTerminals fakeTerminals) {
    CardObject card = event.card();
    if (event.topic() != CardEvent.Topic.INSERTED || card.unknownReason() == null) {
      return;
    }
    String image =
        fakeTerminals.terminals().stream()
            .filter(kt -> kt.id().equals(card.ctId()))
            .findFirst()
            .flatMap(kt -> kt.image(card.slotNo()))
            .map(path -> " Image " + path)
            .orElse("");
    LOG.warnf(
        "%s/%d%s: Karte nicht erkannt, CardType UNKNOWN: %s",
        card.ctId(), card.slotNo(), image, card.unknownReason());
  }

  /** Informationsmodell for TUC_KON_000 from {@code liana.infomodel}. */
  @Produces
  @Singleton
  Infomodel infomodel(LianaConfig config) {
    return infomodel(config.infomodel());
  }

  static Infomodel infomodel(LianaConfig.Infomodel cfg) {
    return new Infomodel(
        cfg.mandants(),
        cfg.clientSystems(),
        cfg.workplaces().stream()
            .map(
                w ->
                    new Infomodel.Workplace(w.id(), w.mandants(), w.clientSystems(), w.terminals()))
            .toList(),
        cfg.smbVerwaltet().orElse(List.of()).stream()
            .collect(
                Collectors.toMap(
                    LianaConfig.SmbVerwaltet::iccsn, LianaConfig.SmbVerwaltet::mandants)));
  }

  /**
   * Card reservations (TUC_KON_023), shared by the card sessions and all card accesses (A_25895).
   */
  @Produces
  @Singleton
  CardLocks cardLocks() {
    return new CardLocks();
  }

  /** TUC_KON_000 with CardHandle and TUC_KON_026 step 2, shared by the operations on a card. */
  @Produces
  @Singleton
  CardAccess cardAccess(Infomodel infomodel, CardList cards, CardLocks locks) {
    return new CardAccess(infomodel, cards, locks);
  }

  /** ReadCardCertificate (TIP1-A_4700-03). */
  @Produces
  @Singleton
  CardCertificates cardCertificates(CardAccess access, TerminalRegistry registry) {
    return new CardCertificates(access, registry);
  }

  /** CARDSESSION.AUTHSTATE; a removed card ends its card sessions. */
  @Produces
  @Singleton
  AuthState authState(CardList cards) {
    AuthState authState = new AuthState();
    cards.addListener(
        event -> {
          if (event.topic() == CardEvent.Topic.REMOVED) {
            authState.removed(event.card().cardHandle());
          }
        });
    return authState;
  }

  /**
   * VerifyPin (TIP1-A_4587) and GetPinStatus (TIP1-A_4589), PIN entry on the PIN pad of the CT;
   * CARD/PIN/VERIFY_STARTED and VERIFY_FINISHED go to the subscriptions of the Clientsysteme, not
   * into the Systemprotokoll (TUC_KON_012 step 7, doLog=false).
   */
  @Produces
  @Singleton
  PinVerification pinVerification(
      CardAccess access,
      TerminalRegistry registry,
      AuthState authState,
      Subscriptions subscriptions) {
    PinVerification pins = new PinVerification(access, registry, authState);
    pins.addListener(event -> subscriptions.publish(Event.of(event)));
    return pins;
  }

  /** ExternalAuthenticate (TIP1-A_5439-02) with the SM-B. */
  @Produces
  @Singleton
  ExternalAuthentication externalAuthentication(
      CardAccess access, TerminalRegistry registry, AuthState authState) {
    return new ExternalAuthentication(access, registry, authState);
  }

  /**
   * TUC_KON_018 and TUC_KON_202 on the eGK, C.CH.AUT offline according to TUC_KON_037 against the
   * Vertrauensraum.
   */
  @Produces
  @Singleton
  EgkFiles egkFiles(TerminalRegistry registry, TrustSpace trustSpace, Clock clock) {
    return new EgkFiles(registry, new EgkCertificateCheck(trustSpace, clock));
  }

  @Produces
  @Singleton
  GetCards getCards(Infomodel infomodel, TerminalRegistry registry, CardList cards) {
    return new GetCards(infomodel, registry, cards);
  }

  @Produces
  @Singleton
  GetCardTerminals getCardTerminals(Infomodel infomodel, TerminalRegistry registry) {
    return new GetCardTerminals(infomodel, registry);
  }

  /**
   * Betriebszustand (LIANA-187): connections from {@code liana.operating-state}, follows
   * MGM_LU_ONLINE.
   */
  @Produces
  @Singleton
  OperatingState operatingState(
      LianaConfig config, ManagementSettings settings, SystemLog systemLog, Clock clock) {
    var boot = config.operatingState();
    return new OperatingState(
        new OperatingState.Connections(
            boot.vpnTiOnline(), boot.vpnSisOnline(), boot.transportOnline()),
        settings,
        systemLog,
        clock);
  }

  @Produces
  @Singleton
  GetResourceInformation getResourceInformation(
      Infomodel infomodel,
      TerminalRegistry registry,
      CardList cards,
      CardAccess cardAccess,
      GetCardTerminals getCardTerminals,
      OperatingState operatingState) {
    return new GetResourceInformation(
        infomodel, registry, cards, cardAccess, getCardTerminals, operatingState);
  }

  /**
   * CheckCertificateExpiration (TIP1-A_4699-07, LIANA-188): the gSMC-K from {@code
   * infrastructure.konnektor.gsmc-k.image}; without an image its entry is missing.
   */
  @Produces
  @Singleton
  CertificateExpiration certificateExpiration(
      LianaConfig config,
      Infomodel infomodel,
      CardList cards,
      CardAccess cardAccess,
      CardCertificates certificates) {
    CardImages images = new CardImages(config.cardImages());
    Optional<GsmcK> gsmcK =
        config
            .infrastructure()
            .konnektor()
            .gsmcK()
            .image()
            .map(image -> new ImageGsmcK(images.resolve(image)));
    return new CertificateExpiration(infomodel, cards, cardAccess, certificates, gsmcK);
  }

  /**
   * RequestCard and EjectCard (LIANA-110); TUC_KON_001 after the insert at most CARD_TIMEOUT_CARD.
   */
  @Produces
  @Singleton
  CardTerminalService cardTerminalService(
      Infomodel infomodel,
      TerminalRegistry registry,
      CardList cards,
      CardLocks locks,
      SystemLog systemLog,
      LianaConfig config) {
    return new CardTerminalService(
        infomodel, registry, cards, locks, systemLog, config.card().cardTimeout());
  }

  /**
   * Vertrauensraum from {@code liana.pki}; loaded at startup, an unreadable TSL aborts the startup.
   */
  @Produces
  @Singleton
  @Startup
  TrustSpace trustSpace(LianaConfig config) {
    TrustSpace trustSpace =
        TrustSpace.load(
            config.pki().tsl(),
            config.pki().importedCas().orElse(List.of()),
            config.pki().bnetzaVl().orElse(null));
    TrustSpace.TslInfo tsl = trustSpace.tsl();
    LOG.infof(
        "TSL %s: SequenceNumber %s, NextUpdate %s, %d CA-Zertifikate; %d importiert; geladen in %d ms, "
            + "davon Zertifikate %d ms",
        tsl.source(),
        tsl.sequenceNumber(),
        tsl.nextUpdate(),
        tsl.caCount(),
        trustSpace.importedCount(),
        tsl.loading().toMillis(),
        tsl.parsing().toMillis());
    trustSpace
        .vl()
        .ifPresentOrElse(
            vl ->
                LOG.infof(
                    "BNetzA-VL %s: SequenceNumber %s, %d qualifizierte CAs; geladen "
                        + "in %d ms, davon Zertifikate %d ms",
                    vl.source(),
                    vl.sequenceNumber(),
                    vl.caCount(),
                    vl.loading().toMillis(),
                    vl.parsing().toMillis()),
            () -> LOG.info("ohne BNetzA-VL: QES-Prüfung ohne Aussteller"));
    LianaConfig.TslOnline online = config.pki().tslOnline();
    de.gematik.liana.crypto.OnlineTsl.start(
        trustSpace, online.mode(), online.url(), online.timeout());
    return trustSpace;
  }

  /** SignedScenario check for SecureSendAPDU (BC, Jackson), signer according to TUC_KON_037. */
  @Produces
  @Singleton
  ScenarioDecoder scenarioDecoder(TrustSpace trustSpace, Clock clock) {
    return new SignedScenarios(new ScenarioSignerCheck(trustSpace, clock));
  }

  /**
   * Card sessions of the PoPP tunnel; a tick ends sessions with an expired APDU scenario timer
   * (A_25860-01) even without a further call.
   */
  @Produces
  @Singleton
  @Startup
  CardSessions cardSessions(
      CardAccess access,
      CardLocks locks,
      TerminalRegistry registry,
      CardList cards,
      ScenarioDecoder decoder,
      Clock clock,
      ManagementSettings settings,
      SystemLog systemLog) {
    CardSessions sessions =
        new CardSessions(access, locks, registry, cards, decoder, clock, settings::sessionTimeout);
    sessions.addListener(systemLog::sessionTimeout);
    sessions.addListener(
        timeout ->
            LOG.infof(
                "%s CardType=%s SessionID=%s Timer=%s",
                CardSessions.Timeout.TOPIC,
                timeout.cardType(),
                timeout.sessionId(),
                timeout.timer()));
    expiry.scheduleWithFixedDelay(sessions::expire, 200, 200, TimeUnit.MILLISECONDS);
    return sessions;
  }

  void close(@Disposes CardSessions sessions) {
    expiry.shutdownNow();
  }

  void close(@Disposes FakeTerminals fakeTerminals) {
    fakeTerminals.close();
  }
}

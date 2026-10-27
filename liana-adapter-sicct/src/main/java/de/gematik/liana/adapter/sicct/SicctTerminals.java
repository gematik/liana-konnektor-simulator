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
package de.gematik.liana.adapter.sicct;

import de.gematik.liana.kern.error.ConnectorError;
import de.gematik.liana.kern.error.ConnectorException;
import de.gematik.liana.kern.event.SystemLog;
import de.gematik.liana.kern.vendor.PeerDeviations;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocket;

/**
 * CTM_CT_LIST for eHealth card terminals (gemSpec_Kon 4.1.4, TAB_KON_522) with TUC_KON_054
 * "Kartenterminal hinzufügen" (add card terminal) and TUC_KON_055 "Befülle CT-Object" (populate CT
 * object), plus the reaction to service announcement packets (TIP1-A_4540).
 *
 * <p>The card terminals configured via YAML (CT.CTID, address) count as manually added: TUC_KON_054
 * with {@code Mode = ManuallyAdded} queries the card terminal for port, MAC and hostname via
 * service discovery, creates it as "zugewiesen" (assigned) and populates it with TUC_KON_055. Card
 * terminals announced unsolicited are added by TUC_KON_054 with {@code Mode = AutoAdded} as
 * "bekannt" (known).
 *
 * <p>Pairing (TUC_KON_053, LIANA-77): EHEALTH TERMINAL AUTHENTICATE CREATE with a new shared
 * secret, verification of the card terminal's signature with C.SMKT.AUT, correlation via "gepairt"
 * (paired) to "aktiv" (active). An active card terminal is connected by TUC_KON_050: TLS,
 * comparison with CT.SMKT_AUT, INIT CT SESSION, VALIDATE with challenge; afterwards the working
 * connection stays open (CT.CONNECTED = Ja) until it breaks off (TIP1-A_4537). A shared secret from
 * the YAML counts as an existing pairing (boot state, decision-4); the Admin API sets or deletes it
 * transiently, {@link #reset()} restores the YAML state.
 */
public final class SicctTerminals {

  private static final System.Logger LOGGER = System.getLogger(SicctTerminals.class.getName());

  /** TLS connection to the card terminal (TUC_KON_050 step 3), handshake completed. */
  @FunctionalInterface
  public interface KtConnector {
    Socket connect(String host, int port) throws IOException;
  }

  /** TUC_KON_054 input parameter Mode. */
  public enum Mode {
    AUTO_ADDED,
    MANUALLY_ADDED,
    MANUALLY_MODIFIED
  }

  /**
   * A card terminal configured via YAML: CT.CTID, address (for the service enquiry) and optionally
   * the shared secret of an already existing pairing (16 bytes).
   */
  public record Spec(String ctId, String host, byte[] sharedSecret) {

    public Spec(String ctId, String host) {
      this(ctId, host, null);
    }
  }

  /**
   * Verifies the terminal's signature over the shared secret (SEQ_KT_0001-01 step 7/8, ECDSA plain,
   * SHA-256).
   */
  @FunctionalInterface
  public interface SignatureCheck {
    boolean verify(X509Certificate certificate, byte[] message, byte[] plainSignature);
  }

  /**
   * @param discoveryPort CTM_SERVICE_DISCOVERY_PORT on which the card terminals listen for service
   *     enquiries
   * @param discoveryTimeout CTM_SERVICE_DISCOVERY_TIMEOUT
   * @param commandTimeout waiting time for an R-command
   * @param supportedVersions CTM_SUPPORTED_KT_VERSIONS
   * @param konnektorHostname MGM_KONN_HOSTNAME for the pairing display
   * @param keepAliveInterval CTM_KEEP_ALIVE_INTERVAL: GET STATUS as heartbeat after this much
   *     silence (TIP1-A_4536)
   * @param keepAliveTryCount CTM_KEEP_ALIVE_TRY_COUNT: this many unanswered heartbeats drop the
   *     connection
   * @param discoveryCycle CTM_SERVICE_DISCOVERY_CYCLE: interval of service enquiries to unconnected
   *     active card terminals (TIP1-A_4538-02), {@link Duration#ZERO} disables them
   */
  public record Settings(
      int discoveryPort,
      Duration discoveryTimeout,
      Duration commandTimeout,
      List<String> supportedVersions,
      String konnektorHostname,
      Duration keepAliveInterval,
      int keepAliveTryCount,
      Duration discoveryCycle) {

    /** With CTM_SERVICE_DISCOVERY_CYCLE = 10 minutes (default value, TAB_KON_527). */
    public Settings(
        int discoveryPort,
        Duration discoveryTimeout,
        Duration commandTimeout,
        List<String> supportedVersions,
        String konnektorHostname,
        Duration keepAliveInterval,
        int keepAliveTryCount) {
      this(
          discoveryPort,
          discoveryTimeout,
          commandTimeout,
          supportedVersions,
          konnektorHostname,
          keepAliveInterval,
          keepAliveTryCount,
          Duration.ofMinutes(10));
    }

    public Settings(
        int discoveryPort,
        Duration discoveryTimeout,
        Duration commandTimeout,
        List<String> supportedVersions) {
      this(discoveryPort, discoveryTimeout, commandTimeout, supportedVersions, "liana");
    }

    public Settings(
        int discoveryPort,
        Duration discoveryTimeout,
        Duration commandTimeout,
        List<String> supportedVersions,
        String konnektorHostname) {
      this(
          discoveryPort,
          discoveryTimeout,
          commandTimeout,
          supportedVersions,
          konnektorHostname,
          Duration.ofSeconds(10),
          3);
    }
  }

  private final List<Spec> configured;
  private final Map<String, SicctTerminal> terminals = new LinkedHashMap<>();
  private final Map<String, CtObject> ctList = new LinkedHashMap<>();
  private final KtConnector connector;
  private final Settings settings;
  private final SystemLog log;
  private final SignatureCheck signatures;
  private final Map<String, SicctConnection> working = new ConcurrentHashMap<>();
  private final Map<String, Integer> missedHeartbeats = new ConcurrentHashMap<>();

  /**
   * Slot events and connection end one after another, not in the reader thread (the card reader
   * sends APDUs).
   */
  private final java.util.concurrent.ExecutorService events =
      java.util.concurrent.Executors.newSingleThreadExecutor(daemon("liana-sicct-events"));

  private final java.util.concurrent.ScheduledExecutorService heartbeat =
      java.util.concurrent.Executors.newSingleThreadScheduledExecutor(
          daemon("liana-sicct-keepalive"));
  private final java.util.concurrent.ScheduledExecutorService rediscovery =
      java.util.concurrent.Executors.newSingleThreadScheduledExecutor(
          daemon("liana-sicct-discovery"));
  private DiscoveryChannel discovery;

  public SicctTerminals(
      List<Spec> configured, KtConnector connector, Settings settings, SystemLog log) {
    this(configured, connector, settings, log, (certificate, message, signature) -> false);
  }

  public SicctTerminals(
      List<Spec> configured,
      KtConnector connector,
      Settings settings,
      SystemLog log,
      SignatureCheck signatures) {
    this(configured, connector, settings, log, signatures, new PeerDeviations(false, log));
  }

  /**
   * {@code deviations}: terminals' deviations from SICCT (LIANA-126), e.g. MODIFY VERIFICATION DATA
   * with kartos.
   */
  public SicctTerminals(
      List<Spec> configured,
      KtConnector connector,
      Settings settings,
      SystemLog log,
      SignatureCheck signatures,
      PeerDeviations deviations) {
    this.configured = List.copyOf(configured);
    this.connector = connector;
    this.settings = settings;
    this.log = log;
    this.signatures = signatures;
    for (Spec spec : configured) {
      terminals.put(
          spec.ctId(),
          new SicctTerminal(
              spec.ctId(),
              () -> ct(spec.ctId()),
              () -> working(spec.ctId()),
              settings.commandTimeout(),
              deviations));
    }
    long tick = Math.max(100, settings.keepAliveInterval().toMillis() / 4);
    heartbeat.scheduleWithFixedDelay(
        this::heartbeat, tick, tick, java.util.concurrent.TimeUnit.MILLISECONDS);
    if (settings.discoveryCycle().isPositive()) {
      long cycle = settings.discoveryCycle().toMillis();
      rediscovery.scheduleWithFixedDelay(
          this::rediscover, cycle, cycle, java.util.concurrent.TimeUnit.MILLISECONDS);
    }
  }

  private static java.util.concurrent.ThreadFactory daemon(String name) {
    return runnable -> {
      Thread thread = new Thread(runnable, name);
      thread.setDaemon(true);
      return thread;
    };
  }

  /** Ends all working connections and background threads. */
  public void close() {
    heartbeat.shutdownNow();
    rediscovery.shutdownNow();
    List.copyOf(working.keySet()).forEach(this::disconnect);
    events.shutdown();
  }

  /** The configured card terminals behind {@code CardTerminal}, in YAML order. */
  public List<SicctTerminal> terminals() {
    return List.copyOf(terminals.values());
  }

  /** CTM_CT_LIST: all known eHealth card terminals, configured and announced. */
  public synchronized List<CtObject> ctList() {
    return List.copyOf(ctList.values());
  }

  public synchronized Optional<CtObject> ct(String ctId) {
    return Optional.ofNullable(ctList.get(ctId));
  }

  /** The configured card terminals, including those without a CT object (TUC_KON_054 failed). */
  public List<Spec> configured() {
    return configured;
  }

  /**
   * Receives service descriptions via {@code channel} and adds the configured card terminals
   * (TUC_KON_054, ManuallyAdded, then TUC_KON_055). A card terminal that does not respond stays
   * without a CT object; the error is recorded in the Systemprotokoll (CT/CT_ADDING_ERROR).
   */
  public void start(DiscoveryChannel channel) {
    this.discovery = channel;
    for (Spec spec : configured) {
      try {
        add(Mode.MANUALLY_ADDED, spec.ctId(), InetAddress.getByName(spec.host()), null, null, null);
        bootPairing(spec);
      } catch (IOException e) {
        addingError(
            spec.host(),
            null,
            ConnectorError.CT_NOT_ANSWERING.exception(e.getMessage()).causedBy(e));
      } catch (ConnectorException e) {
        addingError(spec.host(), null, e);
      }
    }
  }

  /**
   * TUC_KON_054 with Mode = ManuallyAdded again for the configured card terminal {@code ctId}, e.g.
   * if it did not respond at startup (Admin API {@code POST /admin/ct-discovery}, LIANA-149). A CT
   * object newly created this way gets the pairing from the YAML as at startup; an existing one
   * keeps pairing and connection.
   *
   * @throws ConnectorException 4007 for a card terminal that is not configured, otherwise the
   *     errors of TUC_KON_054 (TAB_KON_525), which are also recorded in the Systemprotokoll
   *     (CT/CT_ADDING_ERROR)
   */
  public CtObject discover(String ctId) {
    Spec spec =
        configured.stream()
            .filter(s -> s.ctId().equals(ctId))
            .findFirst()
            .orElseThrow(
                () ->
                    ConnectorError.INVALID_CT_ID.exception(
                        ctId + " ist kein konfiguriertes eHealth-KT"));
    boolean known = ct(ctId).isPresent();
    CtObject ct;
    try {
      ct = add(Mode.MANUALLY_ADDED, ctId, InetAddress.getByName(spec.host()), null, null, null);
    } catch (IOException e) {
      ConnectorException error =
          ConnectorError.CT_NOT_ANSWERING.exception(e.getMessage()).causedBy(e);
      addingError(spec.host(), null, error);
      throw error;
    } catch (ConnectorException e) {
      addingError(spec.host(), null, e);
      throw e;
    }
    if (!known) {
      bootPairing(spec);
    }
    return ct;
  }

  /**
   * TIP1-A_4540: every service description leads to TUC_KON_054 with Mode = AutoAdded; if the card
   * terminal is then at least "zugewiesen" (assigned) with a valid version, TUC_KON_050 follows
   * (role = "User"); a connected card terminal stays connected.
   */
  public void announced(ServiceDiscovery.Announcement announcement) {
    try {
      CtObject ct =
          add(
              Mode.AUTO_ADDED,
              null,
              announcement.ip(),
              announcement.port(),
              announcement.mac(),
              announcement.name());
      if (ct.correlation().compareTo(CtObject.Correlation.BEKANNT) > 0
          && ct.validVersion()
          && !ct.connected()) {
        connect(ct.ctId());
      }
    } catch (IOException e) {
      addingError(
          announcement.ip().getHostAddress(),
          announcement.name(),
          ConnectorError.CT_NOT_ANSWERING.exception(e.getMessage()).causedBy(e));
    } catch (ConnectorException e) {
      addingError(announcement.ip().getHostAddress(), announcement.name(), e);
    }
  }

  /**
   * TUC_KON_054 "Kartenterminal hinzufügen" (add card terminal).
   *
   * @param ctId CT.CTID for a newly configured card terminal; {@code null} derives one from the MAC
   * @throws ConnectorException 4033, 4035, 4036, 4037 (TAB_KON_525)
   */
  public CtObject add(
      Mode mode, String ctId, InetAddress ip, Integer port, String mac, String hostname)
      throws IOException {
    // Step 1: missing data or manual → service discovery as unicast to the card terminal
    if (mode != Mode.AUTO_ADDED || port == null || mac == null || hostname == null) {
      ServiceDiscovery.Announcement answer =
          discovery
              .discover(ip, settings.discoveryPort(), settings.discoveryTimeout())
              .orElseThrow(
                  () ->
                      ConnectorError.CT_NOT_ANSWERING.exception(
                          ip.getHostAddress()
                              + ":"
                              + settings.discoveryPort()
                              + " ohne Antwort in "
                              + settings.discoveryTimeout().toMillis()
                              + " ms"));
      if (mac != null && !mac.equalsIgnoreCase(answer.mac())) {
        throw ConnectorError.CT_MAC_MISMATCH.exception(mac + " ≠ " + answer.mac());
      }
      if (hostname != null && !hostname.equals(answer.name())) {
        throw ConnectorError.CT_HOSTNAME_MISMATCH.exception(hostname + " ≠ " + answer.name());
      }
      port = answer.port();
      mac = answer.mac();
      hostname = answer.name();
    }
    return addFound(mode, ctId, ip, port, mac, hostname);
  }

  /** TUC_KON_054 steps 2–6 with complete device data. */
  private CtObject addFound(
      Mode mode, String ctId, InetAddress ip, int port, String mac, String hostname) {
    CtObject ct;
    boolean fill;
    synchronized (this) {
      // Step 2: find the CT by MAC
      ct =
          ctList.values().stream()
              .filter(c -> mac.equalsIgnoreCase(c.mac()))
              .findFirst()
              .or(() -> Optional.ofNullable(ctId).map(ctList::get))
              .orElse(null);
      if (ct == null && mode == Mode.MANUALLY_MODIFIED) {
        throw ConnectorError.CT_LIST_INCONSISTENT.exception("kein KT mit MAC " + mac);
      }
      // Step 3: new CT object
      if (ct == null) {
        String id = ctId != null ? ctId : "KT-" + mac.replace(":", "").toUpperCase(Locale.ROOT);
        ct = new CtObject(id, mac, CtObject.Correlation.BEKANNT);
        ctList.put(id, ct);
        if (mode == Mode.MANUALLY_ADDED) {
          ct.correlation(CtObject.Correlation.ZUGEWIESEN);
        }
        LOGGER.log(
            System.Logger.Level.INFO,
            "TUC_KON_054: "
                + id
                + " ("
                + mac
                + ", "
                + hostname
                + ") "
                + ct.correlation().name().toLowerCase(Locale.ROOT));
      } else {
        ct.mac(mac);
      }
      // Step 4: a new address drops an existing connection (working connection from LIANA-78 on)
      // Step 5
      ct.address(ip, port, hostname);
      fill = ct.correlation().compareTo(CtObject.Correlation.ZUGEWIESEN) >= 0;
    }
    // Step 6
    if (fill) {
      fill(ct.ctId());
    }
    return ct;
  }

  /**
   * TUC_KON_055 "Befülle CT-Object" (populate CT object): TLS connection (TUC_KON_050 step 3),
   * session with empty username, password and session ID (step 4a, correlation at most
   * "zugewiesen"), GET STATUS for SLOTCOUNT, PRODUCTINFORMATION, EHEALTH_INTERFACE_VERSION and
   * DISPLAY_CAPABILITIES, version check against CTM_SUPPORTED_KT_VERSIONS, disconnect again.
   *
   * @return CT.VALID_VERSION
   * @throws ConnectorException 4028 if TLS or SICCT fail
   */
  public boolean fill(String ctId) {
    CtObject ct = ct(ctId).orElseThrow(() -> ConnectorError.INVALID_CT_ID.exception(ctId));
    String host = ct.ip().getHostAddress();
    try (SicctConnection connection =
        new SicctConnection(
            ctId,
            ct.hostname(),
            connector.connect(host, ct.tcpPort()),
            event -> {},
            (id, name, reason) -> {})) {
      Duration timeout = settings.commandTimeout();
      byte[] session = connection.transmit(SicctEnvelope.FU_TERMINAL, InitCtSession.EMPTY, timeout);
      if (!InitCtSession.ok(session)) {
        throw ConnectorError.CT_CONNECT_FAILED.exception(
            ctId + ": INIT CT SESSION " + hex(session));
      }
      byte[] cts =
          connection.transmit(
              SicctEnvelope.FU_TERMINAL, GetStatus.command(GetStatus.CTS_DO), timeout);
      byte[] ctm =
          connection.transmit(
              SicctEnvelope.FU_TERMINAL, GetStatus.command(GetStatus.CTM_DO), timeout);
      byte[] dsplc =
          connection.transmit(
              SicctEnvelope.FU_TERMINAL, GetStatus.command(GetStatus.DSPLC_DO), timeout);
      GetStatus.Terminal status = GetStatus.parse(cts, ctm, dsplc);
      boolean valid =
          GetStatus.supported(status.ehealthInterfaceVersion(), settings.supportedVersions());
      ct.status(status, valid);
      connection.transmit(SicctEnvelope.FU_TERMINAL, InitCtSession.CLOSE, timeout);
      LOGGER.log(System.Logger.Level.INFO, "TUC_KON_055: " + ctId + " " + ct.snapshot());
      return valid;
    } catch (IOException e) {
      throw ConnectorError.CT_CONNECT_FAILED
          .exception(ctId + " (" + host + ":" + ct.tcpPort() + "): " + e.getMessage())
          .causedBy(e);
    }
  }

  /**
   * Boot state of a configured card terminal (decision-4): with a shared secret from the YAML it
   * counts as paired and active and gets connected (TUC_KON_050), without one as "zugewiesen"
   * (assigned) without pairing.
   */
  private void bootPairing(Spec spec) {
    Optional<CtObject> found = ct(spec.ctId());
    if (found.isEmpty()) {
      return;
    }
    CtObject ct = found.get();
    disconnect(spec.ctId());
    if (spec.sharedSecret() == null) {
      ct.pairing(null, null);
      ct.correlation(CtObject.Correlation.ZUGEWIESEN);
      return;
    }
    ct.pairing(null, spec.sharedSecret());
    ct.correlation(CtObject.Correlation.AKTIV);
    if (ct.validVersion()) {
      try {
        connect(spec.ctId());
      } catch (ConnectorException e) {
        LOGGER.log(
            System.Logger.Level.WARNING, "TUC_KON_050 " + spec.ctId() + ": " + e.getMessage());
      }
    }
  }

  /**
   * TUC_KON_053 "Paire Kartenterminal" (pair card terminal, TIP1-A_4548-03).
   *
   * @param fingerprint SHA-256 fingerprint of C.SMKT.AUT confirmed by the administrator (step 3/4);
   *     {@code null} confirms the presented one
   * @throws ConnectorException 4040, 4041, 4042, 1021 (TAB_KON_113); 4007 for an unknown card
   *     terminal
   */
  public CtObject pair(String ctId, String fingerprint) {
    CtObject ct = require(ctId);
    if (ct.correlation() != CtObject.Correlation.ZUGEWIESEN) {
      throw pairingError(
          ct,
          ConnectorError.CT_PAIRING_FAILED.exception(
              ctId
                  + ": Korrelation "
                  + ct.correlation().name().toLowerCase(Locale.ROOT)
                  + ", Pairing nur aus „zugewiesen“"));
    }
    // Step 1
    if (!ct.validVersion()) {
      throw pairingError(
          ct,
          ConnectorError.CT_VERSION_UNSUPPORTED.exception(
              ctId
                  + ": EHEALTH-Interface-Version "
                  + ct.snapshot().get("EHEALTH_INTERFACE_VERSION")));
    }
    // Step 2: TLS, C.SMKT.AUT verified and stored
    Socket socket;
    try {
      socket = connector.connect(ct.ip().getHostAddress(), ct.tcpPort());
    } catch (IOException e) {
      throw pairingError(
          ct,
          ConnectorError.CT_PAIRING_CONNECT_FAILED
              .exception(ctId + ": " + e.getMessage())
              .causedBy(e));
    }
    X509Certificate smktAut = peerCertificate(socket);
    if (smktAut == null) {
      closeQuietly(socket);
      throw pairingError(
          ct, ConnectorError.CT_PAIRING_CONNECT_FAILED.exception(ctId + ": kein KT-Zertifikat"));
    }
    // Step 3/4: fingerprint confirmed?
    String presented = CtObject.fingerprint(smktAut);
    if (fingerprint != null && !fingerprint.equalsIgnoreCase(presented)) {
      closeQuietly(socket);
      ct.pairing(null, null);
      throw pairingError(
          ct,
          ConnectorError.CT_PAIRING_FAILED.exception(
              ctId
                  + ": Fingerprint "
                  + presented
                  + " vom Administrator nicht bestätigt (erwartet "
                  + fingerprint
                  + ")"));
    }
    byte[] sharedSecret = TerminalAuthenticate.newSharedSecret();
    try (SicctConnection connection =
        new SicctConnection(ctId, ct.hostname(), socket, event -> {}, (id, name, reason) -> {})) {
      Duration timeout = settings.commandTimeout();
      byte[] session = connection.transmit(SicctEnvelope.FU_TERMINAL, InitCtSession.EMPTY, timeout);
      if (!InitCtSession.ok(session)) {
        throw pairingError(
            ct,
            ConnectorError.CT_PAIRING_FAILED.exception(ctId + ": INIT CT SESSION " + sw(session)));
      }
      // Step 5: CREATE
      byte[] response =
          connection.transmit(
              SicctEnvelope.FU_TERMINAL,
              TerminalAuthenticate.create(
                  sharedSecret,
                  TerminalAuthenticate.displayMessage(ct.mac(), settings.konnektorHostname())),
              timeout);
      byte[] signature = TerminalAuthenticate.body(response);
      if (signature == null) {
        throw pairingError(
            ct,
            ConnectorError.CT_PAIRING_FAILED.exception(
                ctId + ": EHEALTH TERMINAL AUTHENTICATE CREATE " + sw(response)));
      }
      // Step 6: signature over the shared secret with C.SMKT.AUT
      if (!signatures.verify(smktAut, sharedSecret, signature)) {
        throw pairingError(
            ct,
            ConnectorError.CT_PAIRING_FAILED.exception(
                ctId + ": Signatur des Shared Secrets mit C.SMKT.AUT ungültig"));
      }
      // Steps 7, 8
      ct.pairing(smktAut, sharedSecret);
      ct.correlation(CtObject.Correlation.GEPAIRT);
      connection.transmit(SicctEnvelope.FU_TERMINAL, InitCtSession.CLOSE, timeout);
    } catch (IOException e) {
      throw pairingError(
          ct, ConnectorError.CT_PAIRING_FAILED.exception(ctId + ": " + e.getMessage()).causedBy(e));
    }
    LOGGER.log(
        System.Logger.Level.INFO, "TUC_KON_053: " + ctId + " gepairt, C.SMKT.AUT " + presented);
    // Steps 9, 10
    ct.correlation(CtObject.Correlation.AKTIV);
    connect(ctId);
    return ct;
  }

  /**
   * TUC_KON_050 "Beginne Kartenterminalsitzung" (begin card terminal session, TIP1-A_4545-04) with
   * role = "User": with correlation from "gepairt" (paired) on, TLS, comparison with CT.SMKT_AUT,
   * INIT CT SESSION and VALIDATE; afterwards CT.CONNECTED = Ja, the connection stays open (working
   * connection).
   *
   * @throws ConnectorException 4028 (TLS), 4029 (foreign card terminal certificate or shared
   *     secret)
   */
  public void connect(String ctId) {
    CtObject ct = require(ctId);
    // Step 2
    if (ct.connected()) {
      return;
    }
    // Step 3
    Socket socket;
    try {
      socket = connector.connect(ct.ip().getHostAddress(), ct.tcpPort());
    } catch (IOException e) {
      throw tlsFailure(
          ct, ConnectorError.CT_CONNECT_FAILED.exception(ctId + ": " + e.getMessage()).causedBy(e));
    }
    X509Certificate smktAut = peerCertificate(socket);
    byte[] sharedSecret = ct.sharedSecret();
    // Step 4: low correlation – no functional use
    if (ct.correlation().compareTo(CtObject.Correlation.ZUGEWIESEN) <= 0 || sharedSecret == null) {
      closeQuietly(socket);
      return;
    }
    // Step 5: card terminal certificate against CT.SMKT_AUT, with the same ICCSN as new reference
    // data
    X509Certificate reference = ct.smktAut();
    if (reference != null && smktAut != null && !reference.equals(smktAut)) {
      if (!iccsn(reference).equals(iccsn(smktAut))) {
        closeQuietly(socket);
        ct.correlation(CtObject.Correlation.GEPAIRT);
        throw tlsFailure(
            ct,
            ConnectorError.CT_AUTHENTICATION_FAILED.exception(
                ctId + ": KT-Zertifikat " + iccsn(smktAut) + " statt " + iccsn(reference)));
      }
    }
    if (smktAut != null) {
      ct.pairing(smktAut, sharedSecret);
    }
    SicctConnection connection;
    java.util.concurrent.atomic.AtomicReference<SicctConnection> self =
        new java.util.concurrent.atomic.AtomicReference<>();
    try {
      connection =
          new SicctConnection(
              ctId,
              ct.hostname(),
              socket,
              event -> events.execute(() -> event(ctId, event)),
              (id, name, reason) -> {
                // TIP1-A_4537: only a working connection reports its end, not an aborted setup;
                // first CT/SLOT_FREE per occupied slot, then CT/DISCONNECTED
                if (working.remove(id, self.get())) {
                  ct.connected(false, null);
                  missedHeartbeats.remove(id);
                  events.execute(
                      () -> {
                        Optional.ofNullable(terminals.get(id)).ifPresent(SicctTerminal::clear);
                        log.ctDisconnected(id, name, reason);
                      });
                }
              });
      self.set(connection);
    } catch (IOException e) {
      closeQuietly(socket);
      throw tlsFailure(
          ct, ConnectorError.CT_CONNECT_FAILED.exception(ctId + ": " + e.getMessage()).causedBy(e));
    }
    try {
      Duration timeout = settings.commandTimeout();
      // Step 6
      byte[] challenge = TerminalAuthenticate.newChallenge();
      byte[] session = connection.transmit(SicctEnvelope.FU_TERMINAL, InitCtSession.EMPTY, timeout);
      if (!InitCtSession.ok(session)) {
        throw ConnectorError.CT_CONNECT_FAILED.exception(ctId + ": INIT CT SESSION " + sw(session));
      }
      // Steps 7, 8
      byte[] response =
          connection.transmit(
              SicctEnvelope.FU_TERMINAL, TerminalAuthenticate.validate(challenge), timeout);
      byte[] answer = TerminalAuthenticate.body(response);
      if (answer == null
          || !java.security.MessageDigest.isEqual(
              answer, TerminalAuthenticate.expectedValidation(challenge, sharedSecret))) {
        ct.correlation(CtObject.Correlation.GEPAIRT);
        // SW 6900: the card terminal does not know the key of ID.SAK.AUT (gemSpec_KT SEQ_KT_0002
        // step 3)
        throw ConnectorError.CT_AUTHENTICATION_FAILED.exception(
            ctId
                + ": Nachweis des Shared Secrets fehlgeschlagen (EHEALTH TERMINAL AUTHENTICATE VALIDATE"
                + (answer == null ? " " + sw(response) : "")
                + "), das KT gehört zu einem anderen Pairing");
      }
    } catch (IOException | ConnectorException e) {
      connection.close();
      ConnectorException failure =
          e instanceof ConnectorException ce
              ? ce
              : ConnectorError.CT_CONNECT_FAILED
                  .exception(ctId + ": " + e.getMessage())
                  .causedBy(e);
      throw tlsFailure(ct, failure);
    }
    // Steps 9, 10
    working.put(ctId, connection);
    ct.connected(true, "User");
    Map<String, String> parameters = new LinkedHashMap<>();
    parameters.put("CtID", ctId);
    parameters.put("Hostname", ct.hostname());
    log.write(SystemLog.Type.OP, SystemLog.Severity.INFO, "CT/CONNECTED", parameters);
    LOGGER.log(
        System.Logger.Level.INFO, "TUC_KON_050: " + ctId + " verbunden (VALIDATE bestanden)");
    // Step 11: refresh device data (TUC_KON_055 step 2, TUC_KON_058) and report the inserted cards
    try {
      GetStatus.Terminal status = status(connection);
      ct.status(
          status,
          GetStatus.supported(status.ehealthInterfaceVersion(), settings.supportedVersions()));
      SicctTerminal terminal = terminals.get(ctId);
      if (terminal != null) {
        events.execute(() -> status.slotsUsed().forEach(terminal::inserted));
      }
    } catch (IOException e) {
      LOGGER.log(
          System.Logger.Level.WARNING,
          "TUC_KON_050 Schritt 11 " + ctId + ": GET STATUS " + e.getMessage());
    }
  }

  /** GET STATUS CTS, CTM and DSPLC via {@code connection} (TUC_KON_055 step 2). */
  private GetStatus.Terminal status(SicctConnection connection) throws IOException {
    Duration timeout = settings.commandTimeout();
    byte[] cts =
        connection.transmit(
            SicctEnvelope.FU_TERMINAL, GetStatus.command(GetStatus.CTS_DO), timeout);
    byte[] ctm =
        connection.transmit(
            SicctEnvelope.FU_TERMINAL, GetStatus.command(GetStatus.CTM_DO), timeout);
    byte[] dsplc =
        connection.transmit(
            SicctEnvelope.FU_TERMINAL, GetStatus.command(GetStatus.DSPLC_DO), timeout);
    return GetStatus.parse(cts, ctm, dsplc);
  }

  /**
   * Event message of the working connection (SICCT 1.2.3 §6.2.4.4): {@code 84}/{@code 85} with FU
   * {@code 00nn} are CT/SLOT_IN_USE or CT/SLOT_FREE for slot {@code nn} (TIP1-A_4541-02,
   * TIP1-A_4542-02); KEEP ALIVE ({@code 80}) only counts as a sign of life, TERMINAL SIGN OFF
   * ({@code 81}) announces the end of the connection.
   */
  private void event(String ctId, SicctEnvelope envelope) {
    SicctTerminal terminal = terminals.get(ctId);
    List<Tlv> objects;
    try {
      objects = Tlv.parse(envelope.payload());
    } catch (IOException e) {
      LOGGER.log(System.Logger.Level.WARNING, ctId + ": Ereignisnachricht unlesbar: " + envelope);
      return;
    }
    for (Tlv event : objects) {
      byte[] fu = event.value();
      int slot = fu.length == 2 && fu[0] == 0 ? fu[1] & 0xFF : -1;
      switch (event.tag()) {
        case 0x84 -> {
          if (terminal != null && slot > 0) {
            terminal.inserted(slot);
          }
        }
        case 0x85 -> {
          if (terminal != null && slot > 0) {
            terminal.removed(slot);
          }
        }
        case 0x81 -> LOGGER.log(System.Logger.Level.INFO, ctId + ": TERMINAL SIGN OFF");
        case 0x80 -> LOGGER.log(System.Logger.Level.DEBUG, ctId + ": KEEP ALIVE");
        default -> LOGGER.log(System.Logger.Level.DEBUG, ctId + ": Ereignis " + event);
      }
    }
  }

  /**
   * TIP1-A_4536: keeps every working connection alive with GET STATUS as heartbeat (SICCT 1.2.3
   * §6.2.4.5) as soon as LIANA has not sent a command for CTM_KEEP_ALIVE_INTERVAL, even if the card
   * terminal sends KEEP ALIVE: a card terminal with KEEP ALIVE drops the connection after 120 s
   * without a command. KEEP ALIVE of the card terminal and every response count as signs of life; a
   * heartbeat counts as unanswered if nothing arrived from the card terminal while waiting. After
   * CTM_KEEP_ALIVE_TRY_COUNT unanswered heartbeats the connection ends (TIP1-A_4537).
   */
  private void heartbeat() {
    for (Map.Entry<String, SicctConnection> entry : Map.copyOf(working).entrySet()) {
      String ctId = entry.getKey();
      SicctConnection connection = entry.getValue();
      if (connection.quietFor().compareTo(settings.keepAliveInterval()) < 0) {
        missedHeartbeats.remove(ctId);
      }
      if (connection.sinceLastCommand().compareTo(settings.keepAliveInterval()) < 0) {
        continue;
      }
      try {
        connection.transmit(
            SicctEnvelope.FU_TERMINAL,
            GetStatus.command(GetStatus.CTS_DO),
            settings.keepAliveInterval());
        missedHeartbeats.remove(ctId);
      } catch (de.gematik.liana.kern.terminal.CardTimeoutException e) {
        if (connection.quietFor().compareTo(settings.keepAliveInterval()) < 0) {
          // KEEP ALIVE while waiting: the card terminal is alive (SICCT §6.2.4.5)
          missedHeartbeats.remove(ctId);
          continue;
        }
        int missed = missedHeartbeats.merge(ctId, 1, Integer::sum);
        LOGGER.log(
            System.Logger.Level.WARNING,
            ctId
                + ": Keep-Alive "
                + missed
                + "/"
                + settings.keepAliveTryCount()
                + " unbeantwortet");
        if (missed >= settings.keepAliveTryCount()) {
          connection.close(
              "Keep-Alive: " + missed + " Heartbeats unbeantwortet (CTM_KEEP_ALIVE_TRY_COUNT)");
        }
      } catch (IOException e) {
        // Connection already closed: the connection itself reports its end
      } catch (RuntimeException e) {
        LOGGER.log(System.Logger.Level.WARNING, ctId + ": Keep-Alive gestört", e);
      }
    }
  }

  /**
   * TIP1-A_4538-02: every CTM_SERVICE_DISCOVERY_CYCLE a service enquiry as unicast to every card
   * terminal with CT.CONNECTED = Nein, CT.VALID_VERSION = true and CT.CORRELATION = "aktiv"
   * (active); the service description goes to {@link #announced} like an announced one
   * (TUC_KON_054, TUC_KON_050). Without a response the card terminal stays unconnected until the
   * next cycle.
   */
  private void rediscover() {
    if (discovery == null) {
      return;
    }
    List<CtObject> unconnected;
    synchronized (this) {
      unconnected =
          ctList.values().stream()
              .filter(
                  ct ->
                      !ct.connected()
                          && ct.validVersion()
                          && ct.correlation() == CtObject.Correlation.AKTIV
                          && ct.ip() != null)
              .toList();
    }
    for (CtObject ct : unconnected) {
      try {
        Optional<ServiceDiscovery.Announcement> answer =
            discovery.discover(ct.ip(), settings.discoveryPort(), settings.discoveryTimeout());
        if (answer.isEmpty()) {
          LOGGER.log(
              System.Logger.Level.INFO,
              "TIP1-A_4538-02: "
                  + ct.ctId()
                  + " antwortet nicht auf die "
                  + "Dienstanfrage, nächster Versuch in "
                  + settings.discoveryCycle());
          continue;
        }
        LOGGER.log(
            System.Logger.Level.INFO,
            "TIP1-A_4538-02: " + ct.ctId() + " unverbunden, Dienstanfrage " + "beantwortet");
        announced(answer.get());
      } catch (IOException | RuntimeException e) {
        LOGGER.log(
            System.Logger.Level.WARNING, "TIP1-A_4538-02: " + ct.ctId() + ": " + e.getMessage());
      }
    }
  }

  /** Ends the working connection (CT.CONNECTED = Nein, CT/DISCONNECTED). */
  public void disconnect(String ctId) {
    SicctConnection connection = working.get(ctId);
    if (connection != null) {
      connection.close();
    }
  }

  /**
   * Admin API (decision-4, transient): set the shared secret – the card terminal counts as paired
   * and active and is reconnected – or delete the pairing with {@code null} (correlation
   * "zugewiesen").
   */
  public CtObject sharedSecret(String ctId, byte[] sharedSecret) {
    CtObject ct = require(ctId);
    disconnect(ctId);
    if (sharedSecret == null) {
      ct.pairing(null, null);
      ct.correlation(CtObject.Correlation.ZUGEWIESEN);
      return ct;
    }
    if (sharedSecret.length != TerminalAuthenticate.SHARED_SECRET_LENGTH) {
      throw new IllegalArgumentException(
          "Shared Secret mit " + sharedSecret.length + " statt 16 Byte");
    }
    ct.pairing(ct.smktAut(), sharedSecret);
    ct.correlation(CtObject.Correlation.AKTIV);
    if (ct.validVersion()) {
      connect(ctId);
    }
    return ct;
  }

  /**
   * {@code POST /admin/reset}: pairing and connection of all configured terminals as in the YAML
   * (decision-4).
   */
  public void reset() {
    for (Spec spec : configured) {
      bootPairing(spec);
    }
  }

  /** The working connection of {@code ctId}, as long as CT.CONNECTED = Ja. */
  Optional<SicctConnection> working(String ctId) {
    return Optional.ofNullable(working.get(ctId));
  }

  private CtObject require(String ctId) {
    return ct(ctId).orElseThrow(() -> ConnectorError.INVALID_CT_ID.exception(ctId));
  }

  /** TUC_KON_053 error case: CT/ERROR, delete pairing data, abort with the error code. */
  private ConnectorException pairingError(CtObject ct, ConnectorException e) {
    ct.pairing(null, null);
    LOGGER.log(System.Logger.Level.WARNING, "CT/ERROR " + ct.ctId() + ": " + e.getMessage());
    Map<String, String> parameters = new LinkedHashMap<>();
    parameters.put("CtID", ct.ctId());
    parameters.put("Name", ct.hostname() == null ? "" : ct.hostname());
    parameters.put("Error", String.valueOf(e.error().code()));
    parameters.put("Bedeutung", e.error().text());
    log.write(SystemLog.Type.OP, SystemLog.Severity.ERR, "CT/ERROR", parameters);
    return e;
  }

  /** TUC_KON_050 error case: CT/TLS_ESTABLISHMENT_FAILURE, CT.CONNECTED = Nein. */
  private ConnectorException tlsFailure(CtObject ct, ConnectorException e) {
    ct.connected(false, null);
    LOGGER.log(
        System.Logger.Level.WARNING,
        "CT/TLS_ESTABLISHMENT_FAILURE " + ct.ctId() + ": " + e.getMessage());
    Map<String, String> parameters = new LinkedHashMap<>();
    parameters.put("CtID", ct.ctId());
    parameters.put("Name", ct.hostname() == null ? "" : ct.hostname());
    parameters.put("Error", String.valueOf(e.error().code()));
    parameters.put("Bedeutung", e.error().text());
    log.write(
        SystemLog.Type.OP, SystemLog.Severity.ERR, "CT/TLS_ESTABLISHMENT_FAILURE", parameters);
    return e;
  }

  private static X509Certificate peerCertificate(Socket socket) {
    if (socket instanceof SSLSocket tls) {
      try {
        Certificate[] chain = tls.getSession().getPeerCertificates();
        return chain.length > 0 && chain[0] instanceof X509Certificate x509 ? x509 : null;
      } catch (SSLPeerUnverifiedException e) {
        return null;
      }
    }
    return null;
  }

  /** ICCSN of the gSMC-KT: CN of C.SMKT.AUT (TUC_KON_050 step 5a). */
  private static String iccsn(X509Certificate certificate) {
    String subject = certificate.getSubjectX500Principal().getName();
    for (String part : subject.split(",")) {
      if (part.trim().startsWith("CN=")) {
        return part.trim().substring(3);
      }
    }
    return subject;
  }

  private static void closeQuietly(Socket socket) {
    try {
      socket.close();
    } catch (IOException e) {
      // already closed
    }
  }

  private static String sw(byte[] response) {
    return response.length < 2
        ? hex(response)
        : hex(java.util.Arrays.copyOfRange(response, response.length - 2, response.length));
  }

  /** TUC_KON_054 error case: TUC_KON_256 with CT/CT_ADDING_ERROR, CTM_CT_LIST unchanged. */
  private void addingError(String ip, String hostname, ConnectorException e) {
    LOGGER.log(System.Logger.Level.WARNING, "CT/CT_ADDING_ERROR " + ip + ": " + e.getMessage());
    Map<String, String> parameters = new LinkedHashMap<>();
    parameters.put("IP", ip);
    parameters.put("Name", hostname == null ? "" : hostname);
    parameters.put("Error", String.valueOf(e.error().code()));
    parameters.put("Bedeutung", e.error().text());
    log.write(SystemLog.Type.OP, SystemLog.Severity.ERR, "CT/CT_ADDING_ERROR", parameters);
  }

  private static String hex(byte[] bytes) {
    return java.util.HexFormat.of().withUpperCase().formatHex(bytes);
  }
}

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

import com.fasterxml.jackson.annotation.JsonInclude;
import de.gematik.liana.adapter.fake.FakeTerminal;
import de.gematik.liana.adapter.fake.FakeTerminals;
import de.gematik.liana.adapter.fake.Fault;
import de.gematik.liana.adapter.fake.PinInput;
import de.gematik.liana.adapter.sicct.CtObject;
import de.gematik.liana.adapter.sicct.SicctTerminals;
import de.gematik.liana.cats.CatsTerminals;
import de.gematik.liana.config.LianaConfig;
import de.gematik.liana.crypto.ClientCertificates;
import de.gematik.liana.crypto.CryptoSelfTest;
import de.gematik.liana.crypto.KonnektorTls;
import de.gematik.liana.crypto.ServerIdentities;
import de.gematik.liana.crypto.TlsIdentity;
import de.gematik.liana.crypto.TlsKeys;
import de.gematik.liana.crypto.TrustSpace;
import de.gematik.liana.kern.card.AuthState;
import de.gematik.liana.kern.card.CardData;
import de.gematik.liana.kern.card.CardList;
import de.gematik.liana.kern.card.CardObject;
import de.gematik.liana.kern.card.CardSessions;
import de.gematik.liana.kern.card.CardVersion;
import de.gematik.liana.kern.error.ConnectorException;
import de.gematik.liana.kern.event.Subscriptions;
import de.gematik.liana.kern.event.SystemLog;
import de.gematik.liana.kern.management.ClientSystemBinding;
import de.gematik.liana.kern.management.ComfortSettings;
import de.gematik.liana.kern.management.ManagementSettings;
import de.gematik.liana.kern.management.OperatingState;
import de.gematik.liana.kern.vendor.Deviation;
import de.gematik.liana.kern.vendor.PeerDeviations;
import de.gematik.liana.kern.vendor.Vendor;
import de.gematik.liana.kern.vendor.VendorProfile;
import de.gematik.liana.kern.vsdm.OnlineCheck;
import de.gematik.liana.robot.RobotTerminals;
import de.gematik.liana.tls.KonnektorTlsServer;
import io.quarkus.runtime.annotations.RegisterForReflection;
import jakarta.inject.Singleton;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateEncodingException;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.IntStream;
import org.eclipse.microprofile.config.inject.ConfigProperty;

/**
 * Content of the admin API (decision-4), independent of the HTTP transport in {@link AdminServer}.
 * Changes are volatile, {@link #reset()} restores the YAML state. Unknown CTs, slots and images
 * report {@link IllegalArgumentException}.
 */
@Singleton
public class AdminApi {

  private final LianaConfig config;
  private final FakeTerminals terminals;
  private final SicctTerminals sicctTerminals;
  private final VendorProfile vendor;
  private final PeerDeviations deviations;
  private final SystemLog systemLog;
  private final ManagementSettings settings;
  private final TlsIdentity tlsIdentity;
  private final KonnektorTlsServer tlsServer;
  private final String version;
  private final int konnektorPort;
  private final CatsTerminals cats;
  private final RobotTerminals robot;
  private final Subscriptions subscriptions;
  private final ClientSystemBinding binding;
  private final ServerIdentities identities;
  private final ClientCertificates clientCertificates;
  private final CardList cards;
  private final CardSessions cardSessions;
  private final AuthState authState;
  private final TrustSpace trustSpace;
  private final CryptoSelfTest selfTest;
  private final OnlineCheck onlineCheck;
  private final ComfortSettings comfort;
  private final OperatingState operatingState;

  AdminApi(
      LianaConfig config,
      FakeTerminals terminals,
      SicctTerminals sicctTerminals,
      VendorProfile vendor,
      SystemLog systemLog,
      ManagementSettings settings,
      TlsIdentity tlsIdentity,
      KonnektorTlsServer tlsServer,
      @ConfigProperty(name = "quarkus.application.version") String version,
      @ConfigProperty(name = "quarkus.http.port") int konnektorPort,
      CatsTerminals cats,
      RobotTerminals robot,
      Subscriptions subscriptions,
      ClientSystemBinding binding,
      ServerIdentities identities,
      ClientCertificates clientCertificates,
      CardList cards,
      PeerDeviations deviations,
      CardSessions cardSessions,
      AuthState authState,
      TrustSpace trustSpace,
      CryptoSelfTest selfTest,
      OnlineCheck onlineCheck,
      ComfortSettings comfort,
      OperatingState operatingState) {
    this.operatingState = operatingState;
    this.onlineCheck = onlineCheck;
    this.comfort = comfort;
    this.cards = cards;
    this.cardSessions = cardSessions;
    this.authState = authState;
    this.trustSpace = trustSpace;
    this.selfTest = selfTest;
    this.deviations = deviations;
    this.binding = binding;
    this.identities = identities;
    this.clientCertificates = clientCertificates;
    this.cats = cats;
    this.robot = robot;
    this.subscriptions = subscriptions;
    this.tlsIdentity = tlsIdentity;
    this.tlsServer = tlsServer;
    this.config = config;
    this.terminals = terminals;
    this.sicctTerminals = sicctTerminals;
    this.vendor = vendor;
    this.systemLog = systemLog;
    this.settings = settings;
    this.version = version;
    this.konnektorPort = konnektorPort;
  }

  @RegisterForReflection
  public record Info(
      String product,
      String version,
      String env,
      String vendor,
      boolean strict,
      int konnektorPort,
      int adminPort,
      String terminalMode) {}

  /**
   * Vendor profile (decision-10): {@code vendor} active, {@code boot} from the YAML, target of
   * {@code reset}; also {@code strict} for deviations of the peers (LIANA-126), {@code strictBoot}
   * from the YAML.
   */
  @RegisterForReflection
  public record VendorState(String vendor, String boot, boolean strict, boolean strictBoot) {}

  /** Missing fields stay as they are. */
  @RegisterForReflection
  public record VendorPut(String vendor, Boolean strict) {}

  /** Entry in the Systemprotokoll (TUC_KON_271); {@code time} ISO-8601 in UTC. */
  @RegisterForReflection
  public record LogEntry(
      String time, String type, String severity, String topic, Map<String, String> parameters) {}

  /**
   * A CT: {@code mode} fake or sicct; for eHealth CTs {@code ct} with the attributes of the CT
   * object (TAB_KON_522), {@code null} as long as TUC_KON_054 has not created it. {@code display}:
   * what a fake CT currently shows (RequestCard/EjectCard, LIANA-110; PIN prompt, LIANA-68),
   * otherwise {@code null}. {@code pinScript}: the not yet consumed PIN inputs of a fake CT in the
   * order in which the PIN pad takes them.
   */
  @RegisterForReflection
  @JsonInclude(JsonInclude.Include.NON_NULL)
  public record Terminal(
      String id,
      String mode,
      List<Slot> slots,
      Map<String, Object> ct,
      String display,
      List<PinScriptEntry> pinScript) {}

  /**
   * Entry in the PIN script of a fake CT (LIANA-68, {@link PinInput}) as with {@code kartos
   * terminal} ({@code /api/v1/tui/script}): {@code outcome} correct, wrong, digits (with {@code
   * pin}), cancel, timeout, puk, transport or incomplete; without {@code slotNo} it applies to the
   * next PIN dialog at any slot. On read, {@code pin} is never returned.
   */
  @RegisterForReflection
  @JsonInclude(JsonInclude.Include.NON_NULL)
  public record PinScriptEntry(String outcome, Integer slotNo, String pin) {

    /** The entry; invalid values report {@link IllegalArgumentException}. */
    FakeTerminal.ScriptedPinInput entry() {
      return new FakeTerminal.ScriptedPinInput(
          slotNo, new PinInput(PinInput.Outcome.of(outcome), pin));
    }
  }

  /**
   * A slot; {@code image} and {@code path} are {@code null} if no card is inserted, {@code fault}
   * without a fault. {@code cardType} is CARD.TYPE of the card in CM_CARD_LIST (TUC_KON_001),
   * {@code null} without a card; {@code unknownReason} says why for UNKNOWN (LIANA-121). {@code
   * card}: the whole entry in CM_CARD_LIST (LIANA-149), {@code null} without an opened card.
   */
  @RegisterForReflection
  public record Slot(
      int slot,
      String image,
      String path,
      SlotFault fault,
      String cardType,
      String unknownReason,
      Card card) {}

  /**
   * Entry in CM_CARD_LIST (TUC_KON_001, TAB_KON_531): CARD.CARDHANDLE, CARD.CTID, CARD.SLOTNO,
   * CARD.INSERTTIME (ISO-8601), CARD.TYPE, CARD.ICCSN, CARD.CARDHOLDERNAME, CARD.KVNR (eGK only),
   * CARD.CARDVERSION (parts read), CARD.CERTEXPIRATIONDATE; {@code locked}: reserved by a card
   * session (A_25895). Unreadable values are missing.
   */
  @RegisterForReflection
  @JsonInclude(JsonInclude.Include.NON_NULL)
  public record Card(
      String cardHandle,
      String ctId,
      int slotNo,
      String insertTime,
      String cardType,
      String iccsn,
      String cardHolderName,
      String kvnr,
      Map<String, String> cardVersion,
      String certExpirationDate,
      String unknownReason,
      boolean locked) {}

  /**
   * The known card images (LIANA-98): folders from {@code liana.card-images} and per image name,
   * file, ICCSN.
   */
  @RegisterForReflection
  public record Images(List<String> directories, List<Image> images) {}

  @RegisterForReflection
  @JsonInclude(JsonInclude.Include.NON_NULL)
  public record Image(String name, String file, String iccsn) {}

  /**
   * A subscription (TIP1-A_4594, TAB_KON_572 saveSubscription): SubscriptionID, TerminationTime,
   * Aufrufkontext, EventTo, Topic, Filter and the last delivery attempt via CETP (TUC_KON_256 step
   * 6), if there was one.
   */
  @RegisterForReflection
  @JsonInclude(JsonInclude.Include.NON_NULL)
  public record SubscriptionView(
      String id,
      String terminationTime,
      String mandantId,
      String clientSystemId,
      String workplaceId,
      String userId,
      String eventTo,
      String topic,
      String filter,
      Delivery lastDelivery) {}

  /** Delivery attempt: time, topic of the event, success, and on failure the reason. */
  @RegisterForReflection
  @JsonInclude(JsonInclude.Include.NON_NULL)
  public record Delivery(String time, String topic, boolean delivered, String error) {}

  /**
   * Card sessions: {@code cardSessions} the PoPP sessions (A_25970-01) with expiry of the APDU
   * scenario timer (A_25860-01), {@code verifiedPins} CARDSESSION.AUTHSTATE (TUC_KON_026) per card,
   * mandant and Clientsystem, only PinRef, never a PIN value.
   */
  @RegisterForReflection
  public record Sessions(List<CardSession> cardSessions, List<VerifiedPin> verifiedPins) {}

  @RegisterForReflection
  public record CardSession(
      String sessionId,
      String cardHandle,
      String ctId,
      int slotNo,
      String deadline,
      String timer) {}

  @RegisterForReflection
  public record VerifiedPin(
      String cardHandle, String mandantId, String clientSystemId, String pinRef) {}

  /**
   * Vertrauensraum (TUC_KON_037): header data of the TSL from {@code liana.pki.tsl} and number of
   * imported CAs.
   */
  @RegisterForReflection
  public record Pki(Tsl tsl, int importedCas) {}

  @RegisterForReflection
  public record Tsl(String file, String sequenceNumber, String nextUpdate, int caCount) {}

  /**
   * Management settings independent of the vendor profile (LIANA-55): CARD_SESSION_TIMEOUT in
   * seconds (TAB_KON_554, 10–180) with the value from the YAML, MGM_LU_ONLINE (TAB_KON_658).
   */
  @RegisterForReflection
  public record Settings(long cardSessionTimeout, long cardSessionTimeoutBoot, boolean luOnline) {}

  /** Missing fields stay as they are. */
  @RegisterForReflection
  public record SettingsPut(Long cardSessionTimeout, Boolean luOnline) {}

  /**
   * Betriebszustand for GetResourceInformation (LIANA-187): VPN to the TI and to the SIS, transport
   * network, each {@code true} for online with the time of the last change, plus the error state
   * list (TAB_KON_503).
   */
  @RegisterForReflection
  public record OperatingStateView(
      ConnectionView vpnTi,
      ConnectionView vpnSis,
      ConnectionView transport,
      List<ErrorStateView> errorStates) {}

  @RegisterForReflection
  public record ConnectionView(boolean online, String since) {}

  @RegisterForReflection
  public record ErrorStateView(
      String condition, String severity, String type, boolean value, String validFrom) {}

  /** Missing fields stay as they are; {@code true} is online. */
  @RegisterForReflection
  public record OperatingStatePut(Boolean vpnTi, Boolean vpnSis, Boolean transport) {}

  /**
   * Known deviations of the peers (LIANA-126) and whether LIANA works around them ({@code strict}
   * off).
   */
  @RegisterForReflection
  public record Deviations(boolean strict, List<DeviationView> deviations) {}

  @RegisterForReflection
  public record DeviationView(
      String id, String peer, String spec, String observed, String fallback) {}

  /**
   * Onlineprüfung of the Fachmodul VSDM (LIANA-141): the chain from {@code
   * liana.vsdm.online.sources} and the last result per eGK.
   */
  @RegisterForReflection
  public record VsdmOnlineChecks(
      List<String> sources, boolean strict, boolean online, List<OnlineCheckView> checks) {}

  /**
   * Last check of an eGK: responding stage ({@code spec} = spec fallback), Prüfungsnachweis
   * (Prüfungsnachweis: result, ErrorCode, Prüfziffer Base64) and why the stages before it did not
   * respond.
   */
  @RegisterForReflection
  public record OnlineCheckView(
      String time,
      String cardHandle,
      String iccsn,
      String source,
      int ergebnis,
      Integer errorCode,
      String pruefziffer,
      String detail,
      List<String> skipped) {}

  /** {@code POST /admin/ct-discovery}: optionally the CT, without it all configured eHealth CTs. */
  @RegisterForReflection
  public record DiscoveryPost(String ctId) {}

  /**
   * Fault of a slot (LIANA-41, {@link Fault}): {@code type} status-word with {@code statusWord},
   * response with {@code response} (LIANA-67), io-error or delay with {@code delayMs}; optionally
   * {@code commandPrefix} (hex) and {@code count}.
   */
  @RegisterForReflection
  @JsonInclude(JsonInclude.Include.NON_NULL)
  public record SlotFault(
      String type,
      String statusWord,
      String response,
      Long delayMs,
      String commandPrefix,
      Integer count) {

    static SlotFault of(Fault fault) {
      return new SlotFault(
          fault.type().value(),
          fault.statusWord(),
          fault.response(),
          fault.delay() == null ? null : fault.delay().toMillis(),
          fault.commandPrefix(),
          fault.count());
    }

    /** The fault; invalid values report {@link IllegalArgumentException}. */
    Fault fault() {
      if (type == null) {
        throw new IllegalArgumentException(
            "type fehlt, erwartet status-word, response, io-error oder delay");
      }
      return new Fault(
          Fault.Type.of(type),
          statusWord,
          response,
          delayMs == null ? null : Duration.ofMillis(delayMs),
          commandPrefix,
          count);
    }
  }

  @RegisterForReflection
  public record SlotPut(String image) {}

  /**
   * {@code POST /admin/terminals/{id}/pairing}: optionally the confirmed fingerprint of C.SMKT.AUT.
   */
  @RegisterForReflection
  public record PairingPost(String fingerprint) {}

  /** {@code PUT /admin/terminals/{id}/pairing}: shared secret as hex. */
  @RegisterForReflection
  public record PairingPut(String sharedSecret) {}

  @RegisterForReflection
  public record Infomodel(
      List<String> mandants,
      List<String> clientSystems,
      List<Workplace> workplaces,
      List<SmbVerwaltet> smbVerwaltet) {}

  /** SM-B_Verwaltet: SMC-B (ICCSN) and its mandants; empty means every SMC-B for every mandant. */
  @RegisterForReflection
  public record SmbVerwaltet(String iccsn, List<String> mandants) {}

  @RegisterForReflection
  public record Workplace(
      String id, List<String> mandants, List<String> clientSystems, List<String> terminals) {}

  /**
   * TLS of the connector interface (LIANA-58, TAB_KON_506-01), read-only: ANCL_TLS_MANDATORY,
   * ANCL_CAUT_MANDATORY, HTTPS port, server certificate with SHA-256 fingerprint (A_24484) and
   * ANCL_CCERT_LIST (Clientsystem, subject, method), each in the current state (KMS, LIANA-65);
   * plus ANCL_DVD_OPEN, TLS_USE_ECC_FOR_CS, the choice of the software key as server identity, and
   * protocol, cipher suites and curves (A_17124-03, LIANA-149).
   */
  @RegisterForReflection
  public record Tls(
      boolean tlsMandatory,
      boolean clientAuthMandatory,
      boolean serverTls,
      int port,
      String certificate,
      String fingerprint,
      List<String> clientCertificates,
      boolean dvdOpen,
      boolean eccForClientSystems,
      boolean serverSoftwareKey,
      String protocol,
      List<String> cipherSuites,
      List<String> namedGroups) {}

  /**
   * Client configuration according to {@code support/kon/kon-format.md} v1.0.0 (decision-5), fields
   * in the order of §8; {@code trustStore} is the chain of the server identity (base64 DER) with
   * which clients verify LIANA.
   */
  @RegisterForReflection
  @JsonInclude(JsonInclude.Include.NON_NULL)
  public record Kon(
      String version,
      String url,
      boolean rewriteServiceEndpoints,
      String mandantId,
      String workplaceId,
      String clientSystemId,
      KonCredentials credentials,
      String env,
      List<String> trustStore) {}

  /**
   * {@code credentials} (kon-format §6): {@code basic} with {@code username}/{@code password},
   * {@code pkcs12} with {@code data} (container base64) and {@code password}; fields not configured
   * are missing from the export.
   */
  @RegisterForReflection
  @JsonInclude(JsonInclude.Include.NON_NULL)
  public record KonCredentials(String type, String username, String data, String password) {}

  Info info(int adminPort) {
    return new Info(
        "LIANA",
        version,
        config.env().value(),
        vendor.vendor().value(),
        deviations.strict(),
        konnektorPort,
        adminPort,
        LianaConfig.Mode.of(config.infrastructure().terminals()).value());
  }

  List<Terminal> terminals() {
    List<Terminal> all =
        new java.util.ArrayList<>(terminals.terminals().stream().map(this::terminal).toList());
    sicctTerminals.terminals().forEach(kt -> all.add(sicct(kt.id())));
    return all;
  }

  Terminal terminal(String id) {
    if (isSicct(id)) {
      return sicct(id);
    }
    return terminal(terminals.terminal(id));
  }

  /**
   * CTM_CT_LIST: all eHealth CTs with a CT object, including those only announced (correlation
   * „bekannt“).
   */
  List<Map<String, Object>> ctList() {
    return sicctTerminals.ctList().stream().map(CtObject::snapshot).toList();
  }

  private boolean isSicct(String id) {
    return sicctTerminals.terminals().stream().anyMatch(kt -> kt.id().equals(id));
  }

  private Terminal sicct(String id) {
    var ct = sicctTerminals.ct(id);
    int slots = ct.map(CtObject::slotCount).orElse(0);
    return new Terminal(
        id,
        "sicct",
        IntStream.rangeClosed(1, slots)
            .mapToObj(slot -> slot(slot, null, null, null, cards.card(id, slot)))
            .toList(),
        ct.map(CtObject::snapshot).orElse(null),
        null,
        null);
  }

  /**
   * TUC_KON_053 „Paire Kartenterminal“; the administrator confirms {@code fingerprint} (SHA-256 of
   * C.SMKT.AUT); without it the presented one counts as confirmed. Afterwards the CT is active and
   * connected (TUC_KON_050).
   */
  Terminal pair(String id, PairingPost request) {
    sicctTerminals.pair(id, request == null ? null : request.fingerprint());
    return sicct(id);
  }

  /**
   * Sets CT.SHARED_SECRET volatilely (decision-4): the CT counts as paired, TUC_KON_050 checks it
   * via VALIDATE.
   */
  Terminal putPairing(String id, PairingPut request) {
    if (request == null
        || request.sharedSecret() == null
        || !request.sharedSecret().matches("[0-9A-Fa-f]{32}")) {
      throw new IllegalArgumentException(
          "sharedSecret: 32 Hex-Zeichen (16 Byte, DO_KT_0003) erwartet");
    }
    sicctTerminals.sharedSecret(id, java.util.HexFormat.of().parseHex(request.sharedSecret()));
    return sicct(id);
  }

  /** Deletes the pairing: correlation „zugewiesen“, connection closed. */
  Terminal deletePairing(String id) {
    sicctTerminals.sharedSecret(id, null);
    return sicct(id);
  }

  /**
   * Cards and faults of an eHealth CT are controlled by the kartos control interface, not LIANA
   * (decision-12).
   */
  private void requireFake(String id) {
    if (isSicct(id)) {
      throw new UnsupportedOperationException(
          id
              + " ist ein eHealth-KT (SICCT): Karten und Störungen über die "
              + "Steuerschnittstelle von kartos terminal (/api/v1/slots/{slotNo}/card, /fault), in LIANA nicht "
              + "umgesetzt");
    }
  }

  Terminal putCard(String id, int slot, SlotPut card) {
    requireFake(id);
    terminals.put(id, slot, card.image());
    return terminal(id);
  }

  Terminal removeCard(String id, int slot) {
    requireFake(id);
    terminals.remove(id, slot);
    return terminal(id);
  }

  Terminal putFault(String id, int slot, Fault fault) {
    requireFake(id);
    terminals.terminal(id).fault(slot, fault);
    return terminal(id);
  }

  Terminal removeFault(String id, int slot) {
    requireFake(id);
    terminals.terminal(id).clearFault(slot);
    return terminal(id);
  }

  /** Appends PIN inputs to the PIN script of the CT. */
  Terminal postPinScript(String id, List<FakeTerminal.ScriptedPinInput> entries) {
    requireFake(id);
    terminals.terminal(id).enterPin(entries);
    return terminal(id);
  }

  /**
   * Discards the PIN script of the CT; without an entry the PIN pad types the configured PIN again.
   */
  Terminal deletePinScript(String id) {
    requireFake(id);
    terminals.terminal(id).clearPinScript();
    return terminal(id);
  }

  Infomodel infomodel() {
    var model = config.infomodel();
    return new Infomodel(
        model.mandants(),
        model.clientSystems(),
        model.workplaces().stream()
            .map(wp -> new Workplace(wp.id(), wp.mandants(), wp.clientSystems(), wp.terminals()))
            .toList(),
        model.smbVerwaltet().orElse(List.of()).stream()
            .map(smb -> new SmbVerwaltet(smb.iccsn(), smb.mandants()))
            .toList());
  }

  /**
   * {@code .kon} for a Clientsystem: Aufrufkontext from the Informationsmodell (first workplace
   * with the Clientsystem, its first mandant), connection and credentials from {@code
   * liana.kon-export}.
   */
  Kon konConfig(String clientSystemId) {
    var model = config.infomodel();
    if (!model.clientSystems().contains(clientSystemId)) {
      throw new IllegalArgumentException("unbekanntes Clientsystem '" + clientSystemId + "'");
    }
    var workplace =
        model.workplaces().stream()
            .filter(wp -> wp.clientSystems().contains(clientSystemId) && !wp.mandants().isEmpty())
            .findFirst()
            .orElseThrow(
                () ->
                    new IllegalArgumentException(
                        "Clientsystem '"
                            + clientSystemId
                            + "' ist keinem Arbeitsplatz mit Mandant zugeordnet"));
    var export = config.konExport();
    var credentials = export.credentials();
    return new Kon(
        "1.0.0",
        export.url(),
        export.rewriteServiceEndpoints(),
        workplace.mandants().getFirst(),
        workplace.id(),
        clientSystemId,
        new KonCredentials(
            credentials.type(),
            credentials.username().orElse(null),
            credentials.keystore().map(AdminApi::base64).orElse(null),
            credentials.password().orElse(null)),
        config.env().value(),
        tlsIdentity.chain().stream().map(AdminApi::base64).toList());
  }

  private static String base64(Path file) {
    try {
      return Base64.getEncoder().encodeToString(Files.readAllBytes(file));
    } catch (IOException e) {
      throw new UncheckedIOException("PKCS#12 für den .kon-Export nicht lesbar: " + file, e);
    }
  }

  private static String base64(java.security.cert.X509Certificate certificate) {
    try {
      return Base64.getEncoder().encodeToString(certificate.getEncoded());
    } catch (CertificateEncodingException e) {
      throw new IllegalStateException(e);
    }
  }

  VendorState vendor() {
    return new VendorState(
        vendor.vendor().value(),
        Vendor.of(config.vendor()).value(),
        deviations.strict(),
        deviations.boot());
  }

  /**
   * Switches profile and {@code strict} volatilely; an unknown vendor or a body without both fields
   * reports {@link IllegalArgumentException}, and then everything stays as it is.
   */
  VendorState putVendor(VendorPut put) {
    if (put.vendor() == null && put.strict() == null) {
      throw new IllegalArgumentException("vendor oder strict erwartet");
    }
    Vendor next = put.vendor() == null ? null : Vendor.of(put.vendor());
    if (next != null) {
      vendor.switchTo(next);
    }
    if (put.strict() != null) {
      deviations.setStrict(put.strict());
    }
    return vendor();
  }

  /** Systemprotokoll with {@code from <= time <= to}; {@code null} means unbounded. */
  List<LogEntry> log(Instant from, Instant to) {
    return systemLog.entries(from, to).stream()
        .map(
            e ->
                new LogEntry(
                    e.time().toString(),
                    e.type().value(),
                    e.severity().value(),
                    e.topic(),
                    e.parameters()))
        .toList();
  }

  /**
   * Current state as set by the KMS (LIANA-65); the certificate is the identity of the next
   * handshake.
   */
  Tls tls() {
    ClientSystemBinding.State state = binding.state();
    TlsIdentity current = identities.current();
    List<String> clients =
        clientCertificates.all().stream()
            .map(
                e ->
                    e.clientSystemId()
                        + ": "
                        + e.certificate().getSubjectX500Principal().getName()
                        + " ("
                        + TlsKeys.describe(e.certificate().getPublicKey())
                        + ")")
            .toList();
    return new Tls(
        state.tlsMandatory(),
        state.authentication() != ClientSystemBinding.Authentication.NONE,
        true,
        tlsServer.port(),
        current.certificate().getSubjectX500Principal().getName(),
        current.fingerprint(),
        clients,
        state.dvdOpen(),
        state.eccForClientSystems(),
        state.serverSoftwareKey(),
        KonnektorTls.protocol(),
        KonnektorTls.cipherSuites(),
        KonnektorTls.namedGroups());
  }

  /** CM_CARD_LIST in the order of opening. */
  List<Card> cards() {
    return cards.cards().stream().map(this::card).toList();
  }

  private Card card(CardObject card) {
    CardData data = card.data();
    return new Card(
        card.cardHandle(),
        card.ctId(),
        card.slotNo(),
        card.insertTime().toString(),
        data.type().value(),
        data.iccsn(),
        data.cardHolderName(),
        data.kvnr(),
        versions(data.version()),
        data.certExpirationDate() == null ? null : data.certExpirationDate().toString(),
        card.unknownReason(),
        cardSessions.locked(card.cardHandle()));
  }

  private static Map<String, String> versions(CardVersion version) {
    if (version == null) {
      return null;
    }
    Map<String, String> parts = new LinkedHashMap<>();
    put(parts, "cos", version.cos());
    put(parts, "objectSystem", version.objectSystem());
    put(parts, "logging", version.logging());
    put(parts, "atr", version.atr());
    put(parts, "gdo", version.gdo());
    put(parts, "keyInfo", version.keyInfo());
    return parts;
  }

  private static void put(Map<String, String> parts, String name, CardVersion.Version version) {
    if (version != null) {
      parts.put(name, version.toString());
    }
  }

  Images images() {
    var index = terminals.images();
    return new Images(
        index.directories().stream().map(Path::toString).toList(),
        index.images().stream()
            .map(
                image ->
                    new Image(image.name(), image.file().toString(), image.iccsn().orElse(null)))
            .toList());
  }

  List<SubscriptionView> subscriptions() {
    return subscriptions.all().stream()
        .map(
            s ->
                new SubscriptionView(
                    s.id(),
                    s.terminationTime().toString(),
                    s.context().mandantId(),
                    s.context().clientSystemId(),
                    s.context().workplaceId(),
                    s.context().userId(),
                    s.eventTo(),
                    s.topic(),
                    s.filter(),
                    subscriptions
                        .lastDelivery(s.id())
                        .map(
                            d ->
                                new Delivery(
                                    d.time().toString(), d.topic(), d.delivered(), d.error()))
                        .orElse(null)))
        .toList();
  }

  Sessions sessions() {
    return new Sessions(
        cardSessions.open().stream()
            .map(
                s ->
                    new CardSession(
                        s.sessionId(),
                        s.cardHandle(),
                        s.ctId(),
                        s.slotNo(),
                        s.deadline().toString(),
                        s.timer()))
            .toList(),
        authState.verified().stream()
            .map(
                v -> new VerifiedPin(v.cardHandle(), v.mandantId(), v.clientSystemId(), v.pinRef()))
            .toList());
  }

  Pki pki() {
    TrustSpace.TslInfo tsl = trustSpace.tsl();
    return new Pki(
        new Tsl(tsl.source(), tsl.sequenceNumber(), tsl.nextUpdate(), tsl.caCount()),
        trustSpace.importedCount());
  }

  Settings settings() {
    return new Settings(
        settings.sessionTimeout().toSeconds(),
        settings.bootSessionTimeout().toSeconds(),
        settings.online());
  }

  /**
   * Sets CARD_SESSION_TIMEOUT and/or MGM_LU_ONLINE volatilely like the KMS; without both fields or
   * outside 10–180 s {@link IllegalArgumentException}, and then everything stays as it is. A change
   * of MGM_LU_ONLINE reports MGM/LU_CHANGED/LU_ONLINE (TAB_KON_658).
   */
  Settings putSettings(SettingsPut put) {
    if (put.cardSessionTimeout() == null && put.luOnline() == null) {
      throw new IllegalArgumentException("cardSessionTimeout oder luOnline erwartet");
    }
    if (put.cardSessionTimeout() != null) {
      settings.sessionTimeout(Duration.ofSeconds(put.cardSessionTimeout()));
    }
    if (put.luOnline() != null) {
      settings.online(put.luOnline());
    }
    return settings();
  }

  OperatingStateView operatingState() {
    synchronized (operatingState) {
      return new OperatingStateView(
          connection(operatingState.vpnTi()),
          connection(operatingState.vpnSis()),
          connection(operatingState.transport()),
          operatingState.errorStates().stream()
              .map(
                  e ->
                      new ErrorStateView(
                          e.condition(),
                          e.severity().value(),
                          e.type().value(),
                          e.value(),
                          e.validFrom().toString()))
              .toList());
    }
  }

  /**
   * Sets the connection states volatilely; without a field {@link IllegalArgumentException}.
   * Changed error states are reported by TUC_KON_256 OPERATIONAL_STATE/$EC (TIP1-A_4512-06).
   */
  OperatingStateView putOperatingState(OperatingStatePut put) {
    if (put.vpnTi() == null && put.vpnSis() == null && put.transport() == null) {
      throw new IllegalArgumentException("vpnTi, vpnSis oder transport erwartet");
    }
    operatingState.set(put.vpnTi(), put.vpnSis(), put.transport());
    return operatingState();
  }

  private static ConnectionView connection(OperatingState.Connection connection) {
    return new ConnectionView(connection.online(), connection.timestamp().toString());
  }

  VsdmOnlineChecks vsdmOnlineChecks() {
    return new VsdmOnlineChecks(
        onlineCheck.sources(),
        deviations.strict(),
        settings.online(),
        onlineCheck.last().stream()
            .map(
                o -> {
                  var pn = o.pruefungsnachweis();
                  return new OnlineCheckView(
                      o.time().toString(),
                      o.cardHandle(),
                      o.iccsn(),
                      o.source(),
                      pn.ergebnis().code(),
                      pn.errorCode(),
                      pn.pruefziffer() == null
                          ? null
                          : Base64.getEncoder().encodeToString(pn.pruefziffer()),
                      o.detail(),
                      o.skipped());
                })
            .toList());
  }

  Deviations deviations() {
    return new Deviations(
        deviations.strict(),
        Arrays.stream(Deviation.values())
            .map(d -> new DeviationView(d.name(), d.peer(), d.spec(), d.observed(), d.fallback()))
            .toList());
  }

  /**
   * A crypto self-test (LIANA-4); an unknown check {@link IllegalArgumentException} with the known
   * ones.
   */
  CryptoSelfTest.Result selfTest(String check) {
    return selfTest
        .run(check)
        .orElseThrow(
            () ->
                new IllegalArgumentException(
                    "unbekannter Selbsttest '" + check + "', bekannt: " + CryptoSelfTest.CHECKS));
  }

  /**
   * Re-runs TUC_KON_054 ManuallyAdded (LIANA-149): for {@code ctId} with its error, without it for
   * all configured eHealth CTs, whose errors then only appear in the Systemprotokoll
   * (CT/CT_ADDING_ERROR). The response is CTM_CT_LIST.
   */
  List<Map<String, Object>> discover(DiscoveryPost request) {
    if (request != null && request.ctId() != null) {
      sicctTerminals.discover(request.ctId());
    } else {
      for (var spec : sicctTerminals.configured()) {
        try {
          sicctTerminals.discover(spec.ctId());
        } catch (ConnectorException e) {
          // recorded as CT/CT_ADDING_ERROR in the Systemprotokoll
        }
      }
    }
    return ctList();
  }

  /**
   * Subscriptions first: the cards from the YAML do not go to Ereignissenken from before the reset
   * (TIP1-A_4613).
   */
  void reset() {
    subscriptions.clear();
    onlineCheck.clear();
    cats.reset();
    robot.reset();
    terminals.reset();
    sicctTerminals.reset();
    vendor.reset();
    deviations.reset();
    settings.reset();
    operatingState.reset();
    comfort.reset();
    binding.reset();
    identities.reset();
    clientCertificates.reset();
    systemLog.clear();
  }

  private Terminal terminal(FakeTerminal kt) {
    return new Terminal(
        kt.id(),
        "fake",
        IntStream.rangeClosed(1, kt.slots())
            .mapToObj(
                slot -> {
                  SlotFault fault = kt.fault(slot).map(SlotFault::of).orElse(null);
                  Optional<CardObject> card = cards.card(kt.id(), slot);
                  return kt.image(slot)
                      .map(image -> slot(slot, imageName(image), image.toString(), fault, card))
                      .orElse(slot(slot, null, null, fault, card));
                })
            .toList(),
        null,
        kt.display().orElse(null),
        kt.pinScript().stream()
            .map(e -> new PinScriptEntry(e.input().outcome().value(), e.slotNo(), null))
            .toList());
  }

  private Slot slot(
      int slot, String image, String path, SlotFault fault, Optional<CardObject> card) {
    return new Slot(
        slot,
        image,
        path,
        fault,
        card.map(c -> c.data().type().value()).orElse(null),
        card.map(CardObject::unknownReason).orElse(null),
        card.map(this::card).orElse(null));
  }

  private static String imageName(Path image) {
    return image.getFileName().toString().replaceFirst("\\.xml$", "");
  }
}

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

import de.gematik.liana.adapter.soap.RequestValidation;
import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;
import java.net.URI;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * Boot configuration {@code liana.*} from {@code application.yaml}. Invalid values (e.g. {@code
 * env}) abort the startup already during mapping, cross-references are checked by {@link
 * ConfigCheck}.
 */
@ConfigMapping(prefix = "liana")
public interface LianaConfig {

  /** Environment, goes into the {@code .kon} export. */
  Env env();

  /**
   * Vendor profile (decision-10): {@code neutral}, {@code KOCO}, {@code RISE}, {@code SECUNET},
   * {@code EHEX} or {@code CGM}. Mapped as text so that {@link ConfigCheck} reports an unknown
   * value with the allowed ones.
   */
  @WithDefault("neutral")
  String vendor();

  /**
   * Do not tolerate known spec deviations of the peers (LIANA-126, {@code
   * kern.vendor.PeerDeviations}): {@code false} works around them and logs a warning, {@code true}
   * makes the operation fail.
   */
  @WithDefault("false")
  boolean strict();

  Admin admin();

  Kms kms();

  Tls tls();

  Infomodel infomodel();

  /** Card terminal service: CTM parameters (LIANA-76). */
  Ctm ctm();

  Card card();

  /**
   * Betriebszustand for GetResourceInformation (LIANA-187, {@code kern.management.OperatingState}):
   * boot state of the connections, changeable volatilely via {@code PUT /admin/operating-state}.
   */
  OperatingState operatingState();

  Pki pki();

  Trace trace();

  /**
   * Folders with card images (LIANA-98), indexed at startup by file name and ICCSN; values in the
   * infrastructure object, the admin API and CATS select from them (CardImages).
   */
  List<Path> cardImages();

  /**
   * Cards and identities in the structure of the TI (LIANA-98, decision-14): connector with gSMC-K,
   * card terminals with slots. The only place where LIANA configures identities.
   */
  Infrastructure infrastructure();

  KonExport konExport();

  /** CATS REST interface for tiger-cats-extensions (LIANA-67). */
  Cats cats();

  /** Robot interface for tiger-ehealth-kt-e2e (LIANA-106), off without {@code port}. */
  Robot robot();

  /** System information service: delivery of events via CETP (LIANA-59). */
  Events events();

  /**
   * the Fachmodul VSDM: parameters according to Tab_FM_VSDM_14 and the sources of the Onlineprüfung
   * (LIANA-141).
   */
  Vsdm vsdm();

  /** SOAP interface of the base services and Fachmodule. */
  Soap soap();

  enum Env {
    RU,
    TU,
    PU;

    /** Spelling in YAML and {@code .kon}. */
    public String value() {
      return name().toLowerCase(Locale.ROOT);
    }
  }

  interface Admin {
    int port();

    /** {@code GET /admin/events} (server-sent events, LIANA-150). */
    AdminEvents events();
  }

  interface AdminEvents {
    /** Events in the ring buffer for resumption with Last-Event-ID. */
    @WithDefault("1000")
    int buffer();

    /** Concurrent streams; beyond that 503. */
    @WithDefault("16")
    int maxStreams();

    /** Interval of the heartbeat comment, so that proxies do not close open streams. */
    @WithDefault("15s")
    Duration heartbeat();
  }

  /**
   * CATS REST interface (LIANA-67): per CATS terminal its own port, as with CATS one terminal per
   * base URL. The slots of the CATS terminal are the slots of the assigned LIANA CT.
   */
  /** System information service (gemSpec_Kon 4.1.6, LIANA-59). */
  interface Events {
    /** EVT_MAX_TRY (TAB_KON_580): consecutive failed deliveries until auto-unsubscribe. */
    @WithDefault("3")
    int maxTry();

    /** Time limit for connection setup and TLS handshake to the Ereignissenke. */
    @WithDefault("5s")
    Duration connectTimeout();

    /**
     * {@code host:port} to which LIANA opens every CETP connection instead of the EventTo of the
     * subscription, e.g. a Tiger proxy in front of the Ereignissenke of a Primärsystem (LIANA-183);
     * the event itself stays unchanged.
     */
    java.util.Optional<String> redirect();
  }

  interface Cats {
    java.util.Optional<List<CatsTerminal>> terminals();
  }

  interface Soap {
    /**
     * Validation of incoming requests against XSD and WSDL (LIANA-48): {@code off}, {@code log}
     * (default, violations as warning) or {@code reject} (4000 or SOAP-ENV:Client).
     */
    @WithDefault("log")
    RequestValidation.Mode requestValidation();
  }

  /** the Fachmodul VSDM ([gemSpec_FM_VSDM] 4.8). MANDANT_SMB is {@code infomodel.smb-verwaltet}. */
  interface Vsdm {
    /** TIMEOUT_VSDM: response time of a Fachdienst. */
    @WithDefault("10s")
    Duration timeout();

    /** MAXTIME_VSDM: processing time of the Onlineprüfung of ReadVSD (4.10). */
    @WithDefault("30s")
    Duration maxTime();

    Online online();
  }

  /**
   * Onlineprüfung of ReadVSD with PerformOnlineCheck=true (LIANA-141, {@code
   * kern.vsdm.OnlineCheck}).
   */
  interface Online {
    /**
     * Chain of sources in this order: {@code ufs}, {@code fixed}. Empty (default): only the spec
     * fallback, Prüfungsnachweis with result 3. Mapped as text so that {@link ConfigCheck} reports
     * unknown names.
     */
    Optional<List<String>> sources();

    Ufs ufs();
  }

  /** Stage {@code ufs}: GetUpdateFlags to UFS endpoints. */
  interface Ufs {
    /** Ordered endpoints; with {@code provider-id} only for eGKs of this ProviderID (C.CH.AUT). */
    Optional<List<UfsEndpoint>> endpoints();

    /** Connection setup (TCP and TLS) per endpoint. */
    @WithDefault("2s")
    Duration connectTimeout();

    /** How long an endpoint is skipped after it was unreachable. */
    @WithDefault("60s")
    Duration retryAfter();
  }

  interface UfsEndpoint {
    /**
     * {@code http://} without, {@code https://} with client authentication by the SM-B
     * (TUC_KON_110).
     */
    URI url();

    /** ProviderID (nine digits, OU in C.CH.AUT); without it the endpoint applies to all eGKs. */
    Optional<String> providerId();
  }

  /**
   * Robot interface (LIANA-106): replaces the card robot of the eHealth CT lab (Removinator with
   * eight compartments per side, plug per terminal, stylus on the PIN pad). Robot terminal n is
   * {@code terminals[n-1]}; the eGK sits in slot 1, the professional card (HBA, SMC-B) in slot 2.
   */
  interface Robot {
    /** HTTP port; without a port the interface does not start, 0 picks a free port. */
    Optional<Integer> port();

    /**
     * CT.CTID of the robot terminals 1, 2, …: fake CTs or eHealth CTs with the control interface of
     * kartos terminal ({@link Terminal#control()}, LIANA-112.15).
     */
    List<String> terminals();

    /**
     * The PIN pads of the robot terminals wait for the PIN input of the robot (LIANA-68,
     * LIANA-112.15): the suites first call the connector operation and then send the input. Fake
     * CT: mode await; eHealth CT: LIANA waits before PERFORM VERIFICATION or MODIFY VERIFICATION
     * DATA and puts the input into the PIN script of kartos. Without the switch the PIN pad types
     * the configured PIN immediately.
     */
    @WithDefault("false")
    boolean awaitPin();

    /**
     * Removinator compartments of the eGK side: {@code SC1}…{@code SC8} → image (file name, ICCSN
     * or path).
     */
    Map<String, String> egk();

    /** Removinator compartments of the professional card side: {@code SC1}…{@code SC8} → image. */
    Map<String, String> berechtigt();
  }

  interface CatsTerminal {
    /**
     * Additional HTTP listener only for this terminal, as up to 0.6 (CATS default 9998); if not
     * set, only under {@code /cats/<terminal>} on the management port (decision-017, LIANA-147). 0
     * picks a free port.
     */
    Optional<Integer> port();

    /** CT.CTID of the LIANA CT the endpoints act on. */
    String terminal();

    /**
     * Delay between {@code POST /config/card/insert} and the insert: CATS confirms the call
     * immediately, with the real connector the event only comes later via CT and SICCT.
     * Konnektor-QES calls further CATS endpoints in between and then waits for a new CARD/INSERTED
     * (KUC_1601_010). Default 0: immediately.
     */
    @WithDefault("0s")
    Duration insertDelay();
  }

  /**
   * Managementschnittstelle (KMS) of the vendor profile (LIANA-62), under {@code /rest/mgmt} on the
   * management port (decision-017).
   */
  interface Kms {
    /**
     * Additional HTTPS listener only for the KMS, as up to 0.6 on 8500; closed if not set
     * (LIANA-146).
     */
    Optional<Integer> port();

    /**
     * Access to the KMS (EHEX: POST …/ak/konten/login), like {@code kmsUsername}/{@code
     * kmsPassword} of the suites.
     */
    String username();

    String password();
  }

  /**
   * TLS of the connector interface (LIANA-58): own HTTPS port next to HTTP (ANCL_TLS_MANDATORY
   * Disabled), server identity and client authentication (TAB_KON_506-01).
   */
  interface Tls {
    /** HTTPS port of the connector interface; 0 picks a free port. */
    int port();

    /** How clients reach the HTTPS port: base of {@code EndpointTLS} in {@code connector.sds}. */
    String url();

    /**
     * Boot state of TLS_USE_ECC_FOR_CS (EHEX KMS): ECC variant of ID.AK.AUT instead of RSA ({@link
     * GsmcK}).
     */
    @WithDefault("true")
    boolean eccForClientSystems();

    /** ANCL_TLS_MANDATORY (TIP1-A_4515): without TLS LIANA rejects calls of the Clientsysteme. */
    @WithDefault("false")
    boolean mandatory();

    /** ANCL_DVD_OPEN: {@code connector.sds} stays reachable over HTTP with ANCL_TLS_MANDATORY. */
    @WithDefault("true")
    boolean dvdOpen();

    /**
     * ANCL_CAUT_MANDATORY with ANCL_CAUT_MODE CERTIFICATE: no TLS without a certificate from {@link
     * #clientCerts()}.
     */
    @WithDefault("false")
    boolean clientAuth();

    /** ANCL_CCERT_LIST: PEM files with the certificates of the Clientsysteme. */
    Optional<List<Path>> clientCerts();
  }

  /** Informationsmodell (Aufrufkontext, TUC_KON_000). */
  interface Infomodel {
    List<String> mandants();

    List<String> clientSystems();

    List<Workplace> workplaces();

    /**
     * SM-B_Verwaltet (TUC_KON_000 rule R7, A_23545-01): SMC-Bs per ICCSN with their mandants.
     * Without an entry every inserted SMC-B counts as SM-B_Verwaltet of every mandant; with entries
     * a foreign SMC-B yields 4009, an SMC-B of another mandant 4013.
     */
    Optional<List<SmbVerwaltet>> smbVerwaltet();
  }

  interface SmbVerwaltet {
    String iccsn();

    List<String> mandants();
  }

  interface Workplace {
    String id();

    List<String> mandants();

    List<String> clientSystems();

    /** CT.CTIDs from {@code liana.infrastructure.terminals}. */
    List<String> terminals();
  }

  /** Card engine (decision-7) and card service. */
  interface OperatingState {
    /**
     * VPNTIStatus online; offline sets EC_No_VPN_TI_Connection with MGM_LU_ONLINE=Enabled
     * (A_17085).
     */
    @WithDefault("true")
    boolean vpnTiOnline();

    /**
     * VPNSISStatus online; LIANA has no SIS, hence offline like the reference connector in the PS
     * lab.
     */
    @WithDefault("false")
    boolean vpnSisOnline();

    /**
     * Services in the transport network reachable; offline sets EC_No_Online_Connection (A_17087).
     */
    @WithDefault("true")
    boolean transportOnline();
  }

  interface Card {
    Path kartosBin();

    /**
     * CARD_SESSION_TIMEOUT (TAB_KON_554): deadline until the first SecureSendAPDU of a card
     * session, 10–180 s.
     */
    @WithDefault("120s")
    Duration sessionTimeout();

    /**
     * CARD_TIMEOUT_CARD (TAB_KON_554): maximum duration of a reset or of an APDU to a card, after
     * that 4094 (TUC_KON_200). The spec gives no value, only „reibungsloser Betrieb“.
     */
    @WithDefault("10s")
    Duration cardTimeout();

    /**
     * Terminate the trusted channel of the PoPP service in LIANA (LIANA-28): two sessions per
     * elcSessionkey4SM, LIANA as card (keys of the twin from {@link #cardImages()}) and as terminal
     * (gSMC-KT of the CT, {@link Terminal#gsmcKt()}); with {@code trace.push-url} the plaintext
     * goes into the Tiger log.
     */
    @WithDefault("false")
    boolean terminateSecureMessaging();
  }

  /** Vertrauensraum for certificate validation (TUC_KON_037). */
  interface Pki {
    /** TSL file (gematik ECC-RSA-TSL), source of the CA certificates. */
    Path tsl();

    /**
     * CERT_IMPORTED_CA_LIST: additional CA certificates (PEM or DER), validated without TSL and
     * OCSP.
     */
    Optional<List<Path>> importedCas();

    /**
     * BNetzA-VL (ETSI TS 119 612), source of the qualified CAs for QES validation (TUC_PKI_030,
     * LIANA-112.07); without a value every QES is invalid (1027).
     */
    Optional<Path> bnetzaVl();

    /**
     * Online retrieval of the TSL at startup (LIANA-180); default: only the built-in {@link
     * #tsl()}.
     */
    TslOnline tslOnline();
  }

  /** {@code liana.pki.tsl-online}: source RU, no signature validation (LIANA-180). */
  interface TslOnline {
    /**
     * off (default), background (fetch after startup, on error continue with the built-in one),
     * enforce.
     */
    @WithDefault("off")
    de.gematik.liana.crypto.OnlineTsl.Mode mode();

    @WithDefault("https://download-ref.tsl.ti-dienste.de/ECC/ECC-RSA_TSL-ref.xml")
    URI url();

    /** Connection setup and response. */
    @WithDefault("10s")
    Duration timeout();
  }

  /** Observation of the card APDUs (LIANA-27). */
  interface Trace {
    /**
     * Base URL of a Tiger proxy (admin port); if set, every APDU to a card goes there via {@code
     * POST /traffic}. Without a value no HTTP traffic.
     */
    Optional<URI> pushUrl();

    /** Timeout for connection and request per push. */
    @WithDefault("500ms")
    Duration pushTimeout();
  }

  /** Cards and identities in the structure of the TI (LIANA-98). */
  interface Infrastructure {
    Konnektor konnektor();

    /** Card terminals per CT.CTID; the order is that of the IDs. */
    Map<String, Terminal> terminals();
  }

  /** The connector itself. */
  interface Konnektor {
    /** gSMC-K: identities of the connector (gemSpec_Kon 4.1.9). */
    GsmcK gsmcK();
  }

  /**
   * Identities of the gSMC-K, as PKCS#12 until there is a gSMC-K image (test identities under
   * {@code support/pki/server/}, {@code tools/pki/}), all with the same password.
   */
  interface GsmcK {
    /**
     * ID.AK.AUT (A_21697-01): TLS server identity of the connector interface and the KMS, client
     * certificate for CETP.
     */
    Path akAut();

    /**
     * RSA variant of ID.AK.AUT when TLS_USE_ECC_FOR_CS is off (LIANA-65); without it {@link
     * #akAut()} stays.
     */
    Optional<Path> akAutRsa();

    /** ID.SAK.AUT: identity towards the eHealth CTs (TUC_KON_050 step 3, LIANA-76). */
    Path sakAut();

    /** Password of the PKCS#12 files. */
    String password();

    /**
     * Image of the gSMC-K (file name, ICCSN or path in {@code card-images}): {@code
     * PrK.SAK.AUTD_CVC.E256} with CVC and CA CVC for the trusted channel to the HBA
     * (TUC_KON_154/158, LIANA-112.13); without it the HBA signs batches and Komfortsignaturen in SE
     * #1 without secure messaging.
     */
    Optional<String> image();
  }

  /**
   * A card terminal: fake CT with card engine (decision-3) or eHealth CT via SICCT (decision-11).
   */
  interface Terminal {
    Type type();

    /**
     * fake: number of slots (CT.SLOTCOUNT), numbered from 1; with an eHealth CT the CT reports it
     * itself.
     */
    Optional<Integer> slotCount();

    /**
     * fake: inserted card per slot as file name, ICCSN or absolute path (CardImages); empty slots
     * are missing.
     */
    Map<Integer, String> slots();

    /**
     * fake: PIN that the simulated PIN pad enters on VerifyPin (TUC_KON_012); default as for the
     * test cards.
     */
    @WithDefault("123456")
    String pin();

    /**
     * fake: PUK that the PIN pad enters for the PIN input {@code puk} (LIANA-68); as in the images
     * of the eHealth CT suite.
     */
    @WithDefault("12345678")
    String puk();

    /**
     * fake: transport PIN for the PIN input {@code transport} (LIANA-68); as in the {@code *_trans}
     * images of the suite.
     */
    @WithDefault("54321")
    String transportPin();

    /**
     * fake: computation time of the card for PSO COMPUTE DIGITAL SIGNATURE, default none. kartos
     * signs in microseconds, a HBA in some tens of milliseconds: Konnektor-QES KUC_1602_072 aborts
     * a batch of 80 after about 3.7 s with StopSignature, KUC_1602_073 expects it finished after
     * about 7 s (LIANA-112.05).
     */
    Optional<Duration> signatureTime();

    /**
     * gSMC-KT of the CT as file name, ICCSN or absolute path (CardImages, LIANA-99): identity of
     * LIANA as terminal in the trusted channel to the card ({@code PrK.SMC.AUTD_RPS_CVC.E256}),
     * mandatory with {@link Card#terminateSecureMessaging()}.
     */
    Optional<String> gsmcKt();

    /**
     * sicct: host name or IP address of the CT to which the service request goes (TUC_KON_054
     * ManuallyAdded).
     */
    Optional<String> host();

    /**
     * sicct: CT.SHARED_SECRET of an existing pairing (32 hex characters, 16 bytes): the CT then
     * counts as paired and active, TUC_KON_050 checks it via VALIDATE. Without a value the CT is
     * only assigned and is paired via the admin API (TUC_KON_053).
     */
    Optional<String> sharedSecret();

    /**
     * sicct: control interface of {@code kartos terminal} ({@code http://host:4743}, OpenAPI {@code
     * kartos-terminal-control-v1}); only in test environments. Through it the robot inserts and
     * removes cards and enters PINs (LIANA-112.15).
     */
    Optional<java.net.URI> control();
  }

  enum Type {
    FAKE,
    SICCT
  }

  /** Which kinds of CTs are running; follows from {@link Infrastructure#terminals()}. */
  enum Mode {
    FAKE,
    SICCT,
    MIXED;

    public static Mode of(Map<String, Terminal> terminals) {
      boolean fake = terminals.values().stream().anyMatch(kt -> kt.type() == Type.FAKE);
      boolean sicct = terminals.values().stream().anyMatch(kt -> kt.type() == Type.SICCT);
      return fake && sicct ? MIXED : sicct ? SICCT : FAKE;
    }

    public String value() {
      return name().toLowerCase(Locale.ROOT);
    }
  }

  /**
   * Parameters of the card terminal service (gemSpec_Kon TAB_KON_527/528); the identity towards the
   * CTs (ID.SAK.AUT) is in the gSMC-K entry of the infrastructure object.
   */
  interface Ctm {
    /** CTM_SERVICE_DISCOVERY_PORT: UDP port on which the CTs listen for service requests. */
    @WithDefault("4742")
    int serviceDiscoveryPort();

    /**
     * CTM_SERVICE_ANNOUNCEMENT_PORT: UDP port on which LIANA listens for service announcements (0:
     * free, tests).
     */
    @WithDefault("4742")
    int serviceAnnouncementPort();

    /** CTM_SERVICE_DISCOVERY_TIMEOUT */
    @WithDefault("3s")
    Duration serviceDiscoveryTimeout();

    /**
     * CTM_SERVICE_DISCOVERY_CYCLE (TAB_KON_527, default 10 minutes, 0 = disabled): interval of the
     * service requests to unconnected active CTs (TIP1-A_4538-02, LIANA-112.15). The spec counts in
     * minutes, tests may go shorter.
     */
    @WithDefault("10m")
    Duration serviceDiscoveryCycle();

    /** CTM_TLS_HS_TIMEOUT (1–60 s) */
    @WithDefault("10s")
    Duration tlsHandshakeTimeout();

    /**
     * CTM_KEEP_ALIVE_INTERVAL (1–10 s): GET STATUS as heartbeat after this much silence
     * (TIP1-A_4536).
     */
    @WithDefault("10s")
    Duration keepAliveInterval();

    /** CTM_KEEP_ALIVE_TRY_COUNT (3–10): unanswered heartbeats until the connection is closed. */
    @WithDefault("3")
    int keepAliveTryCount();

    /** CTM_SUPPORTED_KT_VERSIONS: supported EHEALTH interface versions of the CTs. */
    @WithDefault("1.0.0")
    List<String> supportedKtVersions();

    /**
     * MGM_KONN_HOSTNAME: name of the connector in the pairing display on the CT (TUC_KON_053 step
     * 5).
     */
    @WithDefault("liana")
    String konnektorHostname();
  }

  interface KonExport {
    String url();

    boolean rewriteServiceEndpoints();

    Credentials credentials();
  }

  interface Credentials {
    String type();

    Optional<String> username();

    /** Password for {@code basic}, passphrase of the container for {@code pkcs12}. */
    Optional<String> password();

    /**
     * {@code pkcs12}: container with client certificate and key, goes base64-encoded as {@code
     * data} into the .kon.
     */
    Optional<Path> keystore();
  }
}

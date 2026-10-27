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
package de.gematik.liana.kern.error;

/**
 * Connector error codes, as far as LIANA returns them (GERROR: Code, ErrorType, Severity,
 * ErrorText).
 */
public enum ConnectorError {
  /**
   * Konnektor-QES (KUC_1601_026, KUC_1701_001): warning with MGM_LU_ONLINE=Disabled when a status
   * check would be required; code, type and text as checked there (Tab_PKI_274 is not in the repo)
   */
  OFFLINE_NO_OCSP(
      1039,
      "Security",
      "Warning",
      "Warnung, dass Offline-Modus aktiviert ist und keine OCSP-Statusabfrage durchgeführt wurde"),
  /** Tab_PKI_274 (TUC_PKI_018 2a) */
  WRONG_KEYUSAGE(
      1016,
      "Security",
      "Error",
      "KeyUsage ist nicht vorhanden bzw. entspricht nicht der vorgesehenen KeyUsage"),
  /** Tab_PKI_274 (TUC_PKI_018 9a) */
  CERT_TYPE_MISMATCH(1018, "Security", "Error", "Zertifikatstyp-OID stimmt nicht überein"),
  /** Tab_PKI_274 (TUC_PKI_002) */
  CERTIFICATE_NOT_VALID_TIME(1021, "Security", "Error", "Zertifikat ist zeitlich nicht gültig"),
  /** Tab_PKI_274 (TUC_PKI_004) */
  CERTIFICATE_NOT_VALID_MATH(
      1024, "Security", "Error", "Zertifikats-Signatur ist mathematisch nicht gültig."),
  /** Tab_PKI_274 (TUC_PKI_003) */
  CA_CERT_MISSING(
      1027, "Technical", "Error", "CA kann nicht in den TSL-Informationen ermittelt werden."),
  /** gemSpec_OM Tab_Gen_Fehler: C.CH.AUT invalid after offline check (VSDM-A_2569, A_23157) */
  EGK_CERT_OFFLINE_INVALID(107, "Security", "Fatal", "Zertifikat auf eGK ungültig"),
  /** gemSpec_OM Tab_Gen_Fehler: DF.HCA blocked (VSDM-A_2568, A_23020) */
  HCA_BLOCKED(114, "Technical", "Fatal", "Gesundheitsanwendung auf eGK gesperrt"),
  /**
   * gemILF_PS Tab_ILF_PS_Fehlercodes_VSDM (CompType FM_VSDM, ErrorType and Severity as in example
   * 20): status in EF.StatusVD is „1“ (VSDM-A_2660)
   */
  VSD_INCONSISTENT(3001, "Technical", "Fatal", "VSD ungültig/nicht konsistent"),
  /**
   * gemILF_PS Tab_ILF_PS_Fehlercodes_VSDM: reading the VSD content from the card failed
   * (VSDM-A_2571)
   */
  VSD_PROCESSING_FAILED(
      3011, "Technical", "Fatal", "Verarbeiten der Versichertendaten gescheitert"),
  /**
   * gemILF_PS Tab_ILF_PS_Fehlercodes_VSDM: KVK record could not be read; also data that does not
   * conform to the KVK specifications (VSDM-A_2611, [gemSpec_FM_VSDM] Annex E)
   */
  KVK_READ_FAILED(3020, "Technical", "Fatal", "Lesen KVK gescheitert"),
  /** gemILF_PS Tab_ILF_PS_Fehlercodes_VSDM: checksum of the KVK record wrong (VSDM-A_2611) */
  KVK_CHECKSUM(3021, "Technical", "Fatal", "KVK Prüfsumme falsch, Daten korrupt"),
  /** gemILF_PS Tab_ILF_PS_Fehlercodes_VSDM, Tab_FM_VSDM_15: PIN.SMC of the SM-B not verified */
  SMB_NOT_UNLOCKED(3041, "Technical", "Fatal", "SM-B nicht freigeschaltet"),
  /** TAB_KON_567 and others: checkArguments */
  SYNTAX(4000, "Technical", "Error", "Syntaxfehler"),
  /** TAB_KON_549 GetPinStatus: card answers GET PIN STATUS with an error (TUC_KON_022 3b g) */
  INTERNAL(4001, "Technical", "Error", "interner Fehler"),
  /** TAB_KON_515: TUC_KON_000 rule R9 (HBAx with card session) without UserId */
  USER_ID_MISSING(
      4003,
      "Technical",
      "Error",
      "Keine User-ID angegeben, die zur Identifikation der Kartensitzung_HBAx benötigt wird."),
  /** TAB_KON_515; at the external interface 4021, here only in the log (TAB_KON_514-01 note 3) */
  INVALID_MANDANT(4004, "Technical", "Error", "Ungültige Mandanten-ID"),
  /** TAB_KON_515; at the external interface 4021, here only in the log (TAB_KON_514-01 note 3) */
  INVALID_CLIENT_SYSTEM(4005, "Technical", "Error", "Ungültige Clientsystem-ID"),
  /** TAB_KON_515; at the external interface 4021, here only in the log (TAB_KON_514-01 note 3) */
  INVALID_WORKPLACE(4006, "Technical", "Error", "Ungültige Arbeitsplatz-ID"),
  /** TAB_KON_515, TAB_KON_560 */
  INVALID_CT_ID(4007, "Technical", "Error", "Ungültige Kartenterminal-ID"),
  /** TAB_KON_515: TUC_KON_000 rule R7 */
  SMB_UNKNOWN(4009, "Security", "Error", "SM-B ist dem Konnektor nicht als SM-B_Verwaltet bekannt"),
  /** TAB_KON_515 */
  CS_NOT_IN_MANDANT(4010, "Security", "Error", "Clientsystem ist dem Mandanten nicht zugeordnet"),
  /** TAB_KON_515 */
  WP_NOT_IN_MANDANT(4011, "Security", "Error", "Arbeitsplatz ist dem Mandanten nicht zugeordnet"),
  /** TAB_KON_515: TUC_KON_000 rule R7 */
  SMB_NOT_IN_MANDANT(
      4013, "Security", "Error", "SM-B_Verwaltet ist dem Mandanten nicht zugeordnet"),
  /** TAB_KON_515 */
  WP_NOT_FOR_CS(
      4014,
      "Security",
      "Error",
      "Für den Mandanten ist der Arbeitsplatz nicht dem Clientsystem zugeordnet"),
  /**
   * TAB_KON_515: TUC_KON_000 rule R9, HBAx in a card session of another UserId with elevated
   * security state
   */
  HBA_OTHER_USER(
      4018,
      "Security",
      "Error",
      "Der HBAx hat mindestens eine Kartensitzung zu einer anderen UserId, deren Sicherheitszustand erhöht ist."),
  /** TAB_KON_515 */
  CARD_NOT_INSERTED(4008, "Technical", "Error", "Karte nicht als gesteckt identifiziert"),
  /** TAB_KON_523 (TUC_KON_050) */
  CT_CONNECT_FAILED(
      4028, "Technical", "Error", "Fehler beim Versuch eines Verbindungsaufbaus zu KT"),
  /** TAB_KON_523 (TUC_KON_050) */
  CT_AUTHENTICATION_FAILED(
      4029, "Security", "Error", "Fehler bei der KT-Authentisierung. KT-Zertifikat unbekannt."),
  /** TAB_KON_113 (TUC_KON_053) */
  CT_PAIRING_CONNECT_FAILED(
      4040, "Security", "Error", "Fehler beim Versuch eines Verbindungsaufbaus zum KT"),
  /** TAB_KON_113 (TUC_KON_053); for SICCT errors with the SICCT error code in the detail */
  CT_PAIRING_FAILED(4041, "Technical", "Error", "Fehler im Pairing, SICCT-Fehler"),
  /** TAB_KON_113 (TUC_KON_053) */
  CT_VERSION_UNSUPPORTED(
      4042, "Technical", "Error", "Die Version des Kartenterminals wird nicht unterstützt"),
  /** TAB_KON_525 (TUC_KON_054) */
  CT_NOT_ANSWERING(
      4033, "Technical", "Error", "Kartenterminal antwortet nicht, Zufügen fehlgeschlagen"),
  /** TAB_KON_525 (TUC_KON_054) */
  CT_MAC_MISMATCH(
      4035,
      "Technical",
      "Error",
      "Angegebener IP-Adresse gehört zu einer anderen MAC-Adresse als die, die übergeben wurde. Angaben zur MAC "
          + "prüfen"),
  /** TAB_KON_525 (TUC_KON_054) */
  CT_HOSTNAME_MISMATCH(
      4036,
      "Technical",
      "Error",
      "Angegebener IP-Adresse gehört zu einem anderen Hostname als der, der übergeben wurde. Angaben zum "
          + "Hostname prüfen"),
  /** TAB_KON_525 (TUC_KON_054) */
  CT_LIST_INCONSISTENT(4037, "Technical", "Error", "Verwaltung der Kartenterminals inkonsistent"),
  /** TAB_KON_515 */
  CT_NOT_REACHABLE(
      4015,
      "Security",
      "Error",
      "Kartenterminal ist weder lokal noch entfernt vom Arbeitsplatz aus zugreifbar"),
  /**
   * TAB_KON_515; at the external interface also for unknown mandants, Clientsysteme and workplaces
   */
  CONTEXT_INCOMPLETE(
      4021,
      "Technical",
      "Error",
      "Es sind nicht alle Pflichtparameter mandantId, clientSystemId, workplaceId gefüllt."),
  /** TAB_KON_216: TUC_KON_200 */
  CT_ACCESS(4044, "Technical", "Error", "Fehler beim Zugriff auf das Kartenterminal"),
  /** TAB_KON_724, TAB_KON_796 (TUC_KON_056/057): CT display already shows another prompt */
  CT_BUSY(4039, "Technical", "Error", "Kartenterminal durch andere Nutzung aktuell belegt"),
  /** TAB_KON_724 (TUC_KON_056 step 5) */
  WRONG_CARD_TYPE(4051, "Technical", "Error", "Falscher Kartentyp"),
  /** TAB_KON_724, TAB_KON_796 */
  INVALID_SLOT_ID(4097, "Technical", "Error", "Ungültige Kartenslot-ID"),
  /** TAB_KON_562 (TUC_KON_254) */
  NO_CARD_IN_SLOT(4098, "Technical", "Error", "keine Karte im angegebenen Slot gefunden"),
  /** TAB_KON_562 (TUC_KON_254) */
  NO_CARD_FOR_ICCSN(4099, "Technical", "Error", "keine Karte zur angegebenen Iccsn gefunden"),
  /** TAB_KON_721 EjectCard, TAB_KON_562 */
  INVALID_CARD_HANDLE(4101, "Technical", "Error", "Karten-Handle ungültig"),
  /** TAB_KON_724 (TUC_KON_056 step 4) */
  REQUEST_CARD_TIMEOUT(
      4202,
      "Technical",
      "Error",
      "Timeout. Es wurde keine Karte innerhalb der angegebenen Zeitspanne gesteckt."),
  /** TAB_KON_796 (TUC_KON_057), TAB_KON_721 */
  CARD_NOT_REMOVED(4203, "Technical", "Error", "Karte deaktiviert, aber nicht entnommen"),
  /** TAB_KON_724, TAB_KON_796: CT.CONNECTED = No */
  CT_NOT_CONNECTED(4222, "Technical", "Error", "Kartenterminal ist nicht verbunden"),
  /** TAB_KON_089 (TUC_KON_012 step 7): timeout during PIN entry */
  PIN_TIMEOUT(4043, "Technical", "Warning", "Timeout bei der PIN-Eingabe"),
  /** TAB_KON_089 (TUC_KON_012 step 7): cancelled by the user */
  PIN_CANCELLED(4049, "Technical", "Error", "Abbruch durch den Benutzer"),
  /** TIP1-A_5012 remote PIN procedure: processing error */
  REMOTE_PIN_FAILED(4053, "Security", "Error", "Remote-PIN nicht möglich"),
  /** TAB_KON_535 TUC_KON_005 (9): error not clearly attributable to either card */
  C2C_FAILED(4048, "Technical", "Error", "Fehler bei der C2C-Authentisierung"),
  /** TAB_KON_535 TUC_KON_005 (9): error of the source card */
  C2C_SOURCE_FAILED(4056, "Technical", "Error", "Fehler bei der C2C-Authentisierung, Quellkarte"),
  /** TAB_KON_535 TUC_KON_005 (9): error of the target card */
  C2C_TARGET_FAILED(4057, "Technical", "Error", "Fehler bei der C2C-Authentisierung, Zielkarte"),
  /** TAB_KON_093/193 (TUC_KON_019/021 7b): second new PIN differs from the first */
  PIN_MISMATCH(4067, "Security", "Error", "neue PIN nicht identisch"),
  /** TAB_KON_091 TUC_KON_022 (3b): pinRef not found */
  INVALID_PIN_REF(4072, "Technical", "Error", "ungültige PIN-Referenz PinRef"),
  /** TAB_KON_783 ExternalAuthenticate: card without a permitted key (TAB_KON_784) */
  CALL_NOT_ALLOWED(4058, "Security", "Error", "Aufruf nicht zulässig"),
  /** TAB_KON_543 TUC_KON_218: required PIN not verified */
  ACCESS_CONDITIONS(4085, "Security", "Error", "Zugriffsbedingungen nicht erfüllt"),
  /** TAB_KON_604 ReadCardCertificate */
  EGK_ACCESS_DENIED(4090, "Security", "Error", "Zugriff auf eGK nicht gestattet"),
  /** A_25895, TUC_KON_023 */
  CARD_LOCKED(
      4093, "Technical", "Error", "Karte wird in einer anderen Kartensitzung exklusiv verwendet"),
  /**
   * TUC_KON_200 and the other card TUCs: card does not respond within CARD_TIMEOUT_CARD
   * (TAB_KON_554)
   */
  CARD_TIMEOUT(4094, "Technical", "Error", "Timeout beim Kartenzugriff aufgetreten"),
  /**
   * TAB_KON_557 (TUC_KON_256 step 5c): filter of a subscription cannot be evaluated, only for this
   * subscription
   */
  FILTER_FAILED(4095, "Technical", "Error", "Fehler bei der Auswertung eines XPath-Ausdrucks"),
  /** TAB_KON_576, TAB_KON_579, TAB_KON_794 */
  INVALID_SUBSCRIPTION(4102, "Technical", "Error", "Ungültige SubscriptionId"),
  /** TAB_KON_604 ReadCardCertificate */
  INVALID_CERT_REF(4149, "Technical", "Error", "Ungültige Zertifikatsreferenz"),
  /**
   * TAB_KON_604 ReadCardCertificate; text with Crypt and CardHandle via {@link #exception(String,
   * String)}
   */
  CERT_NOT_ON_CARD(
      4258, "Technical", "Error", "<$Crypt>Zertifikat nicht vorhanden auf Karte: <cardHandle>"),
  /** TAB_KON_600 TUC_KON_033 (2) */
  EXPIRATION_UNREADABLE(4132, "Security", "Error", "Extraktion des Ablaufsdatums fehlgeschlagen"),
  /**
   * TAB_KON_603 CheckCertificateExpiration, TAB_KON_600 TUC_KON_033: warning per card in
   * CONN:Status
   */
  CERT_MISSING(
      4257, "Technical", "Warning", "<$Crypt>Zertifikat nicht vorhanden auf Karte: <cardHandle>"),
  /**
   * TAB_KON_277 StartCardSession; text with the card type via {@link #exception(String, String)}
   */
  CARD_TYPE_UNSUPPORTED(
      4209,
      "Technical",
      "Error",
      "Kartentyp %CardType% wird durch diese Operation nicht unterstützt."),
  /** TUC_KON_208: status word not in expectedStatusWords */
  APDU_NOT_PROCESSED(4284, "Technical", "Warning", "APDU konnte nicht verarbeitet werden."),
  /** TUC_KON_208 */
  UNEXPECTED_SEQUENCE(4285, "Technical", "Error", "Unerwartetes Sequence-Element"),
  /** TUC_KON_208 */
  SCENARIO_INVALID(4286, "Technical", "Error", "Inhalt des signierten Szenarios nicht valide"),
  /** TUC_KON_208, TUC_KON_224 */
  UNKNOWN_SESSION(4288, "Technical", "Error", "Unbekannte Session ID"),
  /** TAB_KON_144: TUC_KON_080 (A), XML document not well-formed */
  XML_NOT_WELL_FORMED(4022, "Security", "Error", "XML-Dokument nicht wohlgeformt"),
  /**
   * TAB_KON_144: TUC_KON_080 (A), XML document not valid against the schema of the signature policy
   */
  XML_NOT_VALID(4023, "Security", "Error", "XML-Dokument nicht valide in Bezug auf XML-Schema"),
  /**
   * TAB_KON_144: TUC_KON_080, validation against the document format; %Format% names the format
   * (PDF/A, TIFF, Text)
   */
  FORMAT_VALIDATION_FAILED(
      4024, "Security", "Error", "Formatvalidierung fehlgeschlagen (%Format%)"),
  /** TAB_KON_128: TUC_KON_150 step 1, document format not supported for the QES (binary) */
  INVALID_DOCUMENT_FORMAT(4110, "Technical", "Error", "ungültiges Dokumentformat (%Format%)"),
  /**
   * TAB_KON_127, TAB_KON_757: TUC_KON_160 step 2, SignatureType, IncludeEContent,
   * ReturnUpdatedSignature; text as in TAB_KON_065 („Fehler 4111 (Ungültiger Signaturtyp oder
   * Signaturvariante)“) and as checked by Konnektor-QES (KUC_1601_002); the error tables write it
   * in lower case
   */
  INVALID_SIGNATURE_TYPE(
      4111, "Technical", "Error", "Ungültiger Signaturtyp oder Signaturvariante"),
  /** TAB_KON_124, TAB_KON_592: TUC_KON_161/151 step 2, SignatureValue or hash value chain wrong */
  DOCUMENT_SIGNATURE_INVALID(
      4115,
      "Security",
      "Error",
      "Signatur des Dokuments ungültig. Prüfung der Hashwertkette bzw. Prüfung der kryptographischen Signatur "
          + "fehlgeschlagen."),
  /** TAB_KON_124, TAB_KON_592: TUC_KON_161/151 step 3 part 1 */
  SIGNER_CERTIFICATE_MISSING(
      4206, "Technical", "Error", "Signaturzertifikat ermitteln ist fehlgeschlagen"),
  /** TAB_KON_124, TAB_KON_592: TUC_KON_161/151, no signature in signedDocument and signature */
  NO_SIGNATURE(4253, "Technical", "Error", "Keine Signatur im Aufruf"),
  /** TAB_KON_120: TUC_KON_166 step 3, mathematical check of the card's signature */
  CARD_SIGNATURE_INVALID(4120, "Security", "Error", "Kartenfehler"),
  /**
   * TAB_KON_893: TUC_KON_159, status response CERT_REVOKED or CERT_UNKNOWN with
   * MGM_LU_ONLINE=Enabled
   */
  SIGNATURE_CREATION_FAILED(4123, "Security", "Error", "Fehler bei Signaturerstellung"),
  /** TAB_KON_127, TAB_KON_757: card type per TAB_KON_900 */
  CARD_TYPE_NOT_FOR_SIGNATURE(4126, "Security", "Error", "Kartentyp nicht zulässig für Signatur"),
  /** TAB_KON_757: SignaturePlacement with a non-XML signature */
  SIGNATURE_PLACEMENT_IGNORED(
      4197, "Technical", "Warning", "Parameter SignaturePlacement wurde ignoriert"),
  /** TAB_KON_842: StopSignature for a Jobnummer without a running signature job */
  JOB_NUMBER_UNKNOWN(4243, "Technical", "Error", "Jobnummer unbekannt"),
  /** TAB_KON_757: Jobnummer already used in the last 1000 calls (TIP1-A_4644) */
  JOB_NUMBER_USED(
      4252,
      "Technical",
      "Error",
      "Jobnummer wurde in den letzten 1.000 Aufrufen bereits verwendet und ist nicht zulässig"),
  /** TAB_KON_872, TAB_KON_886, TAB_KON_887: SAK_COMFORT_SIGNATURE = Disabled */
  COMFORT_DISABLED(4263, "Technical", "Error", "Komfortsignaturfunktion nicht aktiviert"),
  /** TAB_KON_887: TUC_KON_172 with an invalid CardHandle, warning per list */
  COMFORT_CARD_HANDLE_INVALID(4265, "Technical", "Warning", "Karten-Handle ungültig <cardHandles>"),
  /** TAB_KON_887: TUC_KON_172 for a CardHandle without card session, warning per list */
  COMFORT_NO_CARD_SESSION(
      4266, "Technical", "Warning", "Keine Kartensitzung vorhanden <cardHandles>"),
  /** TAB_KON_888: TUC_KON_173 */
  SIGNATURE_MODE_FAILED(
      4269, "Technical", "Error", "Fehler beim Ermitteln des Signaturmodus <cardHandle>"),
  /**
   * TAB_KON_879: ActivateComfortSignature with a UserId from the last 1,000 operations (A_20074)
   */
  USER_ID_USED(
      4270, "Technical", "Error", "UserId wurde in den letzten 1.000 Vorgängen bereits verwendet"),
  /** TAB_KON_872, TAB_KON_873: counter, timer or usage counter of the PIN.QES exhausted */
  COMFORT_ABORTED(4271, "Technical", "Error", "Komfortsignaturmodus abgebrochen"),
  /** TAB_KON_879: UserId not a UUID per RFC 4122 (A_20073-01) */
  USER_ID_INVALID(4272, "Technical", "Error", "UserId nicht zulässig"),
  /** TAB_KON_872, TAB_KON_886: Komfortsignatur with a card other than the HBA */
  COMFORT_HBA_ONLY(
      4274, "Technical", "Error", "Komfortsignaturen werden nur für den HBA unterstützt"),
  /** TAB_KON_886: TUC_KON_171, pinResult = BLOCKED */
  COMFORT_PIN_BLOCKED(4275, "Security", "Error", "PIN jetzt gesperrt (BLOCKED)"),
  /** TAB_KON_886: TUC_KON_171, pinResult = REJECTED */
  COMFORT_PIN_REJECTED(4276, "Security", "Error", "PIN falsch (REJECTED)"),
  /** TAB_KON_757: S/MIME is optional (KANN); a connector without S/MIME reports 4279 */
  SMIME_UNSUPPORTED(4279, "Technical", "Error", "S/MIME-Funktionalität nicht unterstützt"),
  /** TAB_KON_272 SecureSendAPDU: technical role of the signer not oid_popp */
  CERT_ROLE(4700, "Security", "Error", "Zertifikat enthält nicht die erwartete Rolle"),
  /** TAB_KON_272 SecureSendAPDU */
  SIGNATURE_INVALID(4701, "Security", "Error", "Signatur ungültig");

  private final int code;
  private final String errorType;
  private final String severity;
  private final String text;

  ConnectorError(int code, String errorType, String severity, String text) {
    this.code = code;
    this.errorType = errorType;
    this.severity = severity;
    this.text = text;
  }

  public int code() {
    return code;
  }

  public String errorType() {
    return errorType;
  }

  public String severity() {
    return severity;
  }

  public String text() {
    return text;
  }

  /**
   * Exception with this error; {@code detail} names the cause for log and tests, not for the
   * client.
   */
  public ConnectorException exception(String detail) {
    return new ConnectorException(this, text, this, detail);
  }

  /**
   * Like {@link #exception(String)}, with {@code protocol} as the error code in the log:
   * TAB_KON_514-01 note 3, e.g. 4021 at the external interface and 4005 in the log. Which of the
   * two appears at the external interface is decided by the vendor profile ({@code
   * VendorProfile#reportsProtocolError}).
   */
  public ConnectorException exception(ConnectorError protocol, String detail) {
    return new ConnectorException(this, text, protocol, detail);
  }

  /**
   * Like {@link #exception(String)}, with {@code text} instead of the fixed error text
   * (placeholders like %CardType%).
   */
  public ConnectorException exception(String text, String detail) {
    return new ConnectorException(this, text, this, detail);
  }
}

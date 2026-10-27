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
package de.gematik.liana.kern.vendor;

import de.gematik.liana.kern.error.ConnectorError;

/**
 * Vendor profile (decision-10): the central switch for every vendor-dependent behavior. Queries for
 * the vendor exist only here, one method per deviation with its source (expectation of a suite or
 * trace of a connector of this vendor) in the Javadoc; without a source the neutral reading
 * applies. The architecture test {@code VendorArchitectureTest} does not allow vendor queries
 * outside {@code kern.vendor}.
 *
 * <p>The known expectations of the suites are in LIANA-62 and are added here with their tickets
 * (e.g. KUC_1702_008); implemented are the KMS ({@link #ehexKms()}, LIANA-55; {@link #kocoKms()},
 * LIANA-96; {@link #riseKms()}, LIANA-97) and the Informationsmodell errors of Konnektor-QES
 * ({@link #reportsProtocolError(ConnectorError)}, {@link #emptyUserIdIsSyntaxError(boolean)},
 * LIANA-60).
 *
 * <p>Switchable at runtime (Admin API), {@link #reset()} restores the boot state from the YAML
 * (decision-4).
 */
public final class VendorProfile {

  private final Vendor boot;
  private volatile Vendor active;

  public VendorProfile(Vendor boot) {
    this.boot = boot;
    this.active = boot;
  }

  /**
   * The active profile, for display and reporting; do not branch on it, use the methods here
   * instead.
   */
  public Vendor vendor() {
    return active;
  }

  /** Switches volatilely to {@code vendor}. */
  public void switchTo(Vendor vendor) {
    active = vendor;
  }

  /**
   * Whether the KMS speaks the EHEX Managementschnittstelle (LIANA-55). EHEX itself, and SECUNET:
   * the suites address Secunet connectors with {@code kmsVendorName=EHEX} (client, LIANA-62).
   * Neutral has no KMS (decision-12).
   */
  public boolean ehexKms() {
    Vendor vendor = active;
    return vendor == Vendor.EHEX || vendor == Vendor.SECUNET;
  }

  /**
   * Whether the KMS speaks the JSON Managementschnittstelle of the KoCoBox (LIANA-96). KOCO itself:
   * konnektor-service-client 1.6.2 (Konnektor-QES) chooses {@code KmsKoco} for {@code
   * ProductVendorID} KOCOC; and CGM: kms-client maps {@code Vendor.CGM} to {@code KmsKoco} ({@code
   * KmsFactory}, client, LIANA-62).
   */
  public boolean kocoKms() {
    Vendor vendor = active;
    return vendor == Vendor.KOCO || vendor == Vendor.CGM;
  }

  /**
   * Whether the KMS speaks the RISE Managementschnittstelle (LIANA-97). Only RISE:
   * konnektor-service-client 1.6.2 chooses {@code KmsRise} for {@code ProductVendorID} RISEG and
   * addresses it on port 8443; kms-client maps only {@code Vendor.RISE} to {@code KmsRise} ({@code
   * KmsFactory}).
   */
  public boolean riseKms() {
    return active == Vendor.RISE;
  }

  /**
   * Whether the external interface shows the log error code instead of the prescribed one
   * (TAB_KON_514-01 note 3). KOCO reports an unknown Clientsystem as 4005 „Ungültige
   * Clientsystem-ID“ instead of 4021: Konnektor-QES {@code KUC_1702_007.feature:35} (KOCO 4005,
   * RISE/SECUNET 4021). KOCO, too, reports an unknown mandant as 4021 ({@code
   * KUC_1603_008.feature}, all three vendors).
   */
  public boolean reportsProtocolError(ConnectorError protocol) {
    return active == Vendor.KOCO && protocol == ConnectorError.INVALID_CLIENT_SYSTEM;
  }

  /**
   * Whether an empty UserId is a syntax error (4000 in checkArguments, before TUC_KON_000). RISE
   * only without MTOM: Konnektor-QES {@code KUC_1701_008.feature}, scenario „(RISE)“ expects 4000
   * „Syntaxfehler“, KOCO and SECUNET 4003; {@code KUC_1701_031.feature} sends the same request as
   * MTOM and expects 4003 for all three (LIANA-167).
   *
   * @param mtom whether the request came as an MTOM message ({@code multipart/related})
   */
  public boolean emptyUserIdIsSyntaxError(boolean mtom) {
    return active == Vendor.RISE && !mtom;
  }

  /**
   * Whether SignDocument ends with warning 1039 where no status check takes place: offline
   * (MGM_LU_ONLINE=Disabled) with IncludeRevocationInfo=true, for a parallel signature also online.
   * Only KOCO: Konnektor-QES {@code KUC_1601_026.feature} (offline, KOCO Warning 1039, RISE/SECUNET
   * OK), {@code KUC_1601_019.feature} (offline, parallel signature: KOCO Warning, SECUNET OK) and
   * {@code HSK_1601_019.feature} (without switching, i.e. in the boot state online: KOCO Warning,
   * SECUNET OK; {@code HSK_1601_022.feature} with IncludeRevocationInfo OK). The suite checks the
   * code only offline with IncludeRevocationInfo.
   */
  public boolean warnsOfflineWithoutOcsp() {
    return active == Vendor.KOCO;
  }

  /**
   * Whether SignDocument QES checks the binary format (4110, not a QES_DocFormat) before the
   * variant of a CMS signature (ReturnUpdatedSignature, IncludeObjects: 4111); TUC_KON_150 allows
   * steps 1–4 in any order. RISE and SECUNET: Konnektor-QES {@code KUC_1602_045.feature},
   * document-including countersignature over application/octet-stream, scenario „(RISE, SECUNET)“
   * 4110, „(KOCO)“ 4111. All check the signature type before: SECUNET reports S/MIME without MIME
   * type as 4111 ({@code KUC_1602_018.feature}, scenario „(SECUNET)“).
   */
  public boolean checksQesFormatFirst() {
    Vendor vendor = active;
    return vendor == Vendor.RISE || vendor == Vendor.SECUNET;
  }

  /**
   * Whether SignDocument QES reports a format that does not match the signature type (PAdES without
   * PDF/A, S/MIME) as 4110 „ungültiges Dokumentformat“ instead of 4111 „Ungültiger Signaturtyp oder
   * Signaturvariante“. Only RISE: Konnektor-QES {@code KUC_1602_018.feature} (S/MIME) and {@code
   * KUC_1602_019/021/022/023.feature} (PAdES for text or without MIME type), scenarios „(RISE)“
   * 4110, KOCO and SECUNET 4111 (KOCO for S/MIME 4279, {@link #rejectsSmime()}).
   */
  public boolean reportsQesFormatMismatch() {
    return active == Vendor.RISE;
  }

  /**
   * Whether SignDocument and VerifyDocument reject S/MIME with 4279 (S/MIME is KANN, TAB_KON_757,
   * TAB_KON_761), with the error text „SMIME-Funktionalität nicht unterstützt“ without slash. Only
   * KOCO: Konnektor-QES {@code KUC_1601_001/009.feature} (nonQES with the SM-B, RISE and SECUNET
   * sign or 4024), {@code KUC_1602_018.feature} (QES with the HBA; RISE 4110, SECUNET 4111) and
   * {@code KUC_1603_001/010.feature} (VerifyDocument; RISE and SECUNET VALID or 4024), each
   * scenario „(KOCO)“.
   */
  public boolean rejectsSmime() {
    return active == Vendor.KOCO;
  }

  /**
   * Whether VerifyDocument reports a non-well-formed XML document as 4111 „Ungültiger Signaturtyp
   * oder Signaturvariante“ instead of 4022 (TUC_KON_080 (A)). Only RISE: Konnektor-QES {@code
   * KUC_1604_011.feature} (PDF as Base64XML), scenario „(RISE)“ 4111, „(KOCO, SECUNET)“ 4022.
   */
  public boolean reportsMalformedXmlAsSignatureType() {
    return active == Vendor.RISE;
  }

  /**
   * {@code ProductVendorID} in {@code connector.sds} (TAB_KON_516–518, ProductInformation): the
   * vendor identifier by which clients recognize the connector. konnektor-service-client 1.6.2
   * (Konnektor-QES, TKQES steps) chooses the KMS client by it ({@code Vendor.getVendorById}: KOCOC,
   * SECUN, RISEG); without a known identifier the KMS login fails (LIANA-91). The other profiles
   * report {@code LIANA}.
   */
  public String productVendorId() {
    return switch (active) {
      case KOCO -> "KOCOC";
      case SECUNET -> "SECUN";
      case RISE -> "RISEG";
      default -> "LIANA";
    };
  }

  /** Restores the profile from the boot configuration. */
  public void reset() {
    active = boot;
  }
}

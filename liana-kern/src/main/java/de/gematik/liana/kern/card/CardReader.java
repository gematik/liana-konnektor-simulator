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
package de.gematik.liana.kern.card;

import de.gematik.liana.kern.terminal.CardTerminal;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Collections;
import java.util.HexFormat;
import java.util.regex.Pattern;
import javax.naming.InvalidNameException;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

/**
 * TUC_KON_001 step 2c: on insertion reads type, ICCSN, version and the details from the AUT
 * certificate via the port {@link CardTerminal}. GetCards does not query the terminal for them
 * afterwards (TIP1-A_4605-03, notes).
 *
 * <p>Recognized are the eGK of generation 2 and 3 (DF.HCA present, also blocked, EF.Version2 C1 =
 * 4.x.y or 5.x.y, TIP1-A_4988-03), the SMC-B of generation 2 (no DF.HCA, C1 = 4.x.y, C.HCI.AUT in
 * DF.ESIGN with the certificate type oid_smc_b_aut), the HBA of generation 2 (MF D27600014601, no
 * DF.HCA, C1 = 4.x.y, C.HP.AUT in DF.ESIGN with oid_hba_aut) and the gSMC-KT if it is inserted in a
 * slot as in the card terminal of the PS lab (MF D2760001448003, no DF.HCA, C1 = 4.x.y, C.SMKT.AUT
 * in DF.KT, LIANA-188); everything else is UNKNOWN. The AUT certificate is, per type, the ECC
 * certificate, otherwise RSA.
 *
 * <p>The KVK (LIANA-113) has no EF.ATR, EF.GDO and EF.DIR; only the ATR is evaluated (TUC_KON_001,
 * variants): a synchronous ATR (ISO 7816-10, the first byte is not a TS {@code 3B}/{@code 3F} of an
 * asynchronous card) and the KVK application via SELECT FILE ({@code D27600000101} or the old AID
 * {@code D28000000101}, KBV-Merkblatt KVK 4.1), which the card terminal maps to the memory card per
 * [SICCT] 5.5.8.1. The KVK has no ICCSN, version or certificate data.
 */
public final class CardReader {

  private static final HexFormat HEX = HexFormat.of().withUpperCase();
  private static final byte[] OK = {(byte) 0x90, 0x00};

  /** SELECT of a deactivated file (gemSpec_COS, warning „selected file deactivated“). */
  private static final byte[] DEACTIVATED = {0x62, (byte) 0x83};

  private static final Pattern KVNR = Pattern.compile("[A-Z][0-9]{9}");

  /**
   * MF via the AID: eGK (gemSpec_eGK_ObjSys), SMC-B (Tab_SMC-B_ObjSys_002), HBA (AID in the image
   * hba-valid).
   */
  private static final String SELECT_MF_EGK = "00A4040C07D2760001448000";

  private static final String SELECT_MF_SMCB = "00A4040C06D27600014606";
  private static final String SELECT_MF_HBA = "00A4040C06D27600014601";

  /** MF and DF.KT of the gSMC-KT (image gsmckt-root6). */
  private static final String SELECT_MF_SMKT = "00A4040C07D2760001448003";

  private static final String SELECT_DF_KT = "00A4040C06D27600014400";
  private static final String SELECT_DF_HCA = "00A4040C06D27600000102";
  private static final String SELECT_DF_ESIGN = "00A4040C0AA000000167455349474E";

  /**
   * KVK application, KBV-Merkblatt KVK 4.1: SELECT FILE with selection control 04 (AID), new and
   * old AID.
   */
  private static final String SELECT_KVK = "00A4040006D27600000101";

  private static final String SELECT_KVK_OLD = "00A4040006D28000000101";
  private static final String READ_EF_GDO = "00B0820000";
  private static final String READ_EF_ATR = "00B09D0000";
  private static final String READ_EF_VERSION2 = "00B0910000";

  /** eGK: EF.C.CH.AUT.E256 (SFI 04), otherwise EF.C.CH.AUT.R2048 (SFI 01); extended length. */
  private static final String READ_C_CH_AUT_E256 = "00B08400000000";

  private static final String READ_C_CH_AUT_R2048 = "00B08100000000";

  /**
   * SMC-B: EF.C.HCI.AUT.E256 (SFI 06), otherwise EF.C.HCI.AUT.R2048 (SFI 01), gemSpec_SMC-B_ObjSys
   * 5.4.2; for the HBA, EF.C.HP.AUT.E256 and EF.C.HP.AUT.R2048 are under the same SFIs (image
   * hba-valid, FID C506 and C500).
   */
  private static final String READ_C_HCI_AUT_E256 = "00B08600000000";

  private static final String READ_C_HCI_AUT_R2048 = READ_C_CH_AUT_R2048;

  /**
   * gSMC-KT: EF.C.SMKT.AUT2.XXXX (ECC, SFI 04), otherwise EF.C.SMKT.AUT.XXXX (RSA, SFI 01), image
   * gsmckt-root6.
   */
  private static final String READ_C_SMKT_AUT_E256 = READ_C_CH_AUT_E256;

  private static final String READ_C_SMKT_AUT_R2048 = READ_C_CH_AUT_R2048;

  /**
   * oid_smc_b_aut 1.2.276.0.76.4.77 as DER (GS-A_4445), in CertificatePolicies of the C.HCI.AUT.
   */
  private static final byte[] OID_SMC_B_AUT = HEX.parseHex("06072A8214004C044D");

  /** oid_hba_aut 1.2.276.0.76.4.75 as DER (GS-A_4445), in CertificatePolicies of the C.HP.AUT. */
  private static final byte[] OID_HBA_AUT = HEX.parseHex("06072A8214004C044B");

  private CardReader() {}

  /**
   * Result of TUC_KON_001 step 2c: the card data and, if they are UNKNOWN, why (LIANA-121), e.g.
   * „kartos beendet (Exit 1)“ or „kein MF der eGK, SMC-B oder des HBA wählbar“; otherwise {@code
   * null}.
   */
  public record Reading(CardData data, String unknownReason) {

    static Reading unknown(String reason) {
      return new Reading(CardData.UNKNOWN, reason);
    }
  }

  /** Reads the card in {@code slot}; if it is unreadable or unrecognized, the result is UNKNOWN. */
  public static CardData read(CardTerminal terminal, int slot) {
    return open(terminal, slot).data();
  }

  /** Like {@link #read}, plus the reason if the card is UNKNOWN. */
  public static Reading open(CardTerminal terminal, int slot) {
    try {
      return readCard(terminal, slot);
    } catch (IOException | NamingException | RuntimeException e) {
      return Reading.unknown(
          e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
    }
  }

  private static Reading readCard(CardTerminal terminal, int slot)
      throws IOException, NamingException {
    byte[] coldAtr = terminal.reset(slot);
    if (synchronous(coldAtr)) {
      return ok(terminal, slot, SELECT_KVK) || ok(terminal, slot, SELECT_KVK_OLD)
          ? new Reading(new CardData(CardType.KVK, null, null, null, null, null), null)
          : Reading.unknown("synchrone Karte ohne KVK-Anwendung");
    }
    String selectMf =
        ok(terminal, slot, SELECT_MF_EGK)
            ? SELECT_MF_EGK
            : ok(terminal, slot, SELECT_MF_SMCB)
                ? SELECT_MF_SMCB
                : ok(terminal, slot, SELECT_MF_HBA)
                    ? SELECT_MF_HBA
                    : ok(terminal, slot, SELECT_MF_SMKT) ? SELECT_MF_SMKT : null;
    if (selectMf == null) {
      return Reading.unknown("kein MF der eGK, SMC-B, des HBA oder der gSMC-KT wählbar");
    }
    byte[] version2 = read(terminal, slot, READ_EF_VERSION2);
    byte[] versionTemplate = version2 == null ? null : Tlv.find(version2, "EF");
    CardVersion.Version objectSystem =
        versionTemplate == null ? null : CardVersion.Version.of(Tlv.find(versionTemplate, "C1"));
    if (objectSystem == null) {
      return Reading.unknown("EF.Version2 ohne Version des Objektsystems (C1)");
    }
    if (objectSystem.major() != 4 && objectSystem.major() != 5) {
      return Reading.unknown(
          "Objektsystem "
              + objectSystem.major()
              + "."
              + objectSystem.minor()
              + "."
              + objectSystem.revision()
              + " ist weder Generation 2 noch 3 (TIP1-A_4988-03)");
    }
    // DF.HCA present: even deactivated (blocked health application, SELECT → 6283) the card remains
    // an eGK
    byte[] hca = terminal.transmit(slot, HEX.parseHex(SELECT_DF_HCA));
    boolean egk = Arrays.equals(hca, OK) || Arrays.equals(hca, DEACTIVATED);
    if (!egk && objectSystem.major() != 4) {
      return Reading.unknown("Objektsystem " + objectSystem.major() + ".x ohne DF.HCA");
    }
    ok(terminal, slot, selectMf);
    byte[] gdo = read(terminal, slot, READ_EF_GDO);
    byte[] iccsn = gdo == null ? null : Tlv.find(gdo, "5A");
    byte[] atr = read(terminal, slot, READ_EF_ATR);
    CardVersion version =
        new CardVersion(
            atr == null ? null : CardVersion.Version.of(Tlv.find(atr, "D0")),
            objectSystem,
            CardVersion.Version.of(Tlv.find(versionTemplate, "C7")),
            CardVersion.Version.of(Tlv.find(versionTemplate, "C5")),
            CardVersion.Version.of(Tlv.find(versionTemplate, "C4")),
            CardVersion.Version.of(Tlv.find(versionTemplate, "C6")));

    X509Certificate aut = null;
    boolean smkt = selectMf.equals(SELECT_MF_SMKT);
    if (smkt && ok(terminal, slot, SELECT_DF_KT)) {
      byte[] der = read(terminal, slot, READ_C_SMKT_AUT_E256);
      aut = certificate(der != null ? der : read(terminal, slot, READ_C_SMKT_AUT_R2048));
    } else if (!smkt && ok(terminal, slot, SELECT_DF_ESIGN)) {
      byte[] der = read(terminal, slot, egk ? READ_C_CH_AUT_E256 : READ_C_HCI_AUT_E256);
      aut =
          certificate(
              der != null
                  ? der
                  : read(terminal, slot, egk ? READ_C_CH_AUT_R2048 : READ_C_HCI_AUT_R2048));
    }
    ok(terminal, slot, selectMf);
    CardType type =
        egk
            ? CardType.EGK
            : smkt
                ? CardType.SMC_KT
                : selectMf.equals(SELECT_MF_HBA) ? CardType.HBA : CardType.SMC_B;
    if (!egk && aut == null) {
      return Reading.unknown(
          smkt ? "kein lesbares C.SMKT.AUT in DF.KT" : "kein lesbares AUT-Zertifikat in DF.ESIGN");
    }
    if (!egk && !smkt && !hasPolicy(aut, type == CardType.HBA ? OID_HBA_AUT : OID_SMC_B_AUT)) {
      return Reading.unknown(
          type == CardType.HBA
              ? "C.HP.AUT ohne Zertifikatstyp oid_hba_aut"
              : "C.HCI.AUT ohne Zertifikatstyp oid_smc_b_aut");
    }

    String name = null;
    String kvnr = null;
    LocalDate expiration = null;
    if (aut != null) {
      // an RDN can be multi-valued (C.HP.AUT: SN + GN + serialNumber + CN)
      for (Rdn rdn : subject(aut).getRdns()) {
        for (Attribute attribute : Collections.list(rdn.toAttributes().getAll())) {
          String value = String.valueOf(attribute.get());
          if (attribute.getID().equalsIgnoreCase("CN")) {
            name = value;
          } else if (attribute.getID().equalsIgnoreCase("OU") && KVNR.matcher(value).matches()) {
            kvnr = value;
          }
        }
      }
      expiration = LocalDate.ofInstant(aut.getNotAfter().toInstant(), ZoneOffset.UTC);
    }
    return new Reading(
        new CardData(
            type,
            iccsn == null ? null : HEX.formatHex(iccsn),
            version,
            name,
            egk ? kvnr : null,
            expiration),
        null);
  }

  /**
   * An ATR that does not start with the TS of an asynchronous card (ISO 7816-3: {@code 3B} direct,
   * {@code 3F} inverse).
   */
  static boolean synchronous(byte[] atr) {
    return atr != null && atr.length > 0 && atr[0] != 0x3B && atr[0] != 0x3F;
  }

  /**
   * Whether CertificatePolicies contains the certificate type {@code oid} (DER), e.g. oid_smc_b_aut
   * for C.HCI.AUT.
   */
  private static boolean hasPolicy(X509Certificate certificate, byte[] oid) {
    byte[] policies = certificate.getExtensionValue("2.5.29.32");
    return policies != null && indexOf(policies, oid) >= 0;
  }

  private static int indexOf(byte[] data, byte[] part) {
    for (int i = 0; i + part.length <= data.length; i++) {
      if (Arrays.equals(data, i, i + part.length, part, 0, part.length)) {
        return i;
      }
    }
    return -1;
  }

  private static boolean ok(CardTerminal terminal, int slot, String apdu) throws IOException {
    byte[] response = terminal.transmit(slot, HEX.parseHex(apdu));
    return Arrays.equals(response, OK);
  }

  /** Data of a READ BINARY response with 9000, otherwise {@code null}. */
  private static byte[] read(CardTerminal terminal, int slot, String apdu) throws IOException {
    byte[] response = terminal.transmit(slot, HEX.parseHex(apdu));
    int n = response.length;
    if (n < 2 || response[n - 2] != (byte) 0x90 || response[n - 1] != 0x00) {
      return null;
    }
    return Arrays.copyOf(response, n - 2);
  }

  static X509Certificate certificate(byte[] der) {
    if (der == null) {
      return null;
    }
    try {
      return (X509Certificate)
          CertificateFactory.getInstance("X.509")
              .generateCertificate(new ByteArrayInputStream(der));
    } catch (CertificateException e) {
      return null;
    }
  }

  static LdapName subject(X509Certificate certificate) {
    try {
      return new LdapName(certificate.getSubjectX500Principal().getName());
    } catch (InvalidNameException e) {
      throw new IllegalStateException(e);
    }
  }
}

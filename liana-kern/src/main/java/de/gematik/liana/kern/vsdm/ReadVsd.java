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
package de.gematik.liana.kern.vsdm;

import de.gematik.liana.kern.access.Context;
import de.gematik.liana.kern.card.CardAccess;
import de.gematik.liana.kern.card.CardLocks;
import de.gematik.liana.kern.card.CardObject;
import de.gematik.liana.kern.card.CardType;
import de.gematik.liana.kern.card.EgkFiles;
import de.gematik.liana.kern.card.PinVerification;
import de.gematik.liana.kern.error.ConnectorError;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * the Fachmodul VSDM (Fachmodul VSDM), operation ReadVSD ([gemSpec_FM_VSDM] 3.2.1, flow per
 * Tab_FM_VSDM_15): returns PD, VD and the status container of the eGK (VSDM-A_2567) as they are on
 * the card, gzip-compressed (VSDM-A_2652, Base64 is done by the adapter); with
 * PerformOnlineCheck=true additionally the Onlineprüfung via {@link OnlineCheck} (LIANA-141) and
 * with ReadOnlineReceipt=true its Prüfungsnachweis (VSDM-A_2575, VSDM-A_2576, VSDM-A_2578).
 *
 * <p>Flow: TUC_KON_000 for SM-B and eGK, reserve eGK (TUC_KON_023), TUC_KON_018 (blocked health
 * application 114 before offline-invalid C.CH.AUT 107, VSDM-A_2568, VSDM-A_2569, A_23020, A_23157),
 * PIN.SMC via TUC_KON_022 (3041, also prerequisite for TUC_KON_110 to the UFS), determine update
 * jobs, EF.StatusVD (status „1“ → 3001, VSDM-A_2660), EF.PD and the VD from EF.VD between „Offset
 * Start VD“ and „Offset Ende VD“ (VSDM-A_2784), release the reservation, also after an error. An
 * invalid eGK (114, 107) gets no Prüfungsnachweis (A_23020); LIANA then does not ask a UFS either,
 * because without CCS an update changes nothing about the blocking.
 *
 * <p>Not implemented: update via VSDD/CMS (LIANA-102), writing the Prüfungsnachweis to the eGK and
 * reading it from there (ReadOnlineReceipt=true without Onlineprüfung, VSDM-A_2577), card-to-card
 * with the SM-B and thus the GVD (the response may omit them, VSDM-A_2572), log entries on the eGK,
 * HBA as HpcHandle (LIANA-103) and the events VSDM/PROGRESS. For these, {@link #read} throws {@link
 * Unsupported}.
 */
public final class ReadVsd {

  /** HBAx: HBA-qSig, HBA, ZOD_2.0. */
  private static final Set<CardType> HBAX =
      Set.of(CardType.HBA_Q_SIG, CardType.HBA, CardType.ZOD_2_0);

  private static final String PIN_SMC = "PIN.SMC";
  private static final Pattern TIMESTAMP =
      Pattern.compile("(\\d{4})(\\d{2})(\\d{2})(\\d{2})(\\d{2})(\\d{2})");

  /**
   * EF.StatusVD (25 octets): status (1), timestamp (14), Version_XML (5, BCD),
   * Version_Speicherstruktur (5).
   */
  private static final int STATUS_LENGTH = 20;

  /**
   * VSD_StatusType per Tab_FM_VSDM_21: status, timestamp as xsd:dateTime, version of the XML
   * schemas.
   */
  public record Status(String status, String timestamp, String version) {}

  /**
   * PD and VD gzip-compressed, as on the card, plus the status container and the Prüfungsnachweis
   * if it is requested ({@code null} otherwise).
   */
  public record Result(
      byte[] persoenlicheVersichertendaten,
      byte[] allgemeineVersicherungsdaten,
      Status status,
      Pruefungsnachweis pruefungsnachweis) {}

  /** A call LIANA does not implement; the access check (TUC_KON_000) has already passed. */
  public static final class Unsupported extends RuntimeException {

    Unsupported(String reason) {
      super(reason);
    }
  }

  private final CardAccess access;
  private final CardLocks locks;
  private final EgkFiles files;
  private final PinVerification pins;
  private final OnlineCheck onlineCheck;

  public ReadVsd(
      CardAccess access,
      CardLocks locks,
      EgkFiles files,
      PinVerification pins,
      OnlineCheck onlineCheck) {
    this.access = access;
    this.locks = locks;
    this.files = files;
    this.pins = pins;
    this.onlineCheck = onlineCheck;
  }

  public Result read(
      Context context,
      String ehcHandle,
      String hpcHandle,
      boolean performOnlineCheck,
      boolean readOnlineReceipt) {
    // Tab_FM_VSDM_15 „Aufrufkontext prüfen“: TUC_KON_000 first for HBA or SM-B, then for the eGK
    CardObject hpc = access.card(context, hpcHandle);
    CardObject egk = access.card(context, ehcHandle);
    if (egk.data().type() != CardType.EGK) {
      throw unsupportedType(ehcHandle, egk);
    }
    if (HBAX.contains(hpc.data().type())) {
      throw new Unsupported("ReadVSD mit einem HBA als HpcHandle setzt LIANA nicht um (LIANA-103)");
    }
    if (hpc.data().type() != CardType.SMC_B) {
      throw unsupportedType(hpcHandle, hpc);
    }
    if (readOnlineReceipt && !performOnlineCheck) {
      throw new Unsupported(
          "ReadVSD mit ReadOnlineReceipt=true ohne Onlineprüfung (Prüfungsnachweis von der eGK "
              + "lesen, VSDM-A_2577) setzt LIANA nicht um (LIANA-103)");
    }
    // „eGK reservieren“: TUC_KON_026, TUC_KON_023 with DoLock = Ja (4093 if reserved)
    CardLocks.Lock lock = locks.lock(egk.cardHandle());
    try {
      return read(context, egk, hpc, performOnlineCheck, readOnlineReceipt);
    } finally {
      // „Reservierung der eGK aufheben“, also after an error
      locks.unlock(lock);
    }
  }

  private Result read(
      Context context,
      CardObject egk,
      CardObject hpc,
      boolean performOnlineCheck,
      boolean readOnlineReceipt) {
    EgkFiles.Blocking blocking = files.checkBlocking(egk);
    if (blocking.hcaBlocked()) {
      throw ConnectorError.HCA_BLOCKED.exception(egk.cardHandle() + ": DF.HCA nicht wählbar");
    }
    if (blocking.autOfflineInvalid() != null) {
      throw ConnectorError.EGK_CERT_OFFLINE_INVALID.exception(
          egk.cardHandle() + ": " + blocking.autOfflineInvalid());
    }
    // „Echtheit der beteiligten Karten prüfen“: TUC_KON_022 for PIN.SMC, without TUC_KON_005 (C2C)
    PinVerification.PinStatus pin = pins.status(context, hpc.cardHandle(), PIN_SMC).pinStatus();
    if (pin != PinVerification.PinStatus.VERIFIED) {
      throw ConnectorError.SMB_NOT_UNLOCKED.exception(hpc.cardHandle() + ": PIN.SMC " + pin);
    }
    // „Aktualisierungsaufträge ermitteln“, „Prüfungsnachweis erzeugen“
    Pruefungsnachweis pn =
        performOnlineCheck
            ? onlineCheck.check(context, egk, hpc, blocking.providerId()).pruefungsnachweis()
            : null;
    Status status = status(egk, file(egk, EgkFiles.EF_STATUS_VD, "EF.StatusVD"));
    byte[] pd = file(egk, EgkFiles.EF_PD, "EF.PD");
    byte[] vd = file(egk, EgkFiles.EF_VD, "EF.VD");
    return new Result(pd(egk, pd), vd(egk, vd), status, readOnlineReceipt ? pn : null);
  }

  private byte[] file(CardObject egk, int sfi, String name) {
    byte[] data = files.readHca(egk, sfi);
    if (data == null) {
      throw ConnectorError.VSD_PROCESSING_FAILED.exception(
          egk.cardHandle() + ": " + name + " nicht lesbar");
    }
    return data;
  }

  /** Tab_FM_VSDM_21; status „1“ (transactions open) is VSDM-A_2660. */
  static Status status(CardObject egk, byte[] file) {
    if (file.length < STATUS_LENGTH) {
      throw invalid(egk, "EF.StatusVD mit " + file.length + " Oktett");
    }
    String status = new String(file, 0, 1, StandardCharsets.US_ASCII);
    if (status.equals("1")) {
      throw ConnectorError.VSD_INCONSISTENT.exception(egk.cardHandle() + ": EF.StatusVD Status 1");
    }
    var timestamp = TIMESTAMP.matcher(new String(file, 1, 14, StandardCharsets.US_ASCII));
    if (!status.equals("0") || !timestamp.matches()) {
      throw invalid(egk, "EF.StatusVD " + HexFormat.of().formatHex(file, 0, 15));
    }
    // Version_XML BCD: three, three and four digits, 0x0070030001 → 7.3.1 (Tab_FM_VSDM_22)
    String bcd = HexFormat.of().formatHex(file, 15, 20);
    if (!bcd.matches("\\d{10}")) {
      throw invalid(egk, "Version_XML " + bcd);
    }
    String version =
        Integer.parseInt(bcd.substring(0, 3))
            + "."
            + Integer.parseInt(bcd.substring(3, 6))
            + "."
            + Integer.parseInt(bcd.substring(6));
    return new Status(
        status,
        timestamp.group(1)
            + "-"
            + timestamp.group(2)
            + "-"
            + timestamp.group(3)
            + "T"
            + timestamp.group(4)
            + ":"
            + timestamp.group(5)
            + ":"
            + timestamp.group(6),
        version);
  }

  /** EF.PD: length (2 octets), then the gzip-compressed PD record. */
  static byte[] pd(CardObject egk, byte[] file) {
    if (file.length < 2) {
      throw invalid(egk, "EF.PD ohne Länge");
    }
    return gzip(egk, "EF.PD", file, 2, 2 + unsigned(file, 0));
  }

  /**
   * EF.VD: Offset Start VD, Offset Ende VD, Offset Start GVD, Offset Ende GVD (2 octets each); the
   * VD lie between start and end inclusive; the Fachmodul does not read the GVD copy behind them
   * (VSDM-A_2784).
   */
  static byte[] vd(CardObject egk, byte[] file) {
    if (file.length < 8) {
      throw invalid(egk, "EF.VD ohne Offsets");
    }
    return gzip(egk, "EF.VD", file, unsigned(file, 0), unsigned(file, 2) + 1);
  }

  /**
   * The data from {@code from} to {@code to} (exclusive) if they lie within the file and are gzip.
   */
  private static byte[] gzip(CardObject egk, String name, byte[] file, int from, int to) {
    if (from < 0
        || to > file.length
        || to - from < 2
        || file[from] != 0x1F
        || file[from + 1] != (byte) 0x8B) {
      throw invalid(
          egk, name + " ohne gzip-Datensatz bei " + from + ".." + to + " von " + file.length);
    }
    return Arrays.copyOfRange(file, from, to);
  }

  private static int unsigned(byte[] data, int offset) {
    return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
  }

  private static RuntimeException invalid(CardObject egk, String reason) {
    return ConnectorError.VSD_PROCESSING_FAILED.exception(egk.cardHandle() + ": " + reason);
  }

  private static RuntimeException unsupportedType(String cardHandle, CardObject card) {
    String type = card.data().type().value();
    return ConnectorError.CARD_TYPE_UNSUPPORTED.exception(
        ConnectorError.CARD_TYPE_UNSUPPORTED.text().replace("%CardType%", type),
        cardHandle + " ist " + type);
  }
}

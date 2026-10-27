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
import de.gematik.liana.kern.card.CardObject;
import de.gematik.liana.kern.card.CardType;
import de.gematik.liana.kern.card.KvkFiles;
import de.gematik.liana.kern.error.ConnectorError;
import java.time.Clock;
import java.time.YearMonth;

/**
 * the Fachmodul VSDM (Fachmodul VSDM), operation ReadKVK ([gemSpec_FM_VSDM] 3.2.2, flow per
 * Tab_FM_VSDM_16, LIANA-113): returns the VersichertenDatenTemplate of the KVK unchanged
 * (VSDM-A_2609) after it has been checked per [gemSpec_FM_VSDM] Annex E ({@link KvkTemplate}). A
 * wrong checksum aborts with 3021, an unreadable or non-conforming record with 3020 (VSDM-A_2611,
 * gemILF_PS Tab_ILF_PS_Fehlercodes_VSDM).
 *
 * <p>Flow: TUC_KON_000 for the KVKHandle without ctId, needCardSession and allWorkplaces,
 * TUC_KON_026 (foreign reservation 4093), TUC_KON_202 via {@link KvkFiles}. A handle to a card
 * other than the KVK is 4209.
 *
 * <p>VSDM-A_2626 (SOLL): if the validity date has passed, LIANA writes the warning „Das
 * Gültigkeitsdatum der Karte ist überschritten“ to the log instead of showing it on the CT display
 * via TUC_KON_051; the data still goes to the caller.
 */
public final class ReadKvk {

  static final String EXPIRED = "Das Gültigkeitsdatum der Karte ist überschritten";
  private static final System.Logger LOG = System.getLogger(ReadKvk.class.getName());

  private final CardAccess access;
  private final KvkFiles files;
  private final Clock clock;

  public ReadKvk(CardAccess access, KvkFiles files, Clock clock) {
    this.access = access;
    this.files = files;
    this.clock = clock;
  }

  /** ReadKVK with KVKHandle and Context: the checked VersichertenDatenTemplate from tag '60'. */
  public byte[] read(Context context, String kvkHandle) {
    CardObject kvk = access.cardSession(context, kvkHandle);
    if (kvk.data().type() != CardType.KVK) {
      String type = kvk.data().type().value();
      throw ConnectorError.CARD_TYPE_UNSUPPORTED.exception(
          ConnectorError.CARD_TYPE_UNSUPPORTED.text().replace("%CardType%", type),
          kvkHandle + " ist " + type);
    }
    KvkTemplate template;
    try {
      template = KvkTemplate.parse(files.read(kvk));
    } catch (KvkTemplate.ChecksumException e) {
      throw ConnectorError.KVK_CHECKSUM.exception(kvkHandle + ": " + e.getMessage());
    } catch (IllegalArgumentException e) {
      throw ConnectorError.KVK_READ_FAILED.exception(kvkHandle + ": " + e.getMessage());
    }
    if (template.expiredAt(YearMonth.now(clock))) {
      LOG.log(
          System.Logger.Level.WARNING,
          "{0}/{1}: {2} (VSDM-A_2626, Gültigkeitsdatum {3})",
          kvk.ctId(),
          kvk.slotNo(),
          EXPIRED,
          template.validity());
    }
    return template.bytes();
  }
}

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
import de.gematik.liana.kern.card.CardObject;
import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.List;

/**
 * Port to the Fachdienst UFS ([gemSpec_SST_FD_VSDM], {@code cm/uf/UFS.wsdl}): operation
 * GetUpdateFlags for an eGK (ICCSN from EF.GDO), in the header the localization Type UFS and
 * Provider = ProviderID ([gemSpec_FM_VSDM] 4.3.1, 4.3.3).
 */
public interface UpdateFlagService {

  /**
   * An Aktualisierungsauftrag from CM:UpdateFlag; {@code mandatory} for UpdatePriority MANDATORY.
   */
  record UpdateFlag(String type, String provider, String updateId, boolean mandatory) {}

  /** Response of the UFS. */
  sealed interface Answer {}

  /**
   * GetUpdateFlagsResponse: the Aktualisierungsaufträge and the Prüfziffer from
   * CM:ServiceReceipt/CM:Receipt ({@code null} if the UFS sends none).
   */
  record Flags(List<UpdateFlag> flags, byte[] receipt) implements Answer {}

  /** SOAP fault; {@code code} from GERROR:Error/Trace/Code, {@code null} without gematik error. */
  record Fault(Integer code, String text) implements Answer {}

  /**
   * Calls GetUpdateFlags at {@code url}. With HTTPS the Fachmodul authenticates with {@code smb}
   * (TUC_KON_110, MANDANT_SMB), unlocked in the context {@code context}.
   *
   * @throws IOException UFS unreachable, time limit exceeded or no SOAP response
   */
  Answer getUpdateFlags(
      URI url,
      String iccsn,
      String providerId,
      Context context,
      CardObject smb,
      Duration connectTimeout,
      Duration readTimeout)
      throws IOException;
}

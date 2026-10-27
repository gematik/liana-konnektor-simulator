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
package de.gematik.liana.kern.access;

import de.gematik.liana.kern.error.ConnectorError;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Informationsmodell for access authorization (TUC_KON_000): mandants, Clientsysteme and workplaces
 * with their mandants, Clientsysteme (CS_AP) and card terminals. A Clientsystem counts as assigned
 * to the mandant if a workplace lists both.
 *
 * <p>{@code smbVerwaltet} assigns SMC-Bs (ICCSN) to their mandants (SM-B_Verwaltet, A_23545-01). If
 * it is empty, every inserted SMC-B counts as SM-B_Verwaltet of every mandant: LIANA then needs no
 * per-card maintenance.
 */
public record Infomodel(
    List<String> mandants,
    List<String> clientSystems,
    List<Workplace> workplaces,
    Map<String, List<String>> smbVerwaltet) {

  public record Workplace(
      String id, List<String> mandants, List<String> clientSystems, List<String> terminals) {}

  public Infomodel {
    smbVerwaltet = smbVerwaltet == null ? Map.of() : Map.copyOf(smbVerwaltet);
  }

  /** Without SM-B_Verwaltet: every SMC-B belongs to every mandant. */
  public Infomodel(List<String> mandants, List<String> clientSystems, List<Workplace> workplaces) {
    this(mandants, clientSystems, workplaces, Map.of());
  }

  /**
   * TIP1-A_4524-03 TUC_KON_000 without ctId and cardHandle: rule R1 ({@code allWorkplaces}) or R3.
   * Unknown entities report 4021 at the external interface (TAB_KON_514-01, note 3).
   *
   * @return the card terminals reachable in the context (for TUC_KON_253)
   */
  public Set<String> checkAccess(Context context, boolean allWorkplaces) {
    if (blank(context.mandantId())
        || blank(context.clientSystemId())
        || (!allWorkplaces && blank(context.workplaceId()))) {
      throw ConnectorError.CONTEXT_INCOMPLETE.exception("Pflichtparameter fehlt in " + context);
    }
    if (!mandants.contains(context.mandantId())) {
      throw ConnectorError.CONTEXT_INCOMPLETE.exception(
          ConnectorError.INVALID_MANDANT, context.mandantId());
    }
    if (!clientSystems.contains(context.clientSystemId())) {
      throw ConnectorError.CONTEXT_INCOMPLETE.exception(
          ConnectorError.INVALID_CLIENT_SYSTEM, context.clientSystemId());
    }
    List<Workplace> forMandantAndCs =
        workplaces.stream()
            .filter(
                w ->
                    w.mandants().contains(context.mandantId())
                        && w.clientSystems().contains(context.clientSystemId()))
            .toList();
    if (forMandantAndCs.isEmpty()) {
      throw ConnectorError.CS_NOT_IN_MANDANT.exception(
          context.clientSystemId() + " / " + context.mandantId());
    }
    if (allWorkplaces) {
      Set<String> terminals = new LinkedHashSet<>();
      forMandantAndCs.forEach(w -> terminals.addAll(w.terminals()));
      return terminals;
    }
    Workplace workplace =
        workplace(context.workplaceId())
            .orElseThrow(
                () ->
                    ConnectorError.CONTEXT_INCOMPLETE.exception(
                        ConnectorError.INVALID_WORKPLACE, context.workplaceId()));
    if (!workplace.mandants().contains(context.mandantId())) {
      throw ConnectorError.WP_NOT_IN_MANDANT.exception(
          workplace.id() + " / " + context.mandantId());
    }
    if (!workplace.clientSystems().contains(context.clientSystemId())) {
      throw ConnectorError.WP_NOT_FOR_CS.exception(
          workplace.id() + " / " + context.clientSystemId());
    }
    return new LinkedHashSet<>(workplace.terminals());
  }

  /**
   * TUC_KON_000 rule R7, section relations (TAB_KON_514-01): the SMC-B {@code iccsn} is
   * SM-B_Verwaltet (4009) and assigned to the mandant (4013).
   */
  public void checkSmbVerwaltet(String mandantId, String iccsn) {
    if (smbVerwaltet.isEmpty()) {
      return;
    }
    List<String> smbMandants = smbVerwaltet.get(iccsn);
    if (smbMandants == null) {
      throw ConnectorError.SMB_UNKNOWN.exception("ICCSN " + iccsn);
    }
    if (!smbMandants.contains(mandantId)) {
      throw ConnectorError.SMB_NOT_IN_MANDANT.exception("ICCSN " + iccsn + " / " + mandantId);
    }
  }

  private Optional<Workplace> workplace(String id) {
    return workplaces.stream().filter(w -> w.id().equals(id)).findFirst();
  }

  private static boolean blank(String value) {
    return value == null || value.isBlank();
  }
}

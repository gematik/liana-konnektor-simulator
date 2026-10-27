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
package de.gematik.liana.kern.event;

import de.gematik.liana.kern.access.Context;
import de.gematik.liana.kern.access.Infomodel;
import de.gematik.liana.kern.terminal.CardTerminalInfo;
import de.gematik.liana.kern.terminal.TerminalRegistry;
import java.util.List;
import java.util.Set;

/**
 * TIP1-A_4604 operation GetCardTerminals (TAB_KON_563, flow TAB_KON_564): TUC_KON_000 with {@code
 * allWorkplaces = @mandant-wide}, then TUC_KON_252 „Liefere KT_Liste“ (TIP1-A_4599). Returns only
 * the state managed in the connector and does not query any card terminals.
 */
public final class GetCardTerminals {

  /** A CT of the response with the workplaces it is assigned to as a local CT (WorkplaceIds). */
  public record Entry(CardTerminalInfo info, List<String> workplaceIds) {}

  private final Infomodel infomodel;
  private final TerminalRegistry terminals;

  public GetCardTerminals(Infomodel infomodel, TerminalRegistry terminals) {
    this.infomodel = infomodel;
    this.terminals = terminals;
  }

  public List<Entry> execute(Context context, boolean mandantWide) {
    Set<String> reachable = infomodel.checkAccess(context, mandantWide);
    // TUC_KON_252: the CTs of the workplace or of all workplaces of mandant and Clientsystem
    return terminals.terminals().stream()
        .filter(terminal -> reachable.contains(terminal.id()))
        .map(terminal -> new Entry(terminal.info(), workplaces(terminal.id())))
        .toList();
  }

  private List<String> workplaces(String ctId) {
    return infomodel.workplaces().stream()
        .filter(w -> w.terminals().contains(ctId))
        .map(Infomodel.Workplace::id)
        .toList();
  }
}

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
// @ts-check
/**
 * Page event subscriptions (LIANA-151): the subscriptions of the Clientsysteme at the system information service
 * (Subscribe, TIP1-A_4608; TAB_KON_572) with context, target, topic, filter, TerminationTime and last delivery attempt
 * via CETP (TUC_KON_256 step 6). Read-only; refreshes on every subscription event from GET /admin/events.
 */
import { html, useState } from '../vendor/preact-htm.js';
import { admin } from '../api.js';
import { usePoll, useLive, Badge, ApiProblem, Empty, clock, dateTime, relative } from '../ui.js';

/** @param {any} s entry from GET /admin/subscriptions */
function context(s) {
  return [s.mandantId, s.clientSystemId, s.workplaceId].filter(Boolean).join(' / ') + (s.userId ? ' · ' + s.userId : '');
}

export function Subscriptions() {
  const streaming = useLive();
  const subs = usePoll(admin.subscriptions, [], { on: ['subscription', 'state'] });
  const [client, setClient] = useState('');
  const all = /** @type {any[]} */ (subs.data ?? []);
  const clients = [...new Set(all.map((s) => s.clientSystemId).filter(Boolean))].sort();
  const shown = client ? all.filter((s) => s.clientSystemId === client) : all;
  const failed = all.filter((s) => s.lastDelivery && !s.lastDelivery.delivered).length;
  const delivered = all.filter((s) => s.lastDelivery?.delivered).length;

  return html`
    <div class="title-row">
      <h1>Ereignis-Abos</h1>
      <${Badge} kind=${streaming ? 'ok' : 'off'}>${streaming ? 'live' : 'Polling'}<//>
      <span class="muted">Anmeldungen der Clientsysteme am Systeminformationsdienst (Subscribe, TIP1-A_4608). Nur lesend; Zurücksetzen leert die Liste.</span>
    </div>
    <${ApiProblem} error=${subs.error} />
    <section aria-label="Kennzahlen" class="tiles">
      <div class="tile">
        <span class="label">Anmeldungen</span>
        <span class="figure">${subs.data ? all.length : '…'}</span>
      </div>
      <div class="tile">
        <span class="label">Letzte Zustellung</span>
        <span class="badges">
          <${Badge} kind="ok">${delivered} zugestellt<//>
          <${Badge} kind=${failed ? 'err' : 'off'}>${failed} gescheitert<//>
        </span>
        <span class="hint">Nach EVT_MAX_TRY Fehlschlägen in Folge entfernt LIANA alle Anmeldungen der Ereignissenke (TAB_KON_571).</span>
      </div>
    </section>

    <section aria-labelledby="h-subs" class="panel">
      <div class="panel-head">
        <h2 id="h-subs">Subscriptions</h2>
        <div class="grow"></div>
        ${clients.length > 1 ? html`
          <label for="subs-client" class="hint">Clientsystem</label>
          <select id="subs-client" class="mono" value=${client} onChange=${(/** @type {any} */ e) => setClient(e.target.value)}>
            <option value="">alle</option>
            ${clients.map((c) => html`<option value=${c}>${c}</option>`)}
          </select>` : null}
      </div>
      ${subs.data && all.length === 0 ? html`
        <${Empty} title="Keine Anmeldungen">Kein Clientsystem hat sich seit Start oder letztem Zurücksetzen angemeldet (Subscribe am EventService).<//>` : html`
        <div class="scroll">
          <table>
            <thead><tr>
              <th scope="col">SubscriptionID</th><th scope="col">Kontext</th><th scope="col">Ziel (EventTo)</th>
              <th scope="col">Topic · Filter</th><th scope="col">Läuft ab</th><th scope="col">Letzte Zustellung</th>
            </tr></thead>
            <tbody>${shown.map((s) => html`
              <tr key=${s.id}>
                <td class="mono nowrap" title=${s.id}>${s.id.slice(0, 8)}…</td>
                <td class="mono">${context(s)}</td>
                <td class="mono">${s.eventTo}</td>
                <td><span class="mono">${s.topic}</span><div class="mono small muted">${s.filter ?? 'ohne Filter'}</div></td>
                <td class="mono nowrap">${dateTime(s.terminationTime)}<div class="small muted">${relative(s.terminationTime)}</div></td>
                <td>${s.lastDelivery ? html`
                  <${Badge} kind=${s.lastDelivery.delivered ? 'ok' : 'err'}>${s.lastDelivery.delivered ? 'zugestellt' : 'gescheitert'}<//>
                  <div class="mono small muted">${clock(s.lastDelivery.time)} · ${s.lastDelivery.topic}${s.lastDelivery.error ? ' · ' + s.lastDelivery.error : ''}</div>`
                  : html`<${Badge} kind="off">noch keine<//>`}</td>
              </tr>`)}
            </tbody>
          </table>
        </div>`}
      <div class="panel-foot"><span class="mono hint">GET /admin/subscriptions · Push: subscription</span></div>
    </section>`;
}

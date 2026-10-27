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
 * Page 1 · overview: instance, tiles for terminals, cards, event subscriptions, TLS, PKI and profile, latest entries
 * in the Systemprotokoll.
 */
import { html } from '../vendor/preact-htm.js';
import { admin } from '../api.js';
import { usePoll, Badge, ApiProblem, Empty, clock, severityKind, relative } from '../ui.js';
import { tslBadge } from './tls.js';

/**
 * State of a CT in one word: fake CTs are always available, eHealth CTs according to CT.CORRELATION and CT.CONNECTED.
 * @param {any} kt entry from GET /admin/terminals
 * @returns {{ kind: 'ok' | 'warn' | 'off', text: string, connected: boolean }}
 */
export function terminalState(kt) {
  if (kt.mode === 'fake') {
    return { kind: 'ok', text: 'verfügbar', connected: true };
  }
  const ct = kt.ct;
  if (!ct) {
    return { kind: 'off', text: 'nicht gefunden', connected: false };
  }
  if (ct.CONNECTED) {
    return { kind: 'ok', text: 'verbunden', connected: true };
  }
  return { kind: 'off', text: ct.CORRELATION + ' · nicht verbunden', connected: false };
}

export function Overview() {
  const info = usePoll(admin.info, [], { on: ['state'] });
  const terminals = usePoll(admin.terminals, [], { on: ['terminal', 'card', 'state'] });
  const tls = usePoll(admin.tls, [], { on: ['state'] });
  const vendor = usePoll(admin.vendor, [], { on: ['state'] });
  const log = usePoll(() => admin.log('', ''), [], { on: ['log', 'state'] });
  const subs = usePoll(admin.subscriptions, [], { on: ['subscription', 'state'] });
  const pki = usePoll(admin.pki, [], { on: ['state'] });

  const i = info.data;
  const kts = /** @type {any[]} */ (terminals.data ?? []);
  const connected = kts.filter((kt) => terminalState(kt).connected).length;
  /** @type {Record<string, number>} */
  const types = {};
  for (const kt of kts) {
    for (const slot of kt.slots) {
      if (slot.cardType) {
        types[slot.cardType] = (types[slot.cardType] ?? 0) + 1;
      }
    }
  }
  const cards = Object.values(types).reduce((a, b) => a + b, 0);
  const t = tls.data;
  const v = vendor.data;
  const recent = /** @type {any[]} */ (log.data ?? []).slice(-5).reverse();
  const subscriptions = /** @type {any[]} */ (subs.data ?? []);
  const delivered = subscriptions.filter((s) => s.lastDelivery?.delivered).length;
  const failed = subscriptions.filter((s) => s.lastDelivery && !s.lastDelivery.delivered).length;
  const p = pki.data;

  return html`
    <h1>Übersicht</h1>
    <${ApiProblem} error=${info.error ?? terminals.error} />
    <section aria-label="Instanz" class="facts">
      <div><span class="label">Produkt</span><span class="strong">${i?.product ?? '…'}</span></div>
      <div><span class="label">Version</span><span class="mono">${i?.version ?? '…'}</span></div>
      <div><span class="label">Umgebung</span><span class="mono">${i?.env ?? '…'}</span></div>
      <div><span class="label">Konnektor-Port</span><span class="mono">${i ? i.konnektorPort : '…'}${t ? ' · TLS ' + t.port : ''}</span></div>
      <div><span class="label">Management-Port · API + GUI</span><span class="mono">${i?.adminPort ?? '…'}</span></div>
      <div><span class="label">Terminalmodus</span><span class="mono">${i?.terminalMode ?? '…'}</span></div>
    </section>

    <section aria-label="Kennzahlen" class="tiles">
      <a class="tile" href="#/terminals">
        <span class="label">Kartenterminals</span>
        <span class="figure">${connected} <span class="figure-sub">/ ${kts.length} verbunden</span></span>
        <span class="badges">${kts.map((kt) => {
          const s = terminalState(kt);
          return html`<${Badge} kind=${s.kind}>${kt.id}${s.connected ? '' : ' ' + s.text}<//>`;
        })}</span>
      </a>
      <a class="tile" href="#/terminals">
        <span class="label">Gesteckte Karten</span>
        <span class="figure">${cards}</span>
        <span class="badges">${Object.entries(types).map(([type, n]) => html`
          <${Badge} kind=${type === 'UNKNOWN' ? 'warn' : 'info'}>${type} ${n}<//>`)}</span>
      </a>
      <a class="tile" href="#/subscriptions">
        <span class="label">Ereignis-Abos</span>
        <span class="figure">${subs.data ? subscriptions.length : '…'}</span>
        <span class="badges">${subs.data ? html`
          <${Badge} kind="ok">${delivered} zugestellt<//>
          ${failed ? html`<${Badge} kind="err">${failed} gescheitert<//>` : null}` : null}</span>
      </a>
      <a class="tile" href="#/tls">
        <span class="label">TLS / mTLS</span>
        <span class="figure-text">${t ? (t.tlsMandatory ? 'TLS Pflicht' : 'TLS optional') + ' · Client-Auth '
          + (t.clientAuthMandatory ? 'Pflicht' : 'aus') : '…'}</span>
        <span class="badges">${t ? html`<${Badge} kind="ok">${t.port}<//><${Badge} kind="info">${t.clientCertificates.length} Client-Zertifikate<//>` : null}</span>
      </a>
      <a class="tile" href="#/tls/pki">
        <span class="label">PKI</span>
        <span class="figure-text">${p ? (p.tsl ? 'TSL ' + (p.tsl.sequenceNumber ?? '?') : 'keine TSL') : '…'}</span>
        <span class="badges">${p ? html`
          ${tslBadge(p.tsl)}
          ${p.tsl?.nextUpdate ? html`<${Badge} kind="off">NextUpdate ${relative(p.tsl.nextUpdate)}<//>` : null}
          <${Badge} kind="info">${(p.tsl?.caCount ?? 0) + ' CAs' + (p.importedCas ? ' + ' + p.importedCas + ' importiert' : '')}<//>` : null}</span>
      </a>
      <a class="tile" href="#/profile">
        <span class="label">Herstellerprofil</span>
        <span class="figure-text">${v?.vendor ?? '…'}</span>
        <span class="badges">${v ? html`
          ${v.vendor === v.boot ? html`<${Badge} kind="off">wie beim Start<//>` : html`<${Badge} kind="warn">geändert · Start ${v.boot}<//>`}
          <${Badge} kind=${v.strict === v.strictBoot ? 'off' : 'warn'}>strict ${v.strict ? 'an' : 'aus'}<//>` : null}</span>
      </a>
    </section>

    <section aria-labelledby="h-log" class="panel">
      <div class="panel-head">
        <h2 id="h-log">Letzte Einträge im Systemprotokoll</h2>
        <div class="grow"></div>
        <a class="btn" href="#/log">Alle anzeigen</a>
      </div>
      ${log.data && recent.length === 0 ? html`<${Empty} title="Protokoll leer">Seit Start oder letztem Zurücksetzen ist nichts protokolliert worden.<//>` : html`
      <div class="scroll">
        <table>
          <thead><tr><th scope="col">Zeit</th><th scope="col">Typ</th><th scope="col">Schweregrad</th><th scope="col">Topic</th><th scope="col">Parameter</th></tr></thead>
          <tbody>${recent.map((e) => html`
            <tr class=${e.topic === 'LIANA/DEVIATION' ? 'deviation' : ''}>
              <td class="mono nowrap">${clock(e.time)}</td>
              <td>${e.type}</td>
              <td><${Badge} kind=${severityKind(e.severity)}>${e.severity}<//></td>
              <td class="mono nowrap">${e.topic}</td>
              <td class="mono muted">${Object.entries(e.parameters ?? {}).map(([k, val]) => k + '=' + val).join('  ')}</td>
            </tr>`)}
          </tbody>
        </table>
      </div>`}
    </section>`;
}

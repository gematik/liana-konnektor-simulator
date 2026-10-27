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
 * Page 3 · Systemprotokoll (TUC_KON_271): GET /admin/log with from/to, filter by type, severity and topic prefix
 * in the browser, expandable parameters, LIANA/DEVIATION (LIANA-126) highlighted, live via push (LIANA-150).
 */
import { html, useState } from '../vendor/preact-htm.js';
import { admin } from '../api.js';
import { usePoll, Badge, ApiProblem, clock, severityKind } from '../ui.js';

const TYPES = ['Alle', 'Op', 'Sec'];
const SEVERITIES = ['Alle', 'Debug', 'Info', 'Warning', 'Error', 'Fatal'];
const TOPICS = ['Alle', 'CARD/', 'CT/', 'MGM/', 'LIANA/'];

/** @param {string} value */
const isoOrEmpty = (value) => !value || !Number.isNaN(new Date(value).getTime());

export function Log() {
  const [from, setFrom] = useState('');
  const [to, setTo] = useState('');
  const [live, setLive] = useState(true);
  const [type, setType] = useState('Alle');
  const [severity, setSeverity] = useState('Alle');
  const [topic, setTopic] = useState('Alle');
  const [open, setOpen] = useState(/** @type {string | null} */ (null));

  const valid = isoOrEmpty(from) && isoOrEmpty(to);
  const fromIso = valid && from ? new Date(from).toISOString() : '';
  const toIso = valid && to ? new Date(to).toISOString() : '';
  const log = usePoll(() => admin.log(fromIso, toIso), [fromIso, toIso], { live, on: ['log', 'state'] });

  const all = /** @type {any[]} */ (log.data ?? []).slice().reverse();
  const rows = all.filter((e) => (type === 'Alle' || e.type === type)
    && (severity === 'Alle' || e.severity === severity)
    && (topic === 'Alle' || e.topic.startsWith(topic)));

  /** @param {string} label @param {string} value @param {string[]} options @param {(v: string) => void} set */
  const chips = (label, value, options, set) => html`
    <div role="group" aria-label=${label} class="chips">
      <span class="label">${label}</span>
      ${options.map((o) => html`
        <button class=${label === 'Topic' ? 'chip mono' : 'chip'} type="button" aria-pressed=${value === o ? 'true' : 'false'}
            onClick=${() => set(o)}>${o}</button>`)}
    </div>`;

  return html`
    <div class="title-row">
      <h1>Systemprotokoll</h1>
      <span class="muted">Ringpuffer im Speicher · leer nach Zurücksetzen</span>
    </div>
    <section aria-label="Filter" class="panel filters">
      <div class="filter-row">
        <div class="field">
          <label for="from">Von</label>
          <input id="from" class="mono" type="text" value=${from} placeholder="2026-10-16T12:00:00Z"
              aria-invalid=${isoOrEmpty(from) ? undefined : 'true'} onChange=${(/** @type {any} */ e) => setFrom(e.target.value.trim())} />
        </div>
        <div class="field">
          <label for="to">Bis</label>
          <input id="to" class="mono" type="text" value=${to} placeholder="jetzt"
              aria-invalid=${isoOrEmpty(to) ? undefined : 'true'} onChange=${(/** @type {any} */ e) => setTo(e.target.value.trim())} />
        </div>
        ${valid ? null : html`<span class="field-error">ISO-8601 erwartet, z. B. 2026-10-16T12:00:00Z</span>`}
        <div class="grow"></div>
        <button class="btn btn-sm" type="button" aria-pressed=${live ? 'true' : 'false'} onClick=${() => setLive(!live)}>
          ${live ? '● Live' : 'Live aus'}
        </button>
        ${live ? null : html`<button class="btn btn-sm" type="button" onClick=${log.reload}>Neu laden</button>`}
      </div>
      <div class="filter-row">
        ${chips('Typ', type, TYPES, setType)}
        ${chips('Schweregrad', severity, SEVERITIES, setSeverity)}
        ${chips('Topic', topic, TOPICS, setTopic)}
      </div>
    </section>
    <${ApiProblem} error=${log.error} />
    <section aria-label="Einträge" class="panel">
      <div class="panel-head muted small">${rows.length} von ${all.length} Einträgen · GET /admin/log${fromIso ? ' ab ' + fromIso : ''}${toIso ? ' bis ' + toIso : ''}</div>
      <div class="scroll">
        <div class="log">
          <div class="log-grid log-header"><span>Zeit</span><span>Typ</span><span>Schweregrad</span><span>Topic</span><span>Parameter</span></div>
          ${rows.map((e, n) => {
            const key = e.time + e.topic + n;
            const expanded = open === key;
            const params = Object.entries(e.parameters ?? {});
            return html`
              <div key=${key} class=${e.topic === 'LIANA/DEVIATION' ? 'log-row deviation' : 'log-row'}>
                <button class="row" type="button" aria-expanded=${expanded ? 'true' : 'false'} onClick=${() => setOpen(expanded ? null : key)}>
                  <span class="log-grid">
                    <span class="mono" title=${e.time}>${clock(e.time)}</span>
                    <span>${e.type}</span>
                    <span><${Badge} kind=${severityKind(e.severity)}>${e.severity}<//></span>
                    <span class="mono strong">${e.topic}</span>
                    <span class="mono muted ellipsis">${params.map(([k, v]) => k + '=' + v).join('  ')}</span>
                  </span>
                </button>
                ${expanded ? html`
                  <dl class="params">
                    <dt class="mono muted">time</dt><dd class="mono">${e.time}</dd>
                    ${params.map(([k, v]) => html`<dt class="mono muted">${k}</dt><dd class="mono">${v}</dd>`)}
                  </dl>` : null}
              </div>`;
          })}
          ${log.data && rows.length === 0 ? html`
            <div class="empty-row">${all.length ? 'Keine Einträge für diesen Filter.' : 'Protokoll leer: seit Start oder letztem Zurücksetzen ist nichts protokolliert worden.'}</div>` : null}
        </div>
      </div>
    </section>`;
}

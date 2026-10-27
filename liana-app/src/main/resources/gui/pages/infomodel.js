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
 * Page 6 · Informationsmodell (TUC_KON_000, liana.infomodel) and .kon export (support/kon/kon-format.md v1.0.0,
 * LIANA-10/11). The preview does not show password and PKCS#12 container; the download contains them.
 */
import { html, useState } from '../vendor/preact-htm.js';
import { admin } from '../api.js';
import { usePoll, Badge, ApiProblem, Empty, copy } from '../ui.js';

/** @param {{ items: string[] }} props */
const Tags = ({ items }) => html`<span class="tags">${items.length ? items.map((t) => html`<span class="tag mono">${t}</span>`) : html`<span class="muted">–</span>`}</span>`;

export function Infomodel() {
  const model = usePoll(admin.infomodel, [], { live: false });
  const m = model.data;
  const [client, setClient] = useState(/** @type {string | null} */ (null));
  const selected = client ?? m?.clientSystems?.[0] ?? null;

  return html`
    <div class="title-row">
      <h1>Infomodell & .kon</h1>
      <${Badge} kind="off">nur lesend<//>
      <span class="muted">aus der Startkonfiguration (liana.infomodel)</span>
    </div>
    <${ApiProblem} error=${model.error} />
    ${m ? html`
      <section aria-labelledby="h-wp" class="panel">
        <div class="panel-head">
          <h2 id="h-wp">Arbeitsplätze</h2>
          <span class="hint">Mandanten: <${Tags} items=${m.mandants} /> · Clientsysteme: <${Tags} items=${m.clientSystems} /></span>
        </div>
        ${m.workplaces.length ? html`
          <div class="scroll">
            <table>
              <thead><tr><th scope="col">Arbeitsplatz</th><th scope="col">Mandanten</th><th scope="col">Clientsysteme</th><th scope="col">Terminals</th></tr></thead>
              <tbody>${m.workplaces.map((/** @type {any} */ w) => html`
                <tr>
                  <td class="mono">${w.id}</td>
                  <td><${Tags} items=${w.mandants} /></td>
                  <td><${Tags} items=${w.clientSystems} /></td>
                  <td><${Tags} items=${w.terminals} /></td>
                </tr>`)}
              </tbody>
            </table>
          </div>` : html`<${Empty} title="Keine Arbeitsplätze" />`}
        <div class="sub">
          <span class="label">SM-B_Verwaltet</span>
          ${m.smbVerwaltet.length ? m.smbVerwaltet.map((/** @type {any} */ s) => html`
            <div class="smb"><span class="mono">${s.iccsn}</span><span aria-hidden="true">→</span><${Tags} items=${s.mandants} /></div>`)
            : html`<span class="muted small">leer: jede SMC-B gilt für jeden Mandanten</span>`}
        </div>
      </section>

      <div class="split">
        <section aria-labelledby="h-cs" class="panel pad">
          <h2 id="h-cs">Clientsysteme</h2>
          ${m.clientSystems.map((/** @type {string} */ id) => html`
            <button class="cs" type="button" aria-pressed=${selected === id ? 'true' : 'false'} onClick=${() => setClient(id)}>
              <span class="mono strong">${id}</span>
              <span class="hint">${m.workplaces.filter((/** @type {any} */ w) => w.clientSystems.includes(id)).length} Arbeitsplätze</span>
            </button>`)}
          ${m.clientSystems.length ? null : html`<${Empty} title="Keine Clientsysteme" />`}
        </section>
        ${selected ? html`<${Kon} key=${selected} client=${selected} />` : null}
      </div>` : null}`;
}

/** @param {{ client: string }} props */
function Kon({ client }) {
  const kon = usePoll(() => admin.kon(client), [client], { live: false });
  /** @type {any} */
  let parsed = null;
  try {
    parsed = kon.data ? JSON.parse(kon.data) : null;
  } catch (e) {
    parsed = null;
  }
  const c = parsed?.credentials;
  return html`
    <section aria-labelledby="h-kon" class="panel pad">
      <div class="title-row">
        <h2 id="h-kon">.kon für <span class="mono">${client}</span></h2>
        ${parsed ? html`<${Badge} kind="off">v${parsed.version}<//>` : null}
        <div class="grow"></div>
        <button class="btn btn-sm" type="button" disabled=${!kon.data} onClick=${() => kon.data && copy(kon.data, '.kon')}>Kopieren</button>
        <a class="btn btn-sm btn-primary" href=${admin.konPath(client)} download=${client + '.kon'}>.kon herunterladen</a>
      </div>
      <${ApiProblem} error=${kon.error} />
      ${parsed ? html`
        <dl class="kv">
          <dt class="hint">URL</dt><dd class="mono">${parsed.url}</dd>
          <dt class="hint">Endpunkte umschreiben</dt><dd>${parsed.rewriteServiceEndpoints ? 'ja' : 'nein'}</dd>
          <dt class="hint">Kontext</dt><dd class="mono">${[parsed.mandantId, parsed.clientSystemId, parsed.workplaceId].join(' / ')}</dd>
          <dt class="hint">Credentials</dt><dd>${c ? c.type + (c.username ? ' · ' + c.username : '') + (c.data ? ' · Container eingebettet' : '')
            + (c.password ? ' · Passwort gesetzt' : '') : 'keine'}</dd>
          <dt class="hint">Umgebung</dt><dd class="mono">${parsed.env}</dd>
          <dt class="hint">Truststore</dt><dd>${(parsed.trustStore ?? []).length} Zertifikat(e) der Serveridentität</dd>
        </dl>` : null}
      <p class="mono small muted">GET ${admin.konPath(client)}</p>
    </section>`;
}

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
 * Page 5 · profile: vendor profile (decision-10) and strict (LIANA-126), GET/PUT /admin/vendor; catalog of the
 * deviations (GET /admin/deviations) and management settings CARD_SESSION_TIMEOUT and MGM_LU_ONLINE
 * (GET/PUT /admin/settings), LIANA-151.
 */
import { html, useState, useEffect } from '../vendor/preact-htm.js';
import { admin } from '../api.js';
import { usePoll, Badge, ApiProblem, Empty, Field, notify, notifyError, toApiError } from '../ui.js';

/** Profiles as in liana.vendor (docs/handbuch.md, Admin-API) with their effect in one sentence. */
const VENDORS = [
  ['neutral', 'nur Spezifikation'],
  ['KOCO', 'Fehlerbilder KoCo'],
  ['RISE', 'Fehlerbilder RISE'],
  ['SECUNET', 'Fehlerbilder secunet, KMS wie EHEX'],
  ['EHEX', 'KMS unter /rest/mgmt'],
  ['CGM', 'Fehlerbilder CGM'],
];

export function Profile() {
  const vendor = usePoll(admin.vendor, [], { on: ['state'] });
  const v = vendor.data;
  const [selected, setSelected] = useState(/** @type {string | null} */ (null));
  const [strict, setStrict] = useState(/** @type {boolean | null} */ (null));
  const [busy, setBusy] = useState(false);
  // selection follows the server until something is changed
  useEffect(() => {
    if (v && selected === null) setSelected(v.vendor);
    if (v && strict === null) setStrict(v.strict);
  }, [v]);

  const sel = selected ?? v?.vendor;
  const str = strict ?? v?.strict ?? false;
  const dirty = v && (sel !== v.vendor || str !== v.strict);

  /** @param {{ vendor: string, strict: boolean }} body */
  const apply = (body) => {
    setBusy(true);
    admin.putVendor(body).then((state) => {
      setBusy(false);
      setSelected(state.vendor);
      setStrict(state.strict);
      notify('ok', 'Profil ' + state.vendor + ', strict ' + (state.strict ? 'an' : 'aus'), 'PUT /admin/vendor');
      vendor.reload();
    }, (error) => {
      setBusy(false);
      notifyError(error);
    });
  };

  return html`
    <h1>Profil</h1>
    <${ApiProblem} error=${vendor.error} />
    <section aria-labelledby="h-vendor" class="panel pad narrow">
      <div class="title-row">
        <h2 id="h-vendor">Herstellerprofil</h2>
        ${v ? (v.vendor === v.boot ? html`<${Badge} kind="off">wie beim Start<//>` : html`<${Badge} kind="warn">geändert · Start ${v.boot}<//>`) : null}
      </div>
      <p class="muted">Bestimmt, wie LIANA sich als Konnektor eines Herstellers verhält: Fehlerbilder, ProductVendorID im Dienstverzeichnis und welches KMS erreichbar ist.</p>
      <div role="radiogroup" aria-labelledby="h-vendor" class="options">
        ${VENDORS.map(([id, note]) => html`
          <button class="opt" type="button" role="radio" aria-checked=${sel === id ? 'true' : 'false'} onClick=${() => setSelected(id)}>
            <span class="mono strong">${id}</span>
            <span class="hint">${note}${v && id === v.boot ? ' · Start' : ''}${v && id === v.vendor ? ' · aktiv' : ''}</span>
          </button>`)}
      </div>
    </section>

    <section aria-labelledby="h-strict" class="panel pad narrow">
      <div class="title-row">
        <h2 id="h-strict">strict</h2>
        ${v ? (v.strict === v.strictBoot ? html`<${Badge} kind="off">wie beim Start<//>` : html`<${Badge} kind="warn">geändert · Start ${v.strictBoot ? 'an' : 'aus'}<//>`) : null}
      </div>
      <button class="switch" type="button" role="switch" aria-checked=${str ? 'true' : 'false'} onClick=${() => setStrict(!str)}>
        <span class="track" aria-hidden="true"><span class="knob"></span></span>
        <span>Abweichungen der Gegenstellen nicht tolerieren (${str ? 'an' : 'aus'})</span>
      </button>
      <p class="muted">Aus: LIANA weicht bei bekannten Abweichungen von kartos und Terminals aus und schreibt LIANA/DEVIATION (Warning) ins Systemprotokoll. An: dieselben Fälle schlagen fehl (Error), wie die Spezifikation es verlangt.</p>
    </section>

    <div class="row-actions narrow">
      <button class="btn btn-primary" type="button" disabled=${!dirty || busy}
          onClick=${() => sel && apply({ vendor: sel, strict: str })}>Übernehmen</button>
      <button class="btn" type="button" disabled=${!v || busy || (v.vendor === v.boot && v.strict === v.strictBoot)}
          onClick=${() => v && apply({ vendor: v.boot, strict: v.strictBoot })}>Auf Startwerte</button>
      <span class="mono hint">PUT /admin/vendor {"vendor": "${sel ?? '…'}", "strict": ${String(str)}}</span>
    </div>

    <${Deviations} />
    <${Settings} />`;
}

/** Catalog of the known deviations of the peers (kern.vendor.Deviation). */
function Deviations() {
  const deviations = usePoll(admin.deviations, [], { on: ['state'] });
  const d = deviations.data;
  return html`
    <${ApiProblem} error=${deviations.error} />
    <section aria-labelledby="h-dev" class="panel">
      <div class="panel-head">
        <h2 id="h-dev">Katalog der Abweichungen</h2>
        ${d ? (d.strict ? html`<${Badge} kind="warn">strict: schlagen fehl<//>` : html`<${Badge} kind="ok">LIANA weicht aus<//>`) : null}
        <span class="hint">was strict betrifft; jede genutzte Ausweichung steht als LIANA/DEVIATION im Systemprotokoll</span>
      </div>
      ${d && d.deviations.length === 0 ? html`<${Empty} title="Keine bekannten Abweichungen">strict ändert dann nichts.<//>` : html`
        <div class="scroll">
          <table>
            <thead><tr><th scope="col">Abweichung</th><th scope="col">Gegenstelle</th><th scope="col">Spec</th>
              <th scope="col">Beobachtet</th><th scope="col">Rückfall</th></tr></thead>
            <tbody>${(d?.deviations ?? []).map((/** @type {any} */ x) => html`
              <tr key=${x.id}>
                <td class="mono strong">${x.id}</td><td>${x.peer}</td><td>${x.spec}</td><td>${x.observed}</td><td>${x.fallback}</td>
              </tr>`)}
            </tbody>
          </table>
        </div>`}
      <div class="panel-foot"><span class="mono hint">GET /admin/deviations</span></div>
    </section>`;
}

/** CARD_SESSION_TIMEOUT (TAB_KON_554, 10–180 s) and MGM_LU_ONLINE (TAB_KON_658), PUT /admin/settings. */
function Settings() {
  const settings = usePoll(admin.settings, [], { on: ['state'] });
  const s = settings.data;
  const [timeout, setTimeoutValue] = useState(/** @type {string | null} */ (null));
  const [online, setOnline] = useState(/** @type {boolean | null} */ (null));
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  // inputs follow the server until something is changed (also after a change via the KMS)
  useEffect(() => {
    if (s) {
      setTimeoutValue(null);
      setOnline(null);
    }
  }, [s?.cardSessionTimeout, s?.luOnline]);

  const value = timeout ?? (s ? String(s.cardSessionTimeout) : '');
  const on = online ?? s?.luOnline ?? false;
  const dirty = s && (value !== String(s.cardSessionTimeout) || on !== s.luOnline);
  const check = () => (/^\d+$/.test(value) && Number(value) >= 10 && Number(value) <= 180 ? '' : 'CARD_SESSION_TIMEOUT: 10–180 Sekunden');

  /** @param {{ cardSessionTimeout: number, luOnline: boolean }} body */
  const apply = (body) => {
    setBusy(true);
    admin.putSettings(body).then((state) => {
      setBusy(false);
      setError('');
      notify('ok', 'CARD_SESSION_TIMEOUT ' + state.cardSessionTimeout + ' s, Online-Modus ' + (state.luOnline ? 'an' : 'aus'), 'PUT /admin/settings');
      settings.reload();
    }, (e) => {
      setBusy(false);
      const apiError = toApiError(e);
      if (apiError.status === 400) {
        setError(apiError.message);
      } else {
        notifyError(e);
      }
    });
  };
  const submit = (/** @type {Event} */ e) => {
    e.preventDefault();
    const problem = check();
    setError(problem);
    if (!problem) {
      apply({ cardSessionTimeout: Number(value), luOnline: on });
    }
  };

  return html`
    <${ApiProblem} error=${settings.error} />
    <section aria-labelledby="h-set" class="panel pad narrow">
      <div class="title-row">
        <h2 id="h-set">Management-Einstellungen</h2>
        ${s ? (s.cardSessionTimeout === s.cardSessionTimeoutBoot ? html`<${Badge} kind="off">wie beim Start<//>`
          : html`<${Badge} kind="warn">geändert · Start ${s.cardSessionTimeoutBoot} s<//>`) : null}
        <span class="hint">unabhängig vom Herstellerprofil; im Profil EHEX oder SECUNET auch über das KMS</span>
      </div>
      <form id="settings-form" class="settings" novalidate onSubmit=${submit}>
        <${Field} id="set-timeout" label="CARD_SESSION_TIMEOUT (TAB_KON_554)" error=${error} hint="Sekunden, 10–180; gilt für neue Kartensitzungen">
          <div class="inline-field">
            <input id="set-timeout" class="mono" type="number" min="10" max="180" value=${value}
                aria-invalid=${error ? 'true' : undefined} aria-describedby=${error ? 'set-timeout-error' : undefined}
                onInput=${(/** @type {any} */ e) => { setTimeoutValue(e.target.value); setError(''); }} />
            <span class="muted">s</span>
          </div>
        <//>
        <button class="switch" type="button" role="switch" aria-checked=${on ? 'true' : 'false'} onClick=${() => setOnline(!on)}>
          <span class="track" aria-hidden="true"><span class="knob"></span></span>
          <span>Online-Modus (MGM_LU_ONLINE, TAB_KON_658): ${on ? 'an' : 'aus'}</span>
        </button>
      </form>
      <div class="row-actions">
        <button class="btn btn-primary" type="submit" form="settings-form" disabled=${!dirty || busy}>Einstellungen übernehmen</button>
        <button class="btn" type="button" disabled=${!s || busy || s.cardSessionTimeout === s.cardSessionTimeoutBoot}
            onClick=${() => s && apply({ cardSessionTimeout: s.cardSessionTimeoutBoot, luOnline: on })}>Timeout auf Startwert</button>
        <span class="mono hint">PUT /admin/settings {"cardSessionTimeout": ${value || '…'}, "luOnline": ${String(on)}}</span>
      </div>
    </section>`;
}

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
 * Control Center (LIANA-148, decision-018): frame, navigation via hash (#/terminals …), readiness and
 * reachability of the admin API, reset. Every page fetches its own data and reloads on events from
 * GET /admin/events (LIANA-150, LIANA-151); without a stream every 2 s.
 */
import { html, render, useState, useEffect } from './vendor/preact-htm.js';
import { admin, ApiError } from './api.js';
import { usePoll, useLive, Badge, Dialog, Notes, notify, notifyError, POLL_MS } from './ui.js';
import { Overview } from './pages/overview.js';
import { Terminals } from './pages/terminals.js';
import { Log } from './pages/log.js';
import { Subscriptions } from './pages/subscriptions.js';
import { Tls } from './pages/tls.js';
import { Profile } from './pages/profile.js';
import { Infomodel } from './pages/infomodel.js';

/** @typedef {{ id: string, label: string, page: (props: { openReset: () => void }) => any }} Route */

/** @type {Route[]} */
const ROUTES = [
  { id: '', label: 'Übersicht', page: Overview },
  { id: 'terminals', label: 'Kartenterminals', page: Terminals },
  { id: 'log', label: 'Systemprotokoll', page: Log },
  { id: 'subscriptions', label: 'Ereignis-Abos', page: Subscriptions },
  { id: 'tls', label: 'TLS / mTLS', page: Tls },
  { id: 'profile', label: 'Profil', page: Profile },
  { id: 'infomodel', label: 'Infomodell & .kon', page: Infomodel },
];

/** Page from the hash; a remainder after the page is a jump target within it (#/tls/pki). */
function currentRoute() {
  const id = location.hash.replace(/^#\/?/, '').split('/')[0];
  return ROUTES.find((r) => r.id === id) ?? ROUTES[0];
}

const THEME_KEY = 'liana.theme';

/** @returns {'light' | 'dark' | null} */
function storedTheme() {
  try {
    const value = localStorage.getItem(THEME_KEY);
    return value === 'light' || value === 'dark' ? value : null;
  } catch (e) {
    return null;
  }
}

/** Light/dark according to the system; the toggle remembers the choice in the browser. */
function useTheme() {
  const media = window.matchMedia('(prefers-color-scheme: dark)');
  const [chosen, setChosen] = useState(storedTheme());
  const [system, setSystem] = useState(media.matches ? 'dark' : 'light');
  useEffect(() => {
    const listener = (/** @type {MediaQueryListEvent} */ e) => setSystem(e.matches ? 'dark' : 'light');
    media.addEventListener('change', listener);
    return () => media.removeEventListener('change', listener);
  }, []);
  const theme = chosen ?? system;
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);
  const toggle = () => {
    const next = theme === 'dark' ? 'light' : 'dark';
    setChosen(next);
    try {
      localStorage.setItem(THEME_KEY, next);
    } catch (e) {
      // only for this session
    }
  };
  return { theme, toggle };
}

/**
 * Readiness (GET /admin/ready): 503 means „startet noch“, no response „nicht erreichbar“. With an open stream
 * LIANA is ready and reachable; it is checked only without a stream.
 * @param {boolean} streaming
 */
function useReadiness(streaming) {
  const [state, setState] = useState(/** @type {{ kind: 'ok' | 'starting' | 'down', since?: number, last?: number }} */ ({ kind: 'ok' }));
  const check = () => admin.ready().then(
    () => setState({ kind: 'ok', last: Date.now() }),
    (/** @type {unknown} */ error) => setState((s) => {
      if (error instanceof ApiError && error.status === 503) {
        return { kind: 'starting', last: Date.now() };
      }
      return { kind: 'down', since: s.kind === 'down' ? s.since : Date.now(), last: s.last };
    }));
  useEffect(() => {
    check();
    if (streaming) {
      return undefined;
    }
    const timer = setInterval(check, POLL_MS);
    return () => clearInterval(timer);
  }, [streaming]);
  return { ...state, check };
}

function App() {
  const [route, setRoute] = useState(currentRoute());
  const [resetOpen, setResetOpen] = useState(false);
  const { theme, toggle } = useTheme();
  const streaming = useLive();
  const readiness = useReadiness(streaming);
  const info = usePoll(admin.info, [], { on: ['state'] });
  const vendor = usePoll(admin.vendor, [], { on: ['state'] });

  useEffect(() => {
    const listener = () => setRoute(currentRoute());
    window.addEventListener('hashchange', listener);
    return () => window.removeEventListener('hashchange', listener);
  }, []);
  useEffect(() => {
    document.title = 'LIANA – ' + route.label;
  }, [route]);

  const Page = route.page;
  const i = info.data;
  const v = vendor.data;
  return html`
    <div class="app">
      <header class="top">
        <div class="brand">
          <svg class="logo" viewBox="-4 -4 338 112" role="img" aria-label="LIANA"><path d="M50 4 C 44 18, 58 28, 50 42 C 42 56, 30 66, 38 80 C 44 90, 62 88, 64 76 C 66 66, 54 62, 48 70 C 42 80, 50 92, 64 92 H 98" fill="none" class="ink-line" stroke-width="5.5" stroke-linecap="round" stroke-linejoin="round"/> <path d="M0 0 C10 -11 25 -11 34 -2 C23 -5 11 -3 0 0Z" class="ink" transform="translate(51 20) rotate(-18)"/> <path d="M0 0 C10 -11 25 -11 34 -2 C23 -5 11 -3 0 0Z" fill="#f57f1c" transform="translate(47 42) rotate(196)"/> <path d="M0 0 C10 -11 25 -11 34 -2 C23 -5 11 -3 0 0Z" class="ink" transform="translate(40 60) rotate(-10) scale(.85)"/> <path d="M80.97 84V37.42H87.54V84ZM73.52 42.76V37.42H87.54V42.76ZM82.38 28.79Q80.03 28.79 78.86 27.53Q77.69 26.27 77.69 24.32Q77.69 22.37 78.86 21.09Q80.03 19.82 82.39 19.82Q84.75 19.82 85.91 21.09Q87.07 22.37 87.07 24.32Q87.07 26.27 85.92 27.53Q84.76 28.79 82.38 28.79Z M132.21 84V70.04H131.1V53.43Q131.1 48.24 128.39 45.49Q125.67 42.73 119.92 42.73Q117.34 42.73 114.66 42.83Q111.97 42.93 109.55 43.05Q107.13 43.17 105.29 43.37V37.57Q107.16 37.36 109.22 37.2Q111.27 37.04 113.43 36.98Q115.58 36.92 117.58 36.92Q124.67 36.92 129.03 38.68Q133.39 40.44 135.41 44.19Q137.43 47.95 137.43 54.08V84ZM116.46 85.23Q111.5 85.23 107.73 83.49Q103.97 81.74 101.87 78.4Q99.77 75.05 99.77 70.3Q99.77 65.58 101.93 62.32Q104.08 59.07 108.19 57.37Q112.3 55.66 118.1 55.66H131.74V60.71H117.69Q112.15 60.71 109.19 63.38Q106.22 66.05 106.22 70.33Q106.22 74.73 109.3 77.34Q112.38 79.95 117.69 79.95Q120.92 79.95 123.91 78.75Q126.9 77.55 128.91 74.69Q130.92 71.83 131.1 66.87L133.09 69.57Q132.74 74.76 130.6 78.24Q128.46 81.71 124.87 83.47Q121.27 85.23 116.46 85.23Z M152.95 84V37.42H158.17V56.95H157.11Q157.11 50.44 159.05 45.78Q160.99 41.11 164.87 38.59Q168.76 36.07 174.63 36.07H174.92Q183.72 36.07 188.05 41.55Q192.37 47.04 192.37 56.95V84H185.8V55.55Q185.8 49.5 182.47 45.81Q179.14 42.11 173.13 42.11Q166.97 42.11 163.25 45.93Q159.52 49.74 159.52 56.02V84Z M236.17 84V70.04H235.05V53.43Q235.05 48.24 232.34 45.49Q229.62 42.73 223.87 42.73Q221.29 42.73 218.61 42.83Q215.93 42.93 213.51 43.05Q211.09 43.17 209.24 43.37V37.57Q211.11 37.36 213.17 37.2Q215.22 37.04 217.38 36.98Q219.53 36.92 221.53 36.92Q228.63 36.92 232.98 38.68Q237.34 40.44 239.36 44.19Q241.39 47.95 241.39 54.08V84ZM220.41 85.23Q215.46 85.23 211.69 83.49Q207.92 81.74 205.82 78.4Q203.72 75.05 203.72 70.3Q203.72 65.58 205.88 62.32Q208.03 59.07 212.14 57.37Q216.25 55.66 222.06 55.66H235.7V60.71H221.65Q216.1 60.71 213.14 63.38Q210.18 66.05 210.18 70.33Q210.18 74.73 213.26 77.34Q216.34 79.95 221.65 79.95Q224.87 79.95 227.86 78.75Q230.86 77.55 232.87 74.69Q234.87 71.83 235.05 66.87L237.05 69.57Q236.69 74.76 234.55 78.24Q232.41 81.71 228.82 83.47Q225.22 85.23 220.41 85.23Z" class="ink"/></svg>
          <span class="mono muted">${i ? i.version + ' · env ' + i.env : '…'}</span>
        </div>
        ${readiness.kind === 'ok' ? html`<${Badge} kind="ok">bereit<//>` : null}
        ${readiness.kind === 'starting' ? html`<${Badge} kind="warn">nicht bereit<//>` : null}
        ${readiness.kind === 'down' ? html`<${Badge} kind="err">nicht erreichbar<//>` : null}
        ${readiness.kind === 'ok' ? html`<span title=${streaming ? 'Ereignisse per Push (GET /admin/events)' : 'kein Stream, Abfrage alle 2 s'}>
          <${Badge} kind=${streaming ? 'ok' : 'off'}>${streaming ? 'live' : 'Polling'}<//></span>` : null}
        ${v ? html`<${Badge} kind=${v.vendor === v.boot ? 'info' : 'warn'}>Profil ${v.vendor}${v.vendor === v.boot ? '' : ' (geändert)'}<//>` : null}
        ${v ? html`<${Badge} kind=${v.strict === v.strictBoot ? 'off' : 'warn'}>strict ${v.strict ? 'an' : 'aus'}${v.strict === v.strictBoot ? '' : ' (geändert)'}<//>` : null}
        <div class="grow"></div>
        <button class="btn" type="button" onClick=${toggle} aria-label=${theme === 'dark' ? 'Helles Farbschema' : 'Dunkles Farbschema'}>
          ${theme === 'dark' ? 'Hell' : 'Dunkel'}
        </button>
        <button class="btn btn-danger" type="button" onClick=${() => setResetOpen(true)}>Zurücksetzen …</button>
      </header>

      <div class="memory" role="note">
        <strong>Nur im Speicher.</strong>
        <span>Änderungen hier gelten bis zum Zurücksetzen oder Neustart. Danach gilt wieder die Startkonfiguration (application.yaml).</span>
      </div>

      <div class="body">
        <nav aria-label="Bereiche" class="side">
          ${ROUTES.map((r) => html`
            <a class="nav" href=${'#/' + r.id} aria-current=${r === route ? 'page' : undefined}>${r.label}</a>`)}
        </nav>
        <main class="main">
          ${readiness.kind === 'starting' ? html`
            <section class="state">
              <${Badge} kind="warn">nicht bereit<//>
              <h2>LIANA startet noch</h2>
              <p>GET /admin/ready antwortet 503. Terminals werden verbunden, Karten eingelesen. Die Seite prüft alle 2 s erneut.</p>
              <div><button class="btn" type="button" onClick=${readiness.check}>Jetzt erneut prüfen</button></div>
            </section>` : null}
          ${readiness.kind === 'down' ? html`
            <section class="state">
              <${Badge} kind="err">nicht erreichbar<//>
              <h2>Keine Verbindung zur Admin-API</h2>
              <p>${location.host} antwortet nicht. Läuft LIANA?${readiness.last
                ? ' Letzter Kontakt vor ' + Math.round((Date.now() - readiness.last) / 1000) + ' s; angezeigte Daten sind veraltet.'
                : ''}</p>
              <div><button class="btn btn-primary" type="button" onClick=${readiness.check}>Erneut verbinden</button></div>
            </section>` : null}
          <${Page} openReset=${() => setResetOpen(true)} />
        </main>
      </div>
      ${resetOpen ? html`<${ResetDialog} onClose=${() => setResetOpen(false)} />` : null}
      <${Notes} />
    </div>`;
}

/** POST /admin/reset with the list of what gets lost (AdminApi.reset). @param {{ onClose: () => void }} props */
function ResetDialog({ onClose }) {
  const [busy, setBusy] = useState(false);
  const reset = () => {
    setBusy(true);
    admin.reset().then(
      () => {
        notify('ok', 'LIANA auf den Startzustand zurückgesetzt', 'POST /admin/reset');
        onClose();
      },
      (error) => {
        setBusy(false);
        notifyError(error);
      });
  };
  return html`
    <${Dialog} title="LIANA auf den Startzustand zurücksetzen?" onClose=${onClose} actions=${html`
        <button class="btn" type="button" onClick=${onClose}>Abbrechen</button>
        <button class="btn btn-danger" type="button" disabled=${busy} onClick=${reset}>Zurücksetzen</button>`}>
      <p class="muted">Alle Änderungen seit dem Start gehen verloren. Zurückgesetzt werden:</p>
      <ul class="list">
        <li>Ereignis-Abos (Subscriptions) und das Systemprotokoll</li>
        <li>Karten in Fake-Terminals (frisch aus dem Image), Störungen und PIN-Skripte, CATS- und Robot-Zustand</li>
        <li>Pairings der SICCT-Terminals (zurück auf die Konfiguration)</li>
        <li>Herstellerprofil und strict (zurück auf die Startwerte)</li>
        <li>KMS-Einstellungen, Client-Bindung, Server- und Client-Zertifikate</li>
      </ul>
      <p class="mono small muted">POST /admin/reset</p>
    <//>`;
}

render(html`<${App} />`, /** @type {HTMLElement} */ (document.getElementById('app')));

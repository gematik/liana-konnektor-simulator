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
 * Page Verkehr (LIANA-195.03, layout LIANA-195.05, time ranges LIANA-195.06): status of the Traffic-Push, the channels with what LIANA reports
 * where (GET /admin/trace), each switchable (PUT /admin/trace/channels/{id}), and the message list of the linked Tiger
 * proxy through the Admin API (no CORS, the proxy need not be reachable from the browser). The filter starts with
 * LIANA's own messages; an opened message shows its metadata and links to the Tiger WebUI, which renders it.
 * #/trace/<from>/<to> opens a time window (Systemprotokoll, Kartensitzungen).
 */
import { html, useState, useEffect, useRef } from '../vendor/preact-htm.js';
import { admin, ApiError } from '../api.js';
import { usePoll, Badge, ApiProblem, Empty, clock, notify, notifyError, POLL_MS } from '../ui.js';

/** At most this many messages in the list, the newest first. */
const SHOWN = 500;

/**
 * Tiger's info string; for messages it cannot summarize (APDUs, CETP) it sends a placeholder, and does not know
 * whether they are a request. @param {any} m
 */
const info = (m) => (m.infoString && m.infoString !== '<noMenuInfoString>' ? m.infoString : '–');

/** @param {string} value */
const isoOrEmpty = (value) => !value || !Number.isNaN(new Date(value).getTime());

/**
 * Messages from or to LIANA: every address LIANA reports starts with its name (Name/IP:Port, <name>-KT-01:<slot>,
 * LIANA-195.04). @param {string} name
 */
export const lianaFilter = (name) => `$.sender =~ '${name}.*' || $.receiver =~ '${name}.*'`;

/** Time window from the hash: #/trace/<from>/<to>, each part may be empty. */
function windowFromHash() {
  const [, from = '', to = ''] = location.hash.replace(/^#\/?/, '').split('/').map(decodeURIComponent);
  return { from, to };
}

/** Time ranges of the message list (LIANA-195.06): minutes back from now, or since the start of LIANA. */
const RANGES = [
  { id: '5m', label: '5 min', minutes: 5 },
  { id: '15m', label: '15 min', minutes: 15 },
  { id: '1h', label: '1 h', minutes: 60 },
  { id: '24h', label: '24 h', minutes: 24 * 60 },
  { id: 'start', label: 'Seit Start' },
  { id: 'custom', label: 'Eigener …' },
];

/** What an empty Von of the own range means: 15 min back, since the start, or no window (the newest {@link SHOWN}). */
const FALLBACKS = [
  { id: '15m', label: '15 min' },
  { id: 'start', label: 'Seit Start' },
  { id: 'last', label: `Letzte ${SHOWN}` },
];

/**
 * Start of the window as ISO-8601, '' for none. @param {string} range @param {string} started start of LIANA
 * @param {{ from: string, fallback: string }} custom
 */
function windowStart(range, started, custom) {
  const preset = RANGES.find((r) => r.id === range && r.minutes);
  if (preset?.minutes) {
    return new Date(Date.now() - preset.minutes * 60_000).toISOString();
  }
  if (range === 'start') {
    return started;
  }
  if (custom.from) {
    return new Date(custom.from).toISOString();
  }
  return custom.fallback === 'last' ? '' : windowStart(custom.fallback, started, custom);
}

/** Segmented choice. @param {{ label: string, options: { id: string, label: string }[], value: string, onChange: (id: string) => void }} props */
function Segments({ label, options, value, onChange }) {
  return html`
    <div class="seg" role="group" aria-label=${label}>
      ${options.map((o) => html`
        <button key=${o.id} class="seg-btn" type="button" aria-pressed=${value === o.id ? 'true' : 'false'}
            onClick=${() => onChange(o.id)}>${o.label}</button>`)}
    </div>`;
}

const arrowIcon = html`<svg aria-hidden="true" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor"
  stroke-width="2" stroke-linecap="round"><path d="M7 17L17 7M9 7h8v8"></path></svg>`;

export function Trace() {
  const overview = usePoll(admin.trace, [], { on: ['state'] });
  // the counters change with every push, the event stream does not report them
  useEffect(() => {
    const timer = setInterval(() => {
      if (!document.hidden) {
        overview.reload();
      }
    }, 5000);
    return () => clearInterval(timer);
  }, []);
  const o = overview.data;
  return html`
    <div class="title-row">
      <h1>Verkehr</h1>
      <span class="muted">Selbstauskunft an den Tiger-Proxy</span>
      <span class="grow"></span>
      ${o?.webUi ? html`<a class="btn btn-sm" href=${o.webUi} target="_blank" rel="noopener noreferrer">Tiger-WebUI ${arrowIcon}</a>` : null}
    </div>
    <${ApiProblem} error=${overview.error} />
    ${o ? html`<${Status} overview=${o} />` : null}
    ${o ? html`<${Channels} routes=${o.routes ?? []} push=${o.push.state !== 'off'} onChanged=${overview.reload} />` : null}
    ${o && o.push.state !== 'off' ? html`<${Messages} name=${o.name} webUi=${o.webUi} />` : null}`;
}

/** Traffic-Push: state, target, name in the trace, counters since the start. @param {{ overview: any }} props */
function Status({ overview }) {
  const push = overview.push;
  if (push.state === 'off') {
    return html`
      <section aria-label="Weiterleitung" class="panel">
        <${Empty} title="Kein Tiger-Proxy verknüpft">
          Ohne liana.trace.push-url (Env LIANA_TRACE_PUSH_URL, Admin-Port des Proxys) meldet LIANA nichts. Die Kanäle zeigen,
          was mit gesetzter URL wohin ginge.
        <//>
      </section>`;
  }
  const failing = push.state === 'failing';
  return html`
    <section aria-label="Weiterleitung" class="panel trace-status">
      <div class="trace-status-head">
        <span class=${'trace-state ' + (failing ? 'is-err' : 'is-ok')} role="status">
          <span class="trace-dot" aria-hidden="true"></span>${failing ? 'Push scheitert' : 'Push aktiv'}
        </span>
        <span class="mono small muted ellipsis">POST ${push.target}</span>
        <span class="grow"></span>
        <span class="mono small muted">als <span class="trace-name">${overview.name}</span> · Timeout ${seconds(push.timeout)}</span>
      </div>
      <div class="trace-tiles">
        <${Tile} label="Zugestellt" value=${push.delivered} />
        <${Tile} label="Fehlgeschlagen" value=${push.failed} err=${push.failed > 0 && failing} />
        <${Tile} label="Verloren (Warteschlange voll)" value=${push.dropped} err=${push.dropped > 0} />
        <${Tile} label="Letzter Fehler" value=${push.lastError ?? 'keiner'} err=${failing} text />
      </div>
    </section>`;
}

/** @param {{ label: string, value: any, err?: boolean, text?: boolean }} props */
function Tile({ label, value, err, text }) {
  return html`
    <div class="trace-tile">
      <span class="label">${label}</span>
      <span class=${'mono ' + (text ? 'trace-tile-text' : 'trace-tile-figure') + (err ? ' is-err' : '')}>${value}</span>
    </div>`;
}

/** ISO-8601 duration of the push timeout as seconds: PT0.5S → 0,5 s. @param {string} duration */
function seconds(duration) {
  const match = /^PT([\d.]+)S$/.exec(duration ?? '');
  return match ? match[1].replace('.', ',') + ' s' : duration;
}

/**
 * The channels of this start, one row each with its switch; open, a row shows what LIANA reports and how it appears
 * in the Tiger log. Channels without id never report (Admin API, control interface of a CT).
 * @param {{ routes: any[], push: boolean, onChanged: () => void }} props
 */
function Channels({ routes, push, onChanged }) {
  const [open, setOpen] = useState(/** @type {string | null} */ (null));
  // the switch flips at once; an overview from the server with the same state ends that
  const [flipped, setFlipped] = useState(/** @type {Record<string, boolean>} */ ({}));
  useEffect(() => setFlipped((f) => Object.fromEntries(Object.entries(f).filter(([id, value]) =>
    routes.some((r) => r.id === id && r.on !== value)))), [routes]);
  const shown = routes.map((r) => (r.id && r.id in flipped ? { ...r, on: flipped[r.id], pushed: r.pushed && flipped[r.id] } : r));
  const switchable = shown.filter((r) => r.id);
  const on = switchable.filter((r) => r.on).length;
  /** @param {any} r */
  const flip = async (r) => {
    setFlipped({ ...flipped, [r.id]: !r.on });
    try {
      await admin.traceChannel(r.id, !r.on);
      notify('ok', `${r.channel}: ${r.on ? 'aus' : 'an'}`, 'PUT /admin/trace/channels/' + r.id);
    } catch (e) {
      setFlipped(({ [r.id]: _, ...rest }) => rest);
      notifyError(e);
    }
    onChanged();
  };
  return html`
    <section aria-labelledby="h-kanal" class="panel">
      <div class="panel-head">
        <h2 id="h-kanal">Kanäle</h2>
        <span class="hint">${on} von ${switchable.length} ${push ? 'gespiegelt' : 'an'}</span>
        <span class="grow"></span>
        <span class="mono hint" title="Jede Meldung trägt tgr-supplementary: ein Proxy, der dieselbe Nachricht auf der Leitung sieht, behält eine Kopie">tgr-supplementary</span>
      </div>
      ${shown.map((r) => {
        const expanded = open === r.channel;
        const [name, sub] = split(r.channel);
        return html`
          <div key=${r.channel} class="trace-channel">
            <div class="trace-channel-line">
              <button class="row trace-channel-row" type="button" aria-expanded=${expanded ? 'true' : 'false'}
                  onClick=${() => setOpen(expanded ? null : r.channel)}>
                <svg class="chevron" aria-hidden="true" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                  stroke-width="2" stroke-linecap="round"><path d="M9 6l6 6-6 6"></path></svg>
                <span class="trace-channel-name">
                  <span class=${r.on ? 'strong' : 'strong muted'}>${name}</span>
                  ${sub ? html`<span class="hint">${sub}</span>` : null}
                </span>
                <span class="mono small muted trace-channel-wire">${r.endpoint}</span>
              </button>
              ${r.id ? html`
                <button class="switch trace-switch" type="button" role="switch" aria-checked=${r.on ? 'true' : 'false'}
                    aria-label=${name + ' an den Tiger-Proxy spiegeln'} onClick=${() => flip(r)}>
                  <span class="small">${r.pushed ? 'gespiegelt' : r.on ? 'an' : 'aus'}</span>
                  <span class="track" aria-hidden="true"><span class="knob"></span></span>
                </button>` : html`<span class="trace-switch" title="Nicht schaltbar: meldet nie"><${Badge} kind="off">nie<//></span>`}
            </div>
            ${expanded ? html`
              <dl class="kv trace-channel-facts">
                <dt class="label">Meldet</dt><dd>${r.parts}</dd>
                <dt class="label">Im Tiger-Log</dt><dd class="mono small">${r.trace ?? '–'}</dd>
                ${r.note ? html`<dt class="label">Hinweis</dt><dd>${r.note}</dd>` : null}
                ${r.id ? html`<dt class="label">Kanal-ID</dt><dd class="mono small">${r.id}</dd>` : null}
              </dl>` : null}
          </div>`;
      })}
      <div class="panel-foot"><span class="mono hint">GET /admin/trace · PUT /admin/trace/channels/{id}; Zurücksetzen schaltet alle an</span></div>
    </section>`;
}

/** "Konnektor-Schnittstelle (SOAP /ws/*, …)" → name and the part in parentheses. @param {string} channel */
function split(channel) {
  const match = /^(.*?) \((.*)\)$/.exec(channel);
  return match ? [match[1], match[2]] : [channel, ''];
}

/**
 * Messages in the proxy, filtered to LIANA from the start: first the window, then live only what is newer
 * (minTimestamp of the newest one); a proxy with fewer messages than before was reset and is read again.
 * @param {{ name: string, webUi: string | null }} props
 */
function Messages({ name, webUi }) {
  const initial = windowFromHash();
  const linked = !!(initial.from || initial.to);
  const [range, setRange] = useState(linked ? 'custom' : '15m');
  // the own range: inputs, and what Anwenden applied
  const [fromInput, setFromInput] = useState(initial.from);
  const [toInput, setToInput] = useState(initial.to);
  const [fallbackInput, setFallbackInput] = useState('15m');
  const [custom, setCustom] = useState({ from: initial.from, to: initial.to, fallback: '15m' });
  const [started, setStarted] = useState('');
  const [filterInput, setFilterInput] = useState(lianaFilter(name));
  const [filter, setFilter] = useState(lianaFilter(name));
  const [live, setLive] = useState(!initial.to);
  const [attempt, setAttempt] = useState(0);
  const [messages, setMessages] = useState(/** @type {any[]} */ ([]));
  const [error, setError] = useState(/** @type {ApiError | undefined} */ (undefined));
  // Tiger evaluates the filter over all messages; with thousands that takes seconds
  const [loading, setLoading] = useState(true);
  const [open, setOpen] = useState(/** @type {string | null} */ (null));
  const known = useRef({ total: 0, newest: '' });

  useEffect(() => {
    admin.info().then((i) => setStarted(i.started ?? ''), () => {});
  }, []);

  useEffect(() => {
    const listener = () => {
      const w = windowFromHash();
      if (w.from || w.to) {
        setFromInput(w.from);
        setToInput(w.to);
        setCustom({ from: w.from, to: w.to, fallback: fallbackInput });
        setRange('custom');
        setLive(!w.to);
      }
    };
    window.addEventListener('hashchange', listener);
    return () => window.removeEventListener('hashchange', listener);
  }, []);

  const inputsValid = isoOrEmpty(fromInput.trim()) && isoOrEmpty(toInput.trim());
  const toIso = range === 'custom' && custom.to ? new Date(custom.to).toISOString() : '';
  // "Seit Start" waits for the start time from /admin/info
  const ready = !(range === 'start' || (range === 'custom' && !custom.from && custom.fallback === 'start')) || !!started;
  const sliding = RANGES.find((r) => r.id === (range === 'custom' && !custom.from ? custom.fallback : range))?.minutes;
  const [fromIso, setFromIso] = useState('');

  useEffect(() => {
    if (!ready) {
      return undefined;
    }
    const start = windowStart(range, started, custom);
    setFromIso(start);
    let cancelled = false;
    known.current = { total: 0, newest: '' };
    setMessages([]);
    setOpen(null);
    setLoading(true);
    let pending = false;
    const load = () => {
      // live polls more often than Tiger may answer; one request at a time
      if (pending) {
        return;
      }
      pending = true;
      const k = known.current;
      const since = k.newest && (!start || Date.parse(k.newest) > Date.parse(start)) ? k.newest : start;
      admin.traceMessages(filter, since, toIso).finally(() => {
        pending = false;
      }).then(
        (data) => {
          if (cancelled) {
            return;
          }
          setError(undefined);
          setLoading(false);
          const incoming = /** @type {any[]} */ (data.messages ?? []);
          const reset = data.total < k.total;
          known.current = {
            total: data.total,
            newest: incoming.reduce((n, m) => (m.timestamp && (!n || Date.parse(m.timestamp) > Date.parse(n)) ? m.timestamp : n),
              reset ? '' : k.newest),
          };
          setMessages((current) => {
            const byUuid = new Map((reset ? [] : current).map((m) => [m.uuid, m]));
            incoming.forEach((m) => byUuid.set(m.uuid, m));
            // a preset slides along: what falls out of the last n minutes leaves the list
            const oldest = sliding ? Date.now() - sliding * 60_000 : 0;
            return [...byUuid.values()]
              .filter((m) => !oldest || !m.timestamp || Date.parse(m.timestamp) >= oldest).sort((a, b) => b.sequenceNumber - a.sequenceNumber).slice(0, SHOWN);
          });
        },
        (e) => {
          if (!cancelled) {
            setError(e instanceof ApiError ? e : new ApiError(500, String(e), undefined));
            setLoading(false);
          }
        });
    };
    load();
    if (!live) {
      return () => {
        cancelled = true;
      };
    }
    const timer = setInterval(() => {
      if (!document.hidden) {
        load();
      }
    }, POLL_MS);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [filter, range, custom, started, ready, live, attempt]);

  const apply = () => {
    setCustom({ from: fromInput.trim(), to: toInput.trim(), fallback: fallbackInput });
    setLive(!toInput.trim());
  };

  const unreachable = error && (error.status === 502 || error.status === 0);
  const own = filter === lianaFilter(name);
  return html`
    <section aria-labelledby="h-msg" class="panel">
      <div class="panel-head trace-msg-head">
        <h2 id="h-msg">Nachrichten</h2>
        <span class="mono hint" title=${'im Proxy ' + known.current.total}>${messages.length}${messages.length === SHOWN ? '+' : ''}</span>
        <span class="grow"></span>
        <${Segments} label="Zeitraum" options=${RANGES} value=${range} onChange=${(/** @type {string} */ id) => {
          setRange(id);
          if (id !== 'custom') {
            setLive(true);
          }
        }} />
        <form class="trace-filter" onSubmit=${(/** @type {Event} */ e) => { e.preventDefault(); setFilter(filterInput.trim()); }}>
          <label class="sr-only" for="t-filter">Filter (Tiger: JEXL oder "Text"), Enter wendet an</label>
          <svg aria-hidden="true" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
            stroke-linecap="round"><circle cx="11" cy="11" r="7"></circle><path d="M20 20l-4-4"></path></svg>
          <input id="t-filter" class="mono trace-input" type="text" value=${filterInput} placeholder='Filter – JEXL oder "Text"'
              title="Tiger-Filter, Enter wendet an; leer zeigt alle Nachrichten im Proxy"
              onInput=${(/** @type {any} */ e) => setFilterInput(e.target.value)} />
        </form>
        ${own ? null : html`<button class="btn btn-sm" type="button"
            onClick=${() => { setFilterInput(lianaFilter(name)); setFilter(lianaFilter(name)); }}>Nur ${name}</button>`}
        <button class=${'btn btn-sm' + (live ? ' trace-live' : '')} type="button" aria-pressed=${live ? 'true' : 'false'}
            onClick=${() => setLive(!live)}>
          <span class="trace-dot" aria-hidden="true"></span>Live
        </button>
      </div>
      ${range === 'custom' ? html`
        <form class="trace-custom" onSubmit=${(/** @type {Event} */ e) => { e.preventDefault(); if (inputsValid) apply(); }}>
          <div class="field">
            <label for="t-from">Von</label>
            <input id="t-from" class="mono trace-input trace-time" type="text" value=${fromInput} placeholder="2026-11-16 12:00"
                aria-invalid=${isoOrEmpty(fromInput.trim()) ? undefined : 'true'} onInput=${(/** @type {any} */ e) => setFromInput(e.target.value)} />
          </div>
          <span class="trace-dash" aria-hidden="true">–</span>
          <div class="field">
            <label for="t-to">Bis</label>
            <input id="t-to" class="mono trace-input trace-time" type="text" value=${toInput} placeholder="jetzt"
                aria-invalid=${isoOrEmpty(toInput.trim()) ? undefined : 'true'} onInput=${(/** @type {any} */ e) => setToInput(e.target.value)} />
          </div>
          <div class="field">
            <span class="label" id="t-fallback">Wenn leer, zurückfallen auf</span>
            <${Segments} label="Wenn Von leer ist, zurückfallen auf" options=${FALLBACKS} value=${fallbackInput} onChange=${setFallbackInput} />
          </div>
          <span class="grow"></span>
          <button class="btn btn-primary" type="submit" disabled=${!inputsValid}>Anwenden</button>
          ${inputsValid ? null : html`<span class="field-error trace-custom-error">Zeit erwartet, z. B. 2026-11-16 12:00 oder 2026-11-16T12:00:00Z</span>`}
        </form>` : null}
      ${unreachable ? html`
        <div class="trace-unreachable" role="alert">
          <span class="trace-unreachable-icon" aria-hidden="true">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
              <path d="M2 2l20 20M8.5 16.5a5 5 0 017 0M5 12.9a10 10 0 015.2-2.8M19 12.9a10 10 0 00-2.1-1.5M12 20h.01"></path></svg>
          </span>
          <span class="strong">Tiger-Proxy nicht erreichbar</span>
          <span class="mono small muted">${error.status || '—'} · ${error.message}</span>
          <button class="btn btn-sm" type="button" onClick=${() => setAttempt(attempt + 1)}>Erneut versuchen</button>
        </div>` : html`
        ${error ? html`<div class="pad-box"><${ApiProblem} error=${error} /></div>` : null}
        <div class="scroll">
          <div class="log trace">
            <div class="trace-grid log-header"><span>#</span><span>Zeit</span><span>Absender → Empfänger</span><span>Nachricht</span></div>
            ${messages.map((m) => {
              const expanded = open === m.uuid;
              return html`
                <div key=${m.uuid} class="log-row">
                  <button class="row" type="button" aria-expanded=${expanded ? 'true' : 'false'} onClick=${() => setOpen(expanded ? null : m.uuid)}>
                    <span class="trace-grid">
                      <span class="mono muted">${m.sequenceNumber}</span>
                      <span class="mono" title=${m.timestamp}>${m.timestamp ? clock(m.timestamp) : '–'}</span>
                      <span class="mono ellipsis">${m.sender} → ${m.recipient}</span>
                      <span class=${m.request ? 'mono strong ellipsis' : 'mono ellipsis'}>${info(m)}</span>
                    </span>
                  </button>
                  ${expanded ? html`<${Meta} message=${m} webUi=${webUi} />` : null}
                </div>`;
            })}
            ${messages.length === 0 && !error && loading ? html`
              <div class="empty-row" role="status">Lade Nachrichten aus dem Tiger-Proxy …</div>` : null}
            ${messages.length === 0 && !error && !loading ? html`
              <div class="empty-row">
                <span class="strong">${filter || fromIso || toIso ? 'Keine Nachrichten für diesen Filter' : 'Noch keine Nachrichten'}</span><br />
                <span class="hint">${own ? `Sobald ${name} Verkehr meldet, erscheint er hier.` : 'Leerer Filter zeigt alle Nachrichten im Proxy.'}</span>
              </div>` : null}
          </div>
        </div>`}
      <div class="panel-foot"><span class="mono hint">GET /admin/trace/messages${filter ? ' · ' + filter : ''}${fromIso ? ' ab ' + fromIso : ''}${toIso ? ' bis ' + toIso : ''}</span></div>
    </section>`;
}

/** Order of the known fields of getMessagesWithMeta; others follow as Tiger sends them. */
const FIELDS = ['uuid', 'sequenceNumber', 'timestamp', 'sender', 'recipient', 'request', 'infoString', 'additionalInfoStrings',
  'pairedSequenceNumbers', 'offset'];

/** @param {unknown} value */
const show = (value) => (Array.isArray(value) ? (value.length ? value.join(', ') : '–')
  : value === null || value === undefined || value === '' ? '–' : String(value));

/**
 * All metadata Tiger sends for a message, and the link to it in the Tiger WebUI, which renders it
 * (/webui/message/{uuid}, Tiger 4.1+). @param {{ message: any, webUi: string | null }} props
 */
function Meta({ message, webUi }) {
  const keys = [...FIELDS.filter((k) => k in message), ...Object.keys(message).filter((k) => !FIELDS.includes(k))];
  const link = webUi ? webUi.replace(/\/?$/, '/') + 'message/' + encodeURIComponent(message.uuid) : null;
  return html`
    <div class="trace-meta">
      <dl class="kv">
        ${keys.map((k) => html`<dt class="label mono">${k}</dt><dd class="mono small">${show(message[k])}</dd>`)}
      </dl>
      ${link ? html`<div><a class="btn btn-sm" href=${link} target="_blank" rel="noopener noreferrer">In der Tiger-WebUI öffnen ${arrowIcon}</a></div>` : null}
    </div>`;
}

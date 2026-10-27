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
 * Building blocks of the pages: badge, dialog, field, error display (page 7 of the design), push and polling,
 * notifications.
 */
import { html, useState, useEffect, useRef, useCallback } from './vendor/preact-htm.js';
import { admin, ApiError } from './api.js';

/** Polling interval, only while the stream of the admin events is not open (fallback, LIANA-150). */
export const POLL_MS = 2000;

/** Reloading after events is batched so that a reset with many events loads only once. */
const RELOAD_DELAY_MS = 50;

/** All kinds on which a view without explicit kinds reloads (subscription and session since LIANA-151). */
const ALL_EVENTS = ['log', 'card', 'terminal', 'state', 'subscription', 'session'];

/**
 * One stream for all pages (GET /admin/events, LIANA-150). {@code open}: events arrive, polling rests.
 * If it breaks off, the browser reconnects by itself (with Last-Event-ID); until then the pages poll. After
 * reconnecting and after {@code resync} all views reload.
 */
const live = (() => {
  /** @type {Set<(type: string, data: any) => void>} */
  const listeners = new Set();
  /** @type {Set<(open: boolean) => void>} */
  const watchers = new Set();
  let open = false;
  /** @type {EventSource | null} */
  let source = null;
  const setOpen = (/** @type {boolean} */ value) => {
    if (open !== value) {
      open = value;
      watchers.forEach((w) => w(value));
    }
  };
  const emit = (/** @type {string} */ type, /** @type {any} */ data) => listeners.forEach((l) => l(type, data));
  function connect() {
    if (source || typeof EventSource === 'undefined') {
      return;
    }
    source = admin.events();
    source.onopen = () => {
      setOpen(true);
      emit('resync', null);
    };
    source.onerror = () => {
      setOpen(false);
      if (source && source.readyState === EventSource.CLOSED) {
        // 503 (too many streams) or no stream: retry later, polling until then
        source = null;
        setTimeout(connect, 5000);
      }
    };
    for (const type of [...ALL_EVENTS, 'resync']) {
      source.addEventListener(type, (e) => {
        let data = null;
        try {
          data = JSON.parse(/** @type {MessageEvent} */ (e).data);
        } catch (err) {
          data = null;
        }
        emit(type, data);
      });
    }
  }
  return {
    connect,
    isOpen: () => open,
    /** @param {(type: string, data: any) => void} listener */
    subscribe(listener) {
      connect();
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    /** @param {(open: boolean) => void} watcher */
    watch(watcher) {
      connect();
      watchers.add(watcher);
      return () => watchers.delete(watcher);
    },
  };
})();

/** Whether the stream is open (header: „live“ or „Polling“). */
export function useLive() {
  const [open, setOpen] = useState(live.isOpen());
  useEffect(() => live.watch(setOpen), []);
  return open;
}

/**
 * Loads {@code load} immediately and then again on every event of the kinds {@code on} (default all); without an open
 * stream every POLL_MS, as long as the page is visible.
 * @template T
 * @param {() => Promise<T>} load
 * @param {unknown[]} deps
 * @param {{ live?: boolean, on?: string[] }} [options] live false: only on open and on reload()
 * @returns {{ data: T | undefined, error: ApiError | undefined, reload: () => void }}
 */
export function usePoll(load, deps, options = {}) {
  const active = options.live ?? true;
  const on = options.on ?? ALL_EVENTS;
  const [state, setState] = useState(/** @type {{ data: T | undefined, error: ApiError | undefined }} */ ({
    data: undefined, error: undefined,
  }));
  const loadRef = useRef(load);
  loadRef.current = load;
  const run = useCallback(() => {
    loadRef.current().then(
      (data) => setState({ data, error: undefined }),
      (error) => setState((s) => ({ data: s.data, error: toApiError(error) })));
  }, []);
  useEffect(() => {
    run();
    if (!active) {
      return undefined;
    }
    /** @type {ReturnType<typeof setTimeout> | null} */
    let pending = null;
    const unsubscribe = live.subscribe((type) => {
      if ((type === 'resync' || on.includes(type)) && pending === null) {
        pending = setTimeout(() => {
          pending = null;
          run();
        }, RELOAD_DELAY_MS);
      }
    });
    const timer = setInterval(() => {
      if (!document.hidden && !live.isOpen()) {
        run();
      }
    }, POLL_MS);
    return () => {
      unsubscribe();
      clearInterval(timer);
      if (pending !== null) {
        clearTimeout(pending);
      }
    };
  }, [...deps, active]);
  return { data: state.data, error: state.error, reload: run };
}

/** @param {unknown} error */
export function toApiError(error) {
  return error instanceof ApiError ? error : new ApiError(500, String(error), undefined);
}

/**
 * Badge; the state is always also shown as text, not only as color.
 * @param {{ kind?: 'ok' | 'warn' | 'err' | 'off' | 'info', children: any }} props
 */
export function Badge({ kind = 'off', children }) {
  return html`<span class=${'badge b-' + kind}>${children}</span>`;
}

/**
 * Modal dialog with title and actions; Escape and Cancel close it, the first field gets the focus.
 * @param {{ title: any, onClose: () => void, children: any, actions: any, wide?: boolean }} props
 */
export function Dialog({ title, onClose, children, actions, wide }) {
  const ref = useRef(/** @type {HTMLDivElement | null} */ (null));
  useEffect(() => {
    const first = ref.current?.querySelector('input, select, textarea, button.btn-primary, button.btn-danger');
    if (first instanceof HTMLElement) {
      first.focus();
    }
  }, []);
  /** @param {KeyboardEvent} e */
  const onKeyDown = (e) => {
    if (e.key === 'Escape') {
      e.stopPropagation();
      onClose();
    }
  };
  return html`
    <div class="backdrop" onClick=${(/** @type {MouseEvent} */ e) => e.target === e.currentTarget && onClose()}>
      <div class=${wide ? 'dialog wide' : 'dialog'} role="dialog" aria-modal="true" aria-labelledby="dialog-title"
          ref=${ref} onKeyDown=${onKeyDown}>
        <h2 id="dialog-title">${title}</h2>
        ${children}
        <div class="actions">${actions}</div>
      </div>
    </div>`;
}

/**
 * Input field with label, hint and error at the field (400/404 of the API, own validation).
 * @param {{ id: string, label: string, error?: string, hint?: string, children: any }} props
 */
export function Field({ id, label, error, hint, children }) {
  return html`
    <div class="field">
      <label for=${id}>${label}</label>
      ${children}
      ${error ? html`<span class="field-error" id=${id + '-error'}>${error}</span>` : null}
      ${!error && hint ? html`<span class="hint">${hint}</span>` : null}
    </div>`;
}

/**
 * Response of the admin API as a box: 409 with connector error code as alert, 501 neutral (decision-12, not an error
 * of the UI), everything else as an error with status.
 * @param {{ error: ApiError | undefined, onClose?: () => void }} props
 */
export function ApiProblem({ error, onClose }) {
  if (!error) {
    return null;
  }
  const close = onClose ? html`<div><button class="btn btn-sm" type="button" onClick=${onClose}>Schließen</button></div>` : null;
  if (error.status === 501) {
    return html`
      <div class="problem neutral" role="status">
        <div class="problem-head"><span class="mono">501</span><span>In LIANA nicht umgesetzt</span></div>
        <span class="mono small">${error.message}</span>
        ${close}
      </div>`;
  }
  if (error.status === 409) {
    return html`
      <div class="problem" role="alert">
        <div class="problem-head"><span class="mono">409</span><span>Vom Konnektor abgelehnt</span></div>
        ${error.code ? html`<span>Konnektor-Fehler <span class="mono strong">${error.code}</span></span>` : null}
        <span class="mono small">${error.message}</span>
        ${close}
      </div>`;
  }
  return html`
    <div class="problem" role="alert">
      <div class="problem-head"><span class="mono">${error.status || '—'}</span><span>${error.status === 0 ? 'Keine Verbindung' : 'Fehler'}</span></div>
      <span class="mono small">${error.message}</span>
      ${close}
    </div>`;
}

/** @typedef {{ id: number, kind: 'ok' | 'err' | 'neutral', text: any, detail?: string }} Note */

/** @type {(note: Note) => void} */
let push = () => {};
let nextId = 1;

/**
 * Confirmation after an action (role=status) or error of an action, without a dialog.
 * @param {'ok' | 'err' | 'neutral'} kind
 * @param {any} text
 * @param {string} [detail] e.g. the event topic
 */
export function notify(kind, text, detail) {
  push({ id: nextId++, kind, text, detail });
}

/**
 * Error of an action as a notification; 501 neutral.
 * @param {unknown} error
 */
export function notifyError(error) {
  const e = toApiError(error);
  if (e.status === 501) {
    notify('neutral', 'In LIANA nicht umgesetzt (501)', e.message);
  } else {
    notify('err', (e.status ? e.status + ' · ' : '') + (e.code ? 'Konnektor-Fehler ' + e.code + ' · ' : '') + e.message);
  }
}

/** Area for the notifications at the bottom right; 6 s per notification. */
export function Notes() {
  const [notes, setNotes] = useState(/** @type {Note[]} */ ([]));
  useEffect(() => {
    push = (note) => {
      setNotes((n) => [...n.slice(-3), note]);
      setTimeout(() => setNotes((n) => n.filter((x) => x.id !== note.id)), 6000);
    };
    return () => {
      push = () => {};
    };
  }, []);
  return html`
    <div class="notes" role="status" aria-live="polite">
      ${notes.map((n) => html`
        <div key=${n.id} class=${'note note-' + n.kind}>
          <span>${n.text}</span>
          ${n.detail ? html`<span class="mono small">${n.detail}</span>` : null}
          <button class="btn-icon" type="button" aria-label="Meldung schließen"
              onClick=${() => setNotes((all) => all.filter((x) => x.id !== n.id))}>×</button>
        </div>`)}
    </div>`;
}

/**
 * Text to the clipboard, with notification.
 * @param {string} text
 * @param {string} what
 */
export function copy(text, what) {
  if (!navigator.clipboard) {
    notify('err', 'Zwischenablage nicht verfügbar (nur über HTTPS oder localhost)');
    return;
  }
  navigator.clipboard.writeText(text).then(
    () => notify('ok', what + ' kopiert'),
    () => notify('err', what + ' nicht kopiert'));
}

/** Empty state of an area. @param {{ title: string, children?: any }} props */
export function Empty({ title, children }) {
  return html`<div class="empty"><span class="strong">${title}</span>${children ? html`<span class="hint">${children}</span>` : null}</div>`;
}

/** Copy icon (inline, without font). */
export const copyIcon = html`<svg aria-hidden="true" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor"
  stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="12" height="12" rx="2"></rect>
  <path d="M5 15V5a2 2 0 0 1 2-2h10"></path></svg>`;

/** Time of a log entry (ISO-8601 UTC) as local time with milliseconds. @param {string} iso */
export function clock(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) {
    return iso;
  }
  const p = (/** @type {number} */ n, /** @type {number} */ w = 2) => String(n).padStart(w, '0');
  return p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds()) + '.' + p(d.getMilliseconds(), 3);
}

/** Date and time (ISO-8601) local, without seconds. @param {string | undefined} iso */
export function dateTime(iso) {
  if (!iso) {
    return '–';
  }
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) {
    return iso;
  }
  const p = (/** @type {number} */ n) => String(n).padStart(2, '0');
  return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' + p(d.getHours()) + ':' + p(d.getMinutes());
}

/**
 * Distance to now in words: „in 8 s“, „vor 3 min“, „in 17 Tagen“.
 * @param {string | undefined} iso
 * @param {number} [now]
 */
export function relative(iso, now = Date.now()) {
  if (!iso) {
    return '';
  }
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) {
    return '';
  }
  const seconds = Math.round((t - now) / 1000);
  const abs = Math.abs(seconds);
  const text = abs < 90 ? abs + ' s' : abs < 5400 ? Math.round(abs / 60) + ' min' : abs < 172800 ? Math.round(abs / 3600) + ' h'
    : Math.round(abs / 86400) + ' Tagen';
  return seconds >= 0 ? 'in ' + text : 'vor ' + text;
}

/** Seconds tick for remaining times (card sessions); does not change the data. */
export function useTick(active = true) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    if (!active) {
      return undefined;
    }
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [active]);
  return now;
}

/** Class of the severity. @param {string} severity */
export function severityKind(severity) {
  switch ((severity || '').toLowerCase()) {
    case 'error':
    case 'fatal':
      return 'err';
    case 'warning':
      return 'warn';
    default:
      return 'info';
  }
}

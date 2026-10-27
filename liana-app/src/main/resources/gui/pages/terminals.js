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
 * Page 2 · card terminals: fake CTs with slots, insert/remove, faults (LIANA-41) and PIN script (LIANA-68);
 * eHealth CTs (SICCT) with CT object (TAB_KON_522), pairing (TUC_KON_053), shared secret and service discovery
 * (TUC_KON_054). kartos manages cards and faults in SICCT terminals (decision-11), the buttons are greyed out
 * there. Per slot the card from CM_CARD_LIST (TAB_KON_531), insert with a choice from the image catalog; below that
 * card sessions and verified PINs (LIANA-151).
 */
import { html, useState } from '../vendor/preact-htm.js';
import { admin } from '../api.js';
import { usePoll, useLive, useTick, Badge, Dialog, Field, ApiProblem, Empty, notify, notifyError, toApiError, copy, copyIcon,
  clock, relative } from '../ui.js';
import { terminalState } from './overview.js';

/** @typedef {{ kind: 'insert' | 'fault', kt: string, slot: number } | { kind: 'pin', kt: string }
 *   | { kind: 'secret' | 'unpair', kt: string }} DialogState */

export function Terminals() {
  const streaming = useLive();
  const terminals = usePoll(admin.terminals, [], { on: ['terminal', 'card', 'state'] });
  const ctList = usePoll(admin.ctList, [], { on: ['terminal', 'state'] });
  const sessions = usePoll(admin.sessions, [], { on: ['session', 'card', 'state'] });
  const [dialog, setDialog] = useState(/** @type {DialogState | null} */ (null));
  const [expanded, setExpanded] = useState(/** @type {string | null} */ (null));
  const [discovering, setDiscovering] = useState(false);

  const kts = /** @type {any[]} */ (terminals.data ?? []);
  const known = new Set(kts.map((kt) => kt.id));
  const announced = /** @type {any[]} */ (ctList.data ?? []).filter((ct) => !known.has(ct.CTID));
  const hasSicct = kts.some((kt) => kt.mode !== 'fake');
  /** Expand and collapse card details, per CT and slot. @param {string} key */
  const toggle = (key) => setExpanded((e) => (e === key ? null : key));
  const discover = () => {
    setDiscovering(true);
    admin.ctDiscovery().then(() => {
      setDiscovering(false);
      notify('ok', 'Dienstsuche für alle eHealth-KTs ausgelöst', 'TUC_KON_054');
      terminals.reload();
      ctList.reload();
    }, (error) => {
      setDiscovering(false);
      notifyError(error);
    });
  };
  const connected = kts.filter((kt) => terminalState(kt).connected).length;
  const close = () => setDialog(null);
  const done = () => {
    setDialog(null);
    terminals.reload();
    ctList.reload();
  };

  /**
   * Action without dialog, with notification and reload.
   * @param {Promise<unknown>} request
   * @param {string} text
   * @param {string} [topic]
   */
  const act = (request, text, topic) => request.then(() => {
    notify('ok', text, topic);
    terminals.reload();
  }, notifyError);

  return html`
    <div class="title-row">
      <h1>Kartenterminals</h1>
      <span class="muted">${kts.length} Terminals · ${connected} verbunden</span>
      <${Badge} kind=${streaming ? 'ok' : 'off'}>${streaming ? 'live' : 'Polling alle 2 s'}<//>
      <div class="grow"></div>
      ${hasSicct ? html`<button class="btn btn-sm" type="button" disabled=${discovering} onClick=${discover}
          title="POST /admin/ct-discovery: CT-Objects der konfigurierten eHealth-KTs neu anlegen bzw. aktualisieren">Dienstsuche (TUC_KON_054)</button>` : null}
    </div>
    <${ApiProblem} error=${terminals.error} />
    ${terminals.data && kts.length === 0 && announced.length === 0 ? html`
      <${Empty} title="Keine Kartenterminals">In der Startkonfiguration sind keine Terminals eingetragen, und keins hat sich per Discovery angekündigt.<//>` : null}
    ${kts.map((kt) => kt.mode === 'fake'
      ? html`<${FakeTerminal} key=${kt.id} kt=${kt} open=${setDialog} act=${act} expanded=${expanded} toggle=${toggle} />`
      : html`<${SicctTerminal} key=${kt.id} kt=${kt} open=${setDialog} act=${act} expanded=${expanded} toggle=${toggle} />`)}
    ${announced.map((ct) => html`
      <section class="panel kt" aria-labelledby=${'kt-' + ct.CTID}>
        <div class="kt-head">
          <h2 id=${'kt-' + ct.CTID} class="mono">${ct.CTID}</h2>
          <${Badge} kind="off">sicct<//>
          <${Badge} kind="off">${ct.CORRELATION} · nicht konfiguriert<//>
          <span class="muted small">per Discovery angekündigt · ${ct.IP_ADRESS ?? '?'}${ct.PRODUCTINFORMATION ? ' · ' + product(ct.PRODUCTINFORMATION) : ''}</span>
        </div>
      </section>`)}

    <${Sessions} sessions=${sessions} />

    ${dialog?.kind === 'insert' ? html`<${InsertDialog} kt=${dialog.kt} slot=${dialog.slot} onClose=${close} onDone=${done} />` : null}
    ${dialog?.kind === 'fault' ? html`<${FaultDialog} kt=${dialog.kt} slot=${dialog.slot} onClose=${close} onDone=${done} />` : null}
    ${dialog?.kind === 'pin' ? html`<${PinDialog} kt=${dialog.kt} onClose=${close} onDone=${done} />` : null}
    ${dialog?.kind === 'secret' ? html`<${SecretDialog} kt=${dialog.kt} onClose=${close} onDone=${done} />` : null}
    ${dialog?.kind === 'unpair' ? html`<${UnpairDialog} kt=${dialog.kt} onClose=${close} onDone=${done} />` : null}`;
}

/** @param {any} info PRODUCTINFORMATION of the CT object (GET STATUS, CTM-DO and product information) */
function product(info) {
  if (!info || typeof info !== 'object') {
    return String(info ?? '');
  }
  const parts = [info.ProductVendorID, info.ProductCode ?? info.ProductType, info.FWVersion && 'FW ' + info.FWVersion,
    info.HWVersion && 'HW ' + info.HWVersion].filter(Boolean);
  return parts.join(' · ');
}

/** @param {any} fault SlotFault of the admin API */
function faultDetail(fault) {
  const parts = [];
  if (fault.statusWord) parts.push(fault.statusWord);
  if (fault.response) parts.push(fault.response);
  if (fault.delayMs != null) parts.push(fault.delayMs + ' ms');
  if (fault.commandPrefix) parts.push('Präfix ' + fault.commandPrefix);
  if (fault.count != null) parts.push('noch ' + fault.count + '×');
  return parts.join(' · ');
}

/**
 * @typedef {{ kt: any, open: (d: DialogState) => void, act: (r: Promise<unknown>, t: string, topic?: string) => void,
 *   expanded: string | null, toggle: (key: string) => void }} TerminalProps
 */

/**
 * Button „Details“ for the card of a slot, only if LIANA has opened the card (CM_CARD_LIST).
 * @param {{ kt: string, slot: any, expanded: string | null, toggle: (key: string) => void }} props
 */
function DetailsToggle({ kt, slot, expanded, toggle }) {
  if (!slot.card) {
    return null;
  }
  const key = kt + '/' + slot.slot;
  const open = expanded === key;
  return html`<button class="btn-link" type="button" aria-expanded=${open ? 'true' : 'false'}
      aria-controls=${'card-' + key} onClick=${() => toggle(key)}>${open ? 'Details ausblenden' : 'Details'}</button>`;
}

/**
 * Row with the card from CM_CARD_LIST (TAB_KON_531) below the slot.
 * @param {{ kt: string, slot: any, expanded: string | null, columns: number }} props
 */
function CardDetails({ kt, slot, expanded, columns }) {
  const key = kt + '/' + slot.slot;
  if (!slot.card || expanded !== key) {
    return null;
  }
  const c = slot.card;
  const version = Object.entries(c.cardVersion ?? {}).map(([k, v]) => k + ' ' + v).join(' · ');
  return html`
    <tr class="details" id=${'card-' + key}>
      <td></td>
      <td colspan=${columns - 1}>
        <dl class="facts-dl">
          <div><dt class="hint">CardHandle</dt><dd class="mono">${c.cardHandle}</dd></div>
          <div><dt class="hint">ICCSN</dt><dd class="mono">${c.iccsn ?? '–'}</dd></div>
          <div><dt class="hint">Inhaber</dt><dd>${c.cardHolderName ?? '–'}</dd></div>
          ${c.cardType === 'EGK' ? html`<div><dt class="hint">KVNR</dt><dd class="mono">${c.kvnr ?? '–'}</dd></div>` : null}
          <div><dt class="hint">Zertifikat gültig bis</dt><dd class="mono">${c.certExpirationDate ?? '–'}</dd></div>
          <div><dt class="hint">Gesteckt</dt><dd class="mono">${clock(c.insertTime)}</dd></div>
          <div><dt class="hint">Kartenversion</dt><dd class="mono small">${version || '–'}</dd></div>
          <div><dt class="hint">Reserviert (A_25895)</dt><dd>${c.locked ? html`<${Badge} kind="warn">Kartensitzung<//>` : html`<${Badge} kind="off">frei<//>`}</dd></div>
        </dl>
      </td>
    </tr>`;
}

/** @param {TerminalProps} props */
function FakeTerminal({ kt, open, act, expanded, toggle }) {
  const id = kt.id;
  return html`
    <section class="panel kt" aria-labelledby=${'kt-' + id}>
      <div class="kt-head">
        <h2 id=${'kt-' + id} class="mono">${id}</h2>
        <${Badge} kind="off">fake<//>
        <${Badge} kind="ok">verfügbar<//>
        <div class="grow"></div>
        <div class="display"><span class="label">Display</span><span class="mono">${kt.display ?? '–'}</span></div>
      </div>
      <div class="scroll">
        <table>
          <thead><tr><th scope="col">Slot</th><th scope="col">Karte</th><th scope="col">Kartentyp</th><th scope="col">Störung</th><th scope="col">Aktionen</th></tr></thead>
          <tbody>${kt.slots.map((/** @type {any} */ s) => html`
            <tr>
              <td class="mono">${s.slot}</td>
              <td>${s.image ? html`<div class="strong">${s.image}</div><div class="mono small muted">${s.path}</div>
                  <${DetailsToggle} kt=${id} slot=${s} expanded=${expanded} toggle=${toggle} />`
                : html`<span class="muted">leer</span>`}</td>
              <td>${s.cardType ? html`<${Badge} kind=${s.cardType === 'UNKNOWN' ? 'warn' : 'info'}>${s.cardType}<//>
                ${s.unknownReason ? html`<div class="small muted">${s.unknownReason}</div>` : null}` : html`<span class="muted">–</span>`}</td>
              <td>${s.fault ? html`<${Badge} kind="warn">${s.fault.type}<//><div class="mono small muted">${faultDetail(s.fault)}</div>`
                : html`<span class="muted">–</span>`}</td>
              <td><div class="row-actions">
                ${s.image
                  ? html`<button class="btn btn-sm" type="button" onClick=${() => act(admin.removeCard(id, s.slot),
                      'Karte aus ' + id + ' Slot ' + s.slot + ' gezogen', 'CARD/REMOVED')}>Ziehen</button>`
                  : html`<button class="btn btn-sm btn-primary" type="button" onClick=${() => open({ kind: 'insert', kt: id, slot: s.slot })}>Karte stecken …</button>`}
                ${s.fault
                  ? html`<button class="btn btn-sm" type="button" onClick=${() => act(admin.removeFault(id, s.slot),
                      'Störung an ' + id + ' Slot ' + s.slot + ' gelöscht')}>Störung löschen</button>`
                  : html`<button class="btn btn-sm" type="button" onClick=${() => open({ kind: 'fault', kt: id, slot: s.slot })}>Störung …</button>`}
              </div></td>
            </tr>
            <${CardDetails} kt=${id} slot=${s} expanded=${expanded} columns=${5} />`)}
          </tbody>
        </table>
      </div>
      <div class="sub">
        <div class="sub-head">
          <h3>PIN-Skript</h3>
          <span class="hint">Wird bei den nächsten PIN-Eingaben am Terminal der Reihe nach abgespielt; ohne Eintrag tippt das PIN-Pad die konfigurierte PIN. PINs werden nie zurückgegeben.</span>
          <div class="grow"></div>
          <button class="btn btn-sm" type="button" onClick=${() => open({ kind: 'pin', kt: id })}>Eingabe anhängen …</button>
          <button class="btn btn-sm" type="button" disabled=${!kt.pinScript?.length}
              onClick=${() => act(admin.clearPinScript(id), 'PIN-Skript von ' + id + ' geleert')}>Leeren</button>
        </div>
        ${kt.pinScript?.length ? html`
          <ol class="script">${kt.pinScript.map((/** @type {any} */ e, /** @type {number} */ n) => html`
            <li>
              <span class="mono muted">${n + 1}</span>
              <${Badge} kind=${e.outcome === 'correct' ? 'ok' : e.outcome === 'wrong' ? 'err' : 'off'}>${e.outcome}<//>
              <span>${e.slotNo ? 'Slot ' + e.slotNo : 'jeder Slot'}</span>
              ${e.outcome === 'digits' ? html`<span class="mono muted">PIN ••••••</span>` : null}
            </li>`)}
          </ol>` : html`<span class="muted small">leer</span>`}
      </div>
    </section>`;
}

const STEPS = ['bekannt', 'zugewiesen', 'gepairt', 'aktiv'];

/** @param {TerminalProps} props */
function SicctTerminal({ kt, open, act, expanded, toggle }) {
  const id = kt.id;
  const ct = kt.ct;
  const state = terminalState(kt);
  const reason = 'Karten und Störungen in SICCT-Terminals verwaltet der Kartensimulator kartos, nicht LIANA (decision-11).';
  const used = kt.slots.filter((/** @type {any} */ s) => s.cardType).length;
  return html`
    <section class="panel kt" aria-labelledby=${'kt-' + id}>
      <div class="kt-head">
        <h2 id=${'kt-' + id} class="mono">${id}</h2>
        <${Badge} kind="off">sicct<//>
        <${Badge} kind=${state.kind}>${state.text}<//>
        <div class="grow"></div>
        <button class=${ct && ct.CORRELATION === 'bekannt' ? 'btn btn-sm btn-primary' : 'btn btn-sm'} type="button" disabled=${!ct}
            onClick=${() => act(admin.pair(id, {}), 'Pairing mit ' + id + ' ausgelöst', 'TUC_KON_053')}>Pairing auslösen</button>
        <button class="btn btn-sm" type="button" disabled=${!ct} onClick=${() => open({ kind: 'secret', kt: id })}>Shared Secret setzen …</button>
        <button class="btn btn-sm btn-danger" type="button" disabled=${!ct?.SHARED_SECRET} onClick=${() => open({ kind: 'unpair', kt: id })}>Pairing lösen …</button>
      </div>
      ${ct ? html`
        <div class="sicct">
          <ol aria-label="Zustand (CT.CORRELATION)" class="steps">
            ${STEPS.map((step, n) => html`
              ${n > 0 ? html`<li aria-hidden="true" class="arrow">→</li>` : null}
              <li class=${ct.CORRELATION === step || (step === 'aktiv' && ct.CORRELATION === 'aktualisierend') ? 'step current' : 'step'}
                  aria-current=${ct.CORRELATION === step ? 'step' : undefined}>${step}</li>`)}
          </ol>
          <dl class="facts-dl">
            <div><dt class="hint">IP / Port</dt><dd class="mono">${ct.IP_ADRESS ?? '–'}:${ct.TCP_PORT ?? '–'}</dd></div>
            <div><dt class="hint">MAC</dt><dd class="mono">${ct.MAC_ADRESS ?? '–'}</dd></div>
            <div><dt class="hint">Hostname</dt><dd class="mono">${ct.HOSTNAME ?? '–'}</dd></div>
            <div><dt class="hint">Produkt</dt><dd>${product(ct.PRODUCTINFORMATION) || '–'}</dd></div>
            <div><dt class="hint">eHealth-Interface</dt><dd class="mono">${ct.EHEALTH_INTERFACE_VERSION ?? '–'} · ${ct.VALID_VERSION ? 'gültig' : 'nicht gültig'}</dd></div>
            <div><dt class="hint">Slots</dt><dd class="mono">${ct.SLOTCOUNT ?? 0} · ${used} belegt</dd></div>
            <div><dt class="hint">Display</dt><dd>${ct.DISPLAY_CAPABILITIES ? 'vorhanden' : 'keins'}</dd></div>
            <div><dt class="hint">Shared Secret</dt><dd>${ct.SHARED_SECRET ? html`<${Badge} kind="ok">gesetzt<//>` : html`<${Badge} kind="off">keins<//>`}</dd></div>
            <div><dt class="hint">Aktive Rolle</dt><dd class="mono">${ct.ACTIVEROLE ?? '–'}</dd></div>
          </dl>
          ${ct.SMKT_AUT ? html`
            <div class="cert">
              <span class="hint">C.SMKT.AUT</span>
              <span>${ct.SMKT_AUT.subject}</span>
              <div class="fingerprint">
                <span class="mono small muted">SHA-256 ${ct.SMKT_AUT.fingerprint}</span>
                <button class="btn btn-icon" type="button" aria-label="Fingerprint kopieren"
                    onClick=${() => copy(ct.SMKT_AUT.fingerprint, 'Fingerprint')}>${copyIcon}</button>
              </div>
            </div>` : null}
          ${kt.slots.length ? html`
            <div class="scroll">
              <table>
                <thead><tr><th scope="col">Slot</th><th scope="col">Kartentyp</th></tr></thead>
                <tbody>${kt.slots.map((/** @type {any} */ s) => html`
                  <tr><td class="mono">${s.slot}</td><td>${s.cardType ? html`<${Badge} kind=${s.cardType === 'UNKNOWN' ? 'warn' : 'info'}>${s.cardType}<//>
                    <${DetailsToggle} kt=${id} slot=${s} expanded=${expanded} toggle=${toggle} />` : html`<span class="muted">leer</span>`}</td></tr>
                  <${CardDetails} kt=${id} slot=${s} expanded=${expanded} columns=${2} />`)}
                </tbody>
              </table>
            </div>` : null}
          <div class="disabled-note">
            <span>${reason}</span>
            <div class="grow"></div>
            <button class="btn btn-sm" type="button" disabled title=${reason}>Karte stecken</button>
            <button class="btn btn-sm" type="button" disabled title=${reason}>Störung</button>
          </div>
        </div>` : html`<div class="muted small">Noch kein CT-Object: die Dienstsuche hat das KT nicht gefunden (TUC_KON_054).</div>`}
    </section>`;
}

/**
 * Field error from the response: 400 and 404 belong to the field, everything else as a box.
 * @param {unknown} error
 * @param {(m: string) => void} setField
 * @param {(e: any) => void} setProblem
 */
function fieldOrProblem(error, setField, setProblem) {
  const e = toApiError(error);
  if (e.status === 400 || e.status === 404) {
    setField(e.message);
    setProblem(undefined);
  } else {
    setField('');
    setProblem(e);
  }
}

/** Value of the selection for an image outside the catalog (no image name starts with „:“). */
const OTHER = ':anderes';

/**
 * PUT /admin/terminals/{id}/slots/{n} {"image": …}: choice from the image catalog (GET /admin/images, LIANA-98) or a
 * custom path. @param {{ kt: string, slot: number, onClose: () => void, onDone: () => void }} props
 */
function InsertDialog({ kt, slot, onClose, onDone }) {
  const images = usePoll(admin.images, [], { live: false });
  const catalog = /** @type {any[]} */ (images.data?.images ?? []);
  const [choice, setChoice] = useState('');
  const [path, setPath] = useState('');
  const [error, setError] = useState('');
  const [problem, setProblem] = useState(/** @type {any} */ (undefined));
  // without a catalog (empty or not loadable) only the path
  const other = choice === OTHER || (images.data !== undefined && catalog.length === 0) || images.error !== undefined;
  const selected = choice || (catalog[0]?.name ?? '');
  const image = other ? path.trim() : selected;
  const submit = (/** @type {Event} */ e) => {
    e.preventDefault();
    if (!image) {
      setError(other ? 'Image angeben: Dateiname, ICCSN oder absoluter Pfad' : 'Image wählen');
      return;
    }
    admin.putCard(kt, slot, image).then(() => {
      notify('ok', html`Karte <span class="mono">${image}</span> in <span class="mono">${kt}</span> Slot ${slot} gesteckt.`, 'CARD/INSERTED');
      onDone();
    }, (err) => fieldOrProblem(err, setError, setProblem));
  };
  return html`
    <${Dialog} title=${html`Karte stecken · <span class="mono">${kt} Slot ${slot}</span>`} onClose=${onClose} actions=${html`
        <button class="btn" type="button" onClick=${onClose}>Abbrechen</button>
        <button class="btn btn-primary" type="submit" form="insert-form">Stecken</button>`}>
      <form id="insert-form" onSubmit=${submit} class="form">
        ${catalog.length ? html`
          <${Field} id="f-cat" label="Image aus dem Katalog" error=${other ? '' : error}
              hint=${'liana.card-images: ' + (images.data?.directories ?? []).join(', ') + '. Eine gesteckte Karte wird ersetzt.'}>
            <select id="f-cat" class="mono" value=${other ? OTHER : selected}
                onChange=${(/** @type {any} */ e) => { setChoice(e.target.value); setError(''); }}>
              ${catalog.map((i) => html`<option value=${i.name}>${i.name}${i.iccsn ? ' · ' + i.iccsn : ''}</option>`)}
              <option value=${OTHER}>Anderes Image (Dateiname, ICCSN oder Pfad) …</option>
            </select>
          <//>` : null}
        ${other ? html`
          <${Field} id="f-img" label=${catalog.length ? 'Anderes Image' : 'Image'} error=${error}
              hint="Dateiname oder ICCSN aus liana.card-images, oder absoluter Pfad. Eine gesteckte Karte wird ersetzt.">
            <input id="f-img" class="mono" type="text" value=${path} placeholder="/work/cards/eigene.xml" autocomplete="off"
                aria-invalid=${error ? 'true' : undefined} aria-describedby=${error ? 'f-img-error' : undefined}
                onInput=${(/** @type {any} */ e) => { setPath(e.target.value); setError(''); }} />
          <//>` : null}
      </form>
      <${ApiProblem} error=${problem} />
      <p class="mono small muted">PUT /admin/terminals/${kt}/slots/${slot}</p>
    <//>`;
}

/**
 * Card sessions (A_25970-01) with remaining time of the APDU scenario timer (A_25860-01) and verified PINs
 * (CARDSESSION.AUTHSTATE, TUC_KON_026), only PinRef. @param {{ sessions: { data: any, error: any } }} props
 */
function Sessions({ sessions }) {
  const s = sessions.data;
  const open = /** @type {any[]} */ (s?.cardSessions ?? []);
  const pins = /** @type {any[]} */ (s?.verifiedPins ?? []);
  const now = useTick(open.length > 0);
  return html`
    <${ApiProblem} error=${sessions.error} />
    <section aria-labelledby="h-sess" class="panel">
      <div class="panel-head">
        <h2 id="h-sess">Kartensitzungen</h2>
        <${Badge} kind="info">${open.length}<//>
        <span class="hint">PoPP-Sitzungen (A_25970-01) mit Ablauf des APDU-Szenario-Timers (A_25860-01)</span>
      </div>
      ${open.length === 0 ? html`<${Empty} title="Keine Kartensitzung offen">StartCardSession am CardService öffnet eine; sie endet mit StopCardSession, Timeout oder Ziehen der Karte.<//>` : html`
        <div class="scroll">
          <table>
            <thead><tr><th scope="col">SessionID</th><th scope="col">Karte</th><th scope="col">KT · Slot</th><th scope="col">Timer</th><th scope="col">Läuft ab</th></tr></thead>
            <tbody>${open.map((x) => html`
              <tr key=${x.sessionId}>
                <td class="mono" title=${x.sessionId}>${x.sessionId.slice(0, 8)}…</td>
                <td class="mono">${x.cardHandle}</td>
                <td class="mono">${x.ctId} · ${x.slotNo}</td>
                <td><${Badge} kind=${x.timer === 'PoPP' ? 'info' : 'off'}>${x.timer}<//></td>
                <td class="mono nowrap">${clock(x.deadline)} · ${relative(x.deadline, now)}</td>
              </tr>`)}
            </tbody>
          </table>
        </div>`}
      <div class="sub">
        <div class="sub-head">
          <h3>PIN-Status</h3>
          <span class="hint">Verifizierte PINs (CARDSESSION.AUTHSTATE, TUC_KON_026) je Karte, Mandant und Clientsystem; nur PinRef, nie die PIN</span>
        </div>
        ${pins.length === 0 ? html`<span class="muted small">keine PIN verifiziert</span>` : html`
          <div class="scroll">
            <table>
              <thead><tr><th scope="col">Karte</th><th scope="col">Mandant</th><th scope="col">Clientsystem</th><th scope="col">PinRef</th></tr></thead>
              <tbody>${pins.map((x) => html`
                <tr key=${x.cardHandle + x.mandantId + x.clientSystemId + x.pinRef}>
                  <td class="mono">${x.cardHandle}</td><td class="mono">${x.mandantId}</td><td class="mono">${x.clientSystemId}</td>
                  <td><${Badge} kind="ok">${x.pinRef}<//></td>
                </tr>`)}
              </tbody>
            </table>
          </div>`}
      </div>
      <div class="panel-foot"><span class="mono hint">GET /admin/sessions · Push: session, card</span></div>
    </section>`;
}

/**
 * PUT …/slots/{n}/fault (LIANA-41): fields per type.
 * @param {{ kt: string, slot: number, onClose: () => void, onDone: () => void }} props
 */
function FaultDialog({ kt, slot, onClose, onDone }) {
  const [type, setType] = useState('status-word');
  const [value, setValue] = useState('');
  const [prefix, setPrefix] = useState('');
  const [count, setCount] = useState('');
  const [error, setError] = useState('');
  const [problem, setProblem] = useState(/** @type {any} */ (undefined));

  /** Check in the field before sending; the API checks the same again (400). */
  const check = () => {
    if (type === 'status-word' && !/^[0-9A-Fa-f]{4}$/.test(value)) return 'statusWord: 4 Hex-Zeichen erwartet';
    if (type === 'response' && !/^([0-9A-Fa-f]{2}){2,}$/.test(value)) return 'response: Hex, mindestens das Statuswort';
    if (type === 'delay' && !/^\d+$/.test(value)) return 'delayMs: Millisekunden als ganze Zahl';
    if (prefix && !/^([0-9A-Fa-f]{2})+$/.test(prefix)) return 'commandPrefix: Hex in ganzen Bytes';
    if (count && !/^[1-9]\d*$/.test(count)) return 'count: positive ganze Zahl';
    return '';
  };
  const submit = (/** @type {Event} */ e) => {
    e.preventDefault();
    const problemText = check();
    setError(problemText);
    if (problemText) {
      return;
    }
    /** @type {Record<string, unknown>} */
    const body = { type };
    if (type === 'status-word') body.statusWord = value;
    if (type === 'response') body.response = value;
    if (type === 'delay') body.delayMs = Number(value);
    if (prefix) body.commandPrefix = prefix;
    if (count) body.count = Number(count);
    admin.putFault(kt, slot, body).then(() => {
      notify('ok', 'Störung ' + type + ' an ' + kt + ' Slot ' + slot + ' gesetzt');
      onDone();
    }, (err) => fieldOrProblem(err, setError, setProblem));
  };
  const valueField = {
    'status-word': { label: 'Statuswort (hex)', placeholder: '6982', kind: 'text' },
    response: { label: 'Antwort (hex, inkl. Statuswort)', placeholder: '9000', kind: 'text' },
    delay: { label: 'Verzögerung (ms)', placeholder: '1500', kind: 'number' },
  }[type];
  return html`
    <${Dialog} title=${html`Störung setzen · <span class="mono">${kt} Slot ${slot}</span>`} onClose=${onClose} actions=${html`
        <button class="btn" type="button" onClick=${onClose}>Abbrechen</button>
        <button class="btn btn-primary" type="submit" form="fault-form">Störung setzen</button>`}>
      <form id="fault-form" onSubmit=${submit} class="form">
        <${Field} id="f-type" label="Typ">
          <select id="f-type" value=${type} onChange=${(/** @type {any} */ e) => { setType(e.target.value); setValue(''); setError(''); }}>
            <option value="status-word">status-word – Statuswort statt Antwort</option>
            <option value="response">response – eigene Antwort</option>
            <option value="io-error">io-error – Übertragungsfehler (4044)</option>
            <option value="delay">delay – Verzögerung</option>
          </select>
        <//>
        ${valueField ? html`
          <${Field} id="f-value" label=${valueField.label}>
            <input id="f-value" class="mono" type=${valueField.kind} value=${value} placeholder=${valueField.placeholder}
                aria-invalid=${error ? 'true' : undefined} aria-describedby=${error ? 'f-error' : undefined}
                onInput=${(/** @type {any} */ e) => setValue(e.target.value)} />
          <//>` : null}
        <div class="two">
          <${Field} id="f-prefix" label="Nur für Kommandos mit Präfix (hex)" hint="leer = alle, dann auch der Reset">
            <input id="f-prefix" class="mono" type="text" value=${prefix} placeholder="z. B. 0084"
                onInput=${(/** @type {any} */ e) => setPrefix(e.target.value)} />
          <//>
          <${Field} id="f-count" label="Anzahl" hint="leer = bis zum Löschen">
            <input id="f-count" class="mono" type="number" min="1" value=${count}
                onInput=${(/** @type {any} */ e) => setCount(e.target.value)} />
          <//>
        </div>
        ${error ? html`<span class="field-error" id="f-error">${error}</span>` : null}
      </form>
      <${ApiProblem} error=${problem} />
    <//>`;
}

const OUTCOMES = [
  ['correct', 'correct – konfigurierte PIN'],
  ['wrong', 'wrong – jede Ziffer geändert'],
  ['digits', 'digits – eigene Ziffern'],
  ['cancel', 'cancel – Abbruchtaste'],
  ['timeout', 'timeout – keine Eingabe'],
  ['puk', 'puk – konfigurierte PUK'],
  ['transport', 'transport – Transport-PIN'],
  ['incomplete', 'incomplete – ohne Bestätigung'],
];

/** POST …/pin-script [{outcome, slotNo, pin}] (LIANA-68). @param {{ kt: string, onClose: () => void, onDone: () => void }} props */
function PinDialog({ kt, onClose, onDone }) {
  const [outcome, setOutcome] = useState('correct');
  const [slot, setSlot] = useState('');
  const [pin, setPin] = useState('');
  const [error, setError] = useState('');
  const [problem, setProblem] = useState(/** @type {any} */ (undefined));
  const submit = (/** @type {Event} */ e) => {
    e.preventDefault();
    if (outcome === 'digits' && !/^\d{4,12}$/.test(pin)) {
      setError('pin: 4–12 Ziffern');
      return;
    }
    if (slot && !/^[1-9]\d*$/.test(slot)) {
      setError('slotNo: Slotnummer ab 1');
      return;
    }
    /** @type {Record<string, unknown>} */
    const entry = { outcome };
    if (slot) entry.slotNo = Number(slot);
    if (outcome === 'digits') entry.pin = pin;
    admin.appendPinScript(kt, [entry]).then(() => {
      notify('ok', 'PIN-Eingabe ' + outcome + ' an ' + kt + ' angehängt');
      onDone();
    }, (err) => fieldOrProblem(err, setError, setProblem));
  };
  return html`
    <${Dialog} title=${html`PIN-Eingabe anhängen · <span class="mono">${kt}</span>`} onClose=${onClose} actions=${html`
        <button class="btn" type="button" onClick=${onClose}>Abbrechen</button>
        <button class="btn btn-primary" type="submit" form="pin-form">Anhängen</button>`}>
      <form id="pin-form" onSubmit=${submit} class="form">
        <${Field} id="p-out" label="Ergebnis">
          <select id="p-out" value=${outcome} onChange=${(/** @type {any} */ e) => setOutcome(e.target.value)}>
            ${OUTCOMES.map(([value, label]) => html`<option value=${value}>${label}</option>`)}
          </select>
        <//>
        <div class="two">
          <${Field} id="p-slot" label="Slot" hint="leer = nächster PIN-Dialog an jedem Slot">
            <input id="p-slot" class="mono" type="number" min="1" value=${slot} onInput=${(/** @type {any} */ e) => setSlot(e.target.value)} />
          <//>
          ${outcome === 'digits' ? html`
            <${Field} id="p-pin" label="PIN" hint="4–12 Ziffern, wird nie zurückgegeben">
              <input id="p-pin" class="mono" type="password" inputmode="numeric" autocomplete="off" value=${pin}
                  onInput=${(/** @type {any} */ e) => setPin(e.target.value)} />
            <//>` : null}
        </div>
        ${error ? html`<span class="field-error">${error}</span>` : null}
      </form>
      <${ApiProblem} error=${problem} />
    <//>`;
}

/** PUT …/pairing {"sharedSecret": 32 hex}. @param {{ kt: string, onClose: () => void, onDone: () => void }} props */
function SecretDialog({ kt, onClose, onDone }) {
  const [secret, setSecret] = useState('');
  const [apiError, setApiError] = useState('');
  const [problem, setProblem] = useState(/** @type {any} */ (undefined));
  const hex = /^[0-9A-Fa-f]*$/.test(secret);
  const fieldError = !secret ? '' : !hex ? 'Nur Hex-Zeichen (0–9, A–F)'
    : secret.length !== 32 ? 'Genau 32 Hex-Zeichen nötig (jetzt ' + secret.length + ').' : '';
  const error = fieldError || apiError;
  const submit = (/** @type {Event} */ e) => {
    e.preventDefault();
    admin.putSharedSecret(kt, secret).then(() => {
      notify('ok', 'Shared Secret für ' + kt + ' gesetzt');
      onDone();
    }, (err) => fieldOrProblem(err, setApiError, setProblem));
  };
  return html`
    <${Dialog} title=${html`Shared Secret setzen · <span class="mono">${kt}</span>`} onClose=${onClose} actions=${html`
        <button class="btn" type="button" onClick=${onClose}>Abbrechen</button>
        <button class="btn btn-primary" type="submit" form="secret-form" disabled=${secret.length !== 32 || !hex}>Setzen</button>`}>
      <form id="secret-form" onSubmit=${submit} class="form">
        <${Field} id="s-sec" label="Shared Secret (16 Byte, DO_KT_0003)" error=${error}
            hint="Das KT gilt danach als gepairt; beim Verbinden prüft LIANA es per VALIDATE (TUC_KON_050).">
          <input id="s-sec" class="mono" type="text" value=${secret} maxlength="32" autocomplete="off" spellcheck="false"
              aria-invalid=${error ? 'true' : undefined} aria-describedby=${error ? 's-sec-error' : undefined}
              onInput=${(/** @type {any} */ e) => { setSecret(e.target.value.trim()); setApiError(''); }} />
        <//>
      </form>
      <${ApiProblem} error=${problem} />
    <//>`;
}

/** DELETE …/pairing. @param {{ kt: string, onClose: () => void, onDone: () => void }} props */
function UnpairDialog({ kt, onClose, onDone }) {
  const unpair = () => admin.unpair(kt).then(() => {
    notify('ok', 'Pairing von ' + kt + ' gelöst');
    onDone();
  }, notifyError);
  return html`
    <${Dialog} title=${html`Pairing von <span class="mono">${kt}</span> lösen?`} onClose=${onClose} actions=${html`
        <button class="btn" type="button" onClick=${onClose}>Abbrechen</button>
        <button class="btn btn-danger" type="button" onClick=${unpair}>Pairing lösen</button>`}>
      <p class="muted">Das Terminal wird getrennt und das Shared Secret gelöscht (Korrelation „zugewiesen“). Karten in ${kt} sind danach nicht mehr erreichbar, bis erneut gepairt wird.</p>
    <//>`;
}

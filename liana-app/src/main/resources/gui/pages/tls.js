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
 * Page 4 · TLS / mTLS of the connector interface (TAB_KON_506-01, LIANA-58), read-only: obligations, ANCL_DVD_OPEN,
 * TLS_USE_ECC_FOR_CS, server identity, protocol, cipher suites and curves (A_17124-03); plus the Vertrauensraum
 * (TUC_KON_037) with TSL state (LIANA-151).
 */
import { html, useEffect } from '../vendor/preact-htm.js';
import { admin } from '../api.js';
import { usePoll, Badge, ApiProblem, Empty, copy, copyIcon, dateTime, relative } from '../ui.js';

export function Tls() {
  const tls = usePoll(admin.tls, [], { on: ['state'] });
  const pki = usePoll(admin.pki, [], { on: ['state'] });
  const t = tls.data;
  const p = pki.data;
  // jump from the overview (#/tls/pki): to the PKI as soon as TLS and PKI are there (after that nothing shifts any
  // more)
  const loaded = t !== undefined && p !== undefined;
  useEffect(() => {
    if (loaded && location.hash.endsWith('/pki')) {
      document.getElementById('pki')?.scrollIntoView();
    }
  }, [loaded]);
  return html`
    <div class="title-row">
      <h1>TLS / mTLS</h1>
      <${Badge} kind="off">nur lesend<//>
      <span class="muted">Ändern geht über das KMS des Herstellerprofils (/rest/mgmt auf dem Management-Port, Profil EHEX oder SECUNET).</span>
    </div>
    <${ApiProblem} error=${tls.error} />
    ${t ? html`
      <section aria-label="Pflichten" class="tiles">
        <div class="tile">
          <span class="label">TLS-Pflicht (ANCL_TLS_MANDATORY)</span>
          <span class="figure-text">${t.tlsMandatory ? 'an' : 'aus'}</span>
          <span class="hint">${t.tlsMandatory ? 'HTTP auf dem Konnektor-Port antwortet nur noch für das Dienstverzeichnis, wenn es offen ist'
            : 'Konnektordienste auch per HTTP'}</span>
        </div>
        <div class="tile">
          <span class="label">Client-Authentisierung (ANCL_CAUT_MANDATORY)</span>
          <span class="figure-text">${t.clientAuthMandatory ? 'Pflicht' : 'aus'}</span>
          <span class="hint">${t.clientAuthMandatory ? 'Clientsysteme authentisieren sich (Zertifikat oder Basic, je KMS-Einstellung)'
            : 'keine Authentisierung der Clientsysteme'}</span>
        </div>
        <div class="tile">
          <span class="label">HTTPS-Port</span>
          <span class="figure-text mono">${t.port}</span>
          <span class="hint">TLS 1.2 (gemSpec_Krypt)</span>
        </div>
      </section>

      <section aria-labelledby="h-srv" class="panel pad">
        <h2 id="h-srv">Serverzertifikat des Konnektors</h2>
        <div class="strong">${t.certificate}</div>
        <div class="fingerprint">
          <span class="mono small muted">SHA-256 ${t.fingerprint}</span>
          <button class="btn btn-icon" type="button" aria-label="Fingerprint kopieren" onClick=${() => copy(t.fingerprint, 'Fingerprint')}>${copyIcon}</button>
        </div>
      </section>

      <section aria-labelledby="h-cli" class="panel">
        <div class="panel-head">
          <h2 id="h-cli">Client-Zertifikate (ANCL_CCERT_LIST)</h2>
          <${Badge} kind="info">${t.clientCertificates.length}<//>
        </div>
        ${t.clientCertificates.length ? html`
          <ul class="plain">${t.clientCertificates.map((/** @type {string} */ c) => html`<li class="mono small">${c}</li>`)}</ul>`
          : html`<${Empty} title="Keine Client-Zertifikate">Weder in liana.tls.client-certs noch über das KMS hinterlegt.<//>`}
      </section>

      <section aria-label="Weitere Einstellungen" class="tiles">
        <div class="tile">
          <span class="label">Dienstverzeichnis offen (ANCL_DVD_OPEN)</span>
          <span class="figure-text">${t.dvdOpen ? 'ja' : 'nein'}</span>
          <span class="hint">${t.dvdOpen ? 'connector.sds auch ohne Client-Authentisierung und per HTTP' : 'connector.sds nur mit Client-Authentisierung'}</span>
        </div>
        <div class="tile">
          <span class="label">ECC für Clientsysteme (TLS_USE_ECC_FOR_CS)</span>
          <span class="figure-text">${t.eccForClientSystems ? 'an' : 'aus'}</span>
          <span class="hint">${t.eccForClientSystems ? 'Serveridentität mit ECC-Schlüssel (brainpoolP256r1)' : 'Serveridentität mit RSA-Schlüssel'}</span>
        </div>
        <div class="tile">
          <span class="label">Serveridentität</span>
          <span class="figure-text">${t.serverSoftwareKey ? 'Software-Schlüssel' : 'ID.AK.AUT'}</span>
          <span class="hint">${t.serverSoftwareKey ? 'über das KMS erzeugtes oder importiertes Serverzertifikat (A_21811-05)'
            : 'Identität der gSMC-K (TIP1-A_4514-01); ein Software-Schlüssel ist über das KMS wählbar (A_21811-05)'}</span>
        </div>
      </section>

      <section aria-labelledby="h-suites" class="panel pad">
        <div class="title-row">
          <h2 id="h-suites">Protokoll, Cipher-Suites und Kurven</h2>
          <${Badge} kind="info">${t.protocol}<//>
          <span class="hint">A_17124-03 (gemSpec_Krypt)</span>
        </div>
        <div class="tags">${t.cipherSuites.map((/** @type {string} */ c) => html`<span class="tag mono">${c}</span>`)}</div>
        <div class="tags"><span class="hint">Kurven</span>${t.namedGroups.map((/** @type {string} */ g) => html`<span class="tag mono">${g}</span>`)}</div>
      </section>` : null}

    <${ApiProblem} error=${pki.error} />
    ${p ? html`
      <section id="pki" aria-labelledby="h-pki" class="panel">
        <div class="panel-head">
          <h2 id="h-pki">PKI · Vertrauensraum (TUC_KON_037)</h2>
          ${tslBadge(p.tsl)}
        </div>
        <div class="pad-box">
          <dl class="facts-dl">
            <div><dt class="hint">TSL-Datei (liana.pki.tsl)</dt><dd class="mono">${p.tsl?.file ?? 'keine'}</dd></div>
            <div><dt class="hint">Sequenznummer</dt><dd class="mono">${p.tsl?.sequenceNumber ?? '–'}</dd></div>
            <div><dt class="hint">NextUpdate</dt><dd class="mono">${p.tsl?.nextUpdate ? dateTime(p.tsl.nextUpdate) + ' · ' + relative(p.tsl.nextUpdate) : '–'}</dd></div>
            <div><dt class="hint">CAs aus der TSL</dt><dd class="mono">${p.tsl ? p.tsl.caCount : '–'}</dd></div>
            <div><dt class="hint">Importierte CAs (liana.pki.imported-cas)</dt><dd class="mono">${p.importedCas}</dd></div>
          </dl>
        </div>
        <div class="panel-foot"><span class="mono hint">GET /admin/pki · Änderung nur per Neustart</span></div>
      </section>` : null}`;
}

/** State of the TSL: none, expired (NextUpdate passed) or valid. @param {any} tsl */
export function tslBadge(tsl) {
  if (!tsl) {
    return html`<${Badge} kind="off">keine TSL<//>`;
  }
  if (tsl.nextUpdate && new Date(tsl.nextUpdate).getTime() < Date.now()) {
    return html`<${Badge} kind="warn">NextUpdate überschritten<//>`;
  }
  return html`<${Badge} kind="ok">TSL aktuell<//>`;
}

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
 * Client of the admin API (decision-018): the GUI knows only the JSON endpoints under /admin, the same as
 * liana-control-client and the suites. All calls are in {@link admin}, one per line as a
 * template literal; from them GuiTest in verify reads the endpoints used and checks that they exist.
 */

/** Error response of the admin API ({"error": …, "code": …}) or no connection (status 0). */
export class ApiError extends Error {
  /**
   * @param {number} status HTTP status, 0 without connection
   * @param {string} message message from {"error": …}
   * @param {number | undefined} code connector error code on 409 (TUC error)
   */
  constructor(status, message, code) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

/**
 * @param {string} method
 * @param {string} path
 * @param {unknown} [body]
 * @returns {Promise<any>}
 */
async function call(method, path, body) {
  /** @type {RequestInit} */
  const init = { method, headers: { Accept: 'application/json' } };
  if (body !== undefined) {
    init.headers = { ...init.headers, 'Content-Type': 'application/json' };
    init.body = JSON.stringify(body);
  }
  let response;
  try {
    response = await fetch(path, init);
  } catch (e) {
    throw new ApiError(0, 'Keine Verbindung zur Admin-API', undefined);
  }
  const text = await response.text();
  /** @type {any} */
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch (e) {
    json = null;
  }
  if (!response.ok) {
    const message = json && typeof json.error === 'string' ? json.error : text || response.statusText;
    throw new ApiError(response.status, message, json && typeof json.code === 'number' ? json.code : undefined);
  }
  return json;
}

/** @param {string} path */
const get = (path) => call('GET', path);
/** @param {string} path @param {unknown} body */
const put = (path, body) => call('PUT', path, body);
/** @param {string} path @param {unknown} [body] */
const post = (path, body) => call('POST', path, body);
/** @param {string} path */
const del = (path) => call('DELETE', path);

/**
 * Text of a response, without interpreting JSON (.kon preview).
 * @param {string} path
 */
async function getText(path) {
  let response;
  try {
    response = await fetch(path);
  } catch (e) {
    throw new ApiError(0, 'Keine Verbindung zur Admin-API', undefined);
  }
  const text = await response.text();
  if (!response.ok) {
    let message = text;
    try {
      message = JSON.parse(text).error ?? text;
    } catch (e) {
      // not JSON
    }
    throw new ApiError(response.status, message, undefined);
  }
  return text;
}

/**
 * Stream of the admin events (server-sent events, LIANA-150); the browser reconnects by itself and sends
 * Last-Event-ID when doing so.
 * @param {string} path
 */
const stream = (path) => new EventSource(path);

/** Path segment (CT IDs, Clientsysteme) safely into a URL. */
const seg = encodeURIComponent;

/**
 * Query for /admin/log: from and to as ISO-8601, omitted when empty.
 * @param {string} from
 * @param {string} to
 */
function range(from, to) {
  const query = new URLSearchParams();
  if (from) query.set('from', from);
  if (to) query.set('to', to);
  return query.size ? '?' + query : '';
}

/**
 * The endpoints of the admin API that the GUI uses (docs/handbuch.md, section Admin-API). Placeholders in the paths:
 * kt, slot, client; GuiTest fills in example values.
 */
export const admin = {
  ready: () => get(`/admin/ready`),
  info: () => get(`/admin/info`),
  terminals: () => get(`/admin/terminals`),
  ctList: () => get(`/admin/ct-list`),
  /** @param {string} kt @param {unknown} body {"fingerprint": …} or {} */
  pair: (kt, body) => post(`/admin/terminals/${seg(kt)}/pairing`, body),
  /** @param {string} kt @param {string} sharedSecret */
  putSharedSecret: (kt, sharedSecret) => put(`/admin/terminals/${seg(kt)}/pairing`, { sharedSecret }),
  /** @param {string} kt */
  unpair: (kt) => del(`/admin/terminals/${seg(kt)}/pairing`),
  /** @param {string} kt @param {number} slot @param {string} image */
  putCard: (kt, slot, image) => put(`/admin/terminals/${seg(kt)}/slots/${slot}`, { image }),
  /** @param {string} kt @param {number} slot */
  removeCard: (kt, slot) => del(`/admin/terminals/${seg(kt)}/slots/${slot}`),
  /** @param {string} kt @param {number} slot @param {unknown} fault */
  putFault: (kt, slot, fault) => put(`/admin/terminals/${seg(kt)}/slots/${slot}/fault`, fault),
  /** @param {string} kt @param {number} slot */
  removeFault: (kt, slot) => del(`/admin/terminals/${seg(kt)}/slots/${slot}/fault`),
  /** @param {string} kt @param {unknown[]} entries */
  appendPinScript: (kt, entries) => post(`/admin/terminals/${seg(kt)}/pin-script`, entries),
  /** @param {string} kt */
  clearPinScript: (kt) => del(`/admin/terminals/${seg(kt)}/pin-script`),
  infomodel: () => get(`/admin/infomodel`),
  tls: () => get(`/admin/tls`),
  vendor: () => get(`/admin/vendor`),
  /** @param {{ vendor?: string, strict?: boolean }} body */
  putVendor: (body) => put(`/admin/vendor`, body),
  /** @param {string} from @param {string} to */
  log: (from, to) => get(`/admin/log${range(from, to)}`),
  /** Path for preview and download. @param {string} client */
  konPath: (client) => `/admin/clients/${seg(client)}/config.kon`,
  /** @param {string} client */
  kon: (client) => getText(`/admin/clients/${seg(client)}/config.kon`),
  reset: () => post(`/admin/reset`),
  images: () => get(`/admin/images`),
  subscriptions: () => get(`/admin/subscriptions`),
  sessions: () => get(`/admin/sessions`),
  pki: () => get(`/admin/pki`),
  settings: () => get(`/admin/settings`),
  /** @param {{ cardSessionTimeout?: number, luOnline?: boolean }} body */
  putSettings: (body) => put(`/admin/settings`, body),
  deviations: () => get(`/admin/deviations`),
  /** Service discovery (TUC_KON_054) for all configured eHealth CTs. */
  ctDiscovery: () => post(`/admin/ct-discovery`, {}),
  /** Push: log, card, terminal, state, subscription, session, resync. */
  events: () => stream(`/admin/events`),
};

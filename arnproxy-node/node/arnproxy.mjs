/** ARNPROXY thin client 1.1.0. Server-side Node.js only; never embed your key in browser code. */
import https from 'node:https';
import { readFileSync } from 'node:fs';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { TextDecoder } from 'node:util';

const RESOURCES = JSON.parse(readFileSync(new URL('../resources.json', import.meta.url), 'utf8')).resources;
const MAX = 2 * 1024 * 1024;
export class ArnproxyError extends Error {
  constructor(code, { http_status = null, request_id = null, retry_after = null, uncertain = false } = {}) {
    super(code); this.name = 'ArnproxyError'; Object.assign(this, { code, http_status, request_id, retry_after, uncertain });
  }
}
const plain = v => v !== null && typeof v === 'object' && (Object.getPrototypeOf(v) === Object.prototype || Object.getPrototypeOf(v) === null);
function jsonValue(v, depth = 0) {
  if (depth > 32) return false;
  if (v === null || typeof v === 'string' || typeof v === 'boolean') return true;
  if (typeof v === 'number') return Number.isFinite(v) && Math.abs(v) <= Number.MAX_SAFE_INTEGER;
  if (Array.isArray(v)) return v.every(x => jsonValue(x, depth + 1));
  return plain(v) && Object.values(v).every(x => jsonValue(x, depth + 1));
}
export class Client {
  #key;
  static BASE = 'https://www.arnproxy.com/account/api/v1/';
  constructor(apiKey, { allow_writes = false, allow_provider_reads = false, timeout = 20 } = {}) {
    if (typeof apiKey !== 'string' || !/^(?:[A-Za-z0-9]{32}|arnp_[a-f0-9]{16}_[a-f0-9]{64})$/.test(apiKey)) throw new ArnproxyError('INVALID_KEY_FORMAT');
    if (typeof allow_writes !== 'boolean' || typeof allow_provider_reads !== 'boolean' || typeof timeout !== 'number' || !Number.isFinite(timeout) || timeout < 1 || timeout > 60) throw new ArnproxyError('INVALID_CLIENT_OPTIONS');
    this.#key = apiKey; this.allow_writes = allow_writes; this.allow_provider_reads = allow_provider_reads; this.timeout = timeout;
  }
  account() { return this.request('account'); }
  capabilities() { return this.request('capabilities'); }
  async request(resource, params = {}, { operation_key = null } = {}) {
    const spec = typeof resource === 'string' && Object.hasOwn(RESOURCES, resource) ? RESOURCES[resource] : null;
    if (!spec) throw new ArnproxyError('UNKNOWN_RESOURCE');
    if (!plain(params) || Object.hasOwn(params, 'resource')) throw new ArnproxyError('INVALID_PARAMETERS');
    params = { ...params };
    if (spec.disabled) throw new ArnproxyError('DISABLED_RESOURCE');
    const write = spec.write;
    if (write && this.allow_writes !== true) throw new ArnproxyError('WRITES_DISABLED');
    if (spec.provider_read && this.allow_provider_reads !== true) throw new ArnproxyError('PROVIDER_READS_DISABLED');
    const headers = { Authorization: 'Bearer ' + this.#key, Accept: 'application/json', 'User-Agent': 'ARNPROXY-Node/1.1.0' };
    if (spec.idempotency) {
      if (typeof operation_key !== 'string' || !/^[A-Za-z0-9_-]{16,100}$/.test(operation_key)) throw new ArnproxyError('OPERATION_KEY_REQUIRED');
      headers['Idempotency-Key'] = operation_key;
    } else if (operation_key !== null) throw new ArnproxyError('UNEXPECTED_OPERATION_KEY');
    let path = spec.path;
    if (path.includes('{id}')) {
      const id = params.id;
      if (!['string', 'number'].includes(typeof id) || !/^[1-9][0-9]{0,9}$/.test(String(id)) || Number(id) > 2147483647) throw new ArnproxyError('INVALID_ROUTE_ID');
      path = path.replace('{id}', String(id)); delete params.id;
    }
    let body = null;
    if (spec.method === 'GET') {
      const query = new URLSearchParams();
      for (const [k, v] of Object.entries(params)) {
        if (!['string', 'boolean', 'number'].includes(typeof v) || typeof v === 'number' && !Number.isSafeInteger(v)) throw new ArnproxyError('INVALID_QUERY_VALUE');
        query.set(k, typeof v === 'boolean' ? v ? '1' : '0' : String(v));
      }
      if (query.size) path += '?' + query.toString();
    } else {
      try { if (!jsonValue(params)) throw new Error(); body = Buffer.from(JSON.stringify(params)); } catch { throw new ArnproxyError('INVALID_JSON_BODY'); }
      if (body.length > MAX) throw new ArnproxyError('REQUEST_TOO_LARGE');
      headers['Content-Type'] = 'application/json'; headers['Content-Length'] = String(body.length);
    }
    let response;
    try { response = await this._send(spec.method, '/account/api/v1/' + path, headers, body); }
    catch (e) { throw new ArnproxyError(e instanceof ArnproxyError ? e.code : 'TRANSPORT_ERROR', { uncertain: write }); }
    const { status, headers: received, body: raw } = response;
    if (status >= 300 && status < 400) throw new ArnproxyError('REDIRECT_BLOCKED', { http_status: status, uncertain: write });
    const retry = received['retry-after'];
    const retry_after = typeof retry === 'string' && /^[0-9]{1,5}$/.test(retry) && Number(retry) <= 86400 ? Number(retry) : null;
    if (!Buffer.isBuffer(raw) || raw.length > MAX) throw new ArnproxyError('RESPONSE_TOO_LARGE', { http_status: status, uncertain: write });
    let result;
    try { result = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw)); } catch { throw new ArnproxyError('INVALID_API_RESPONSE', { http_status: status, retry_after, uncertain: write }); }
    const request_id = typeof result?.meta?.request_id === 'string' && /^[a-f0-9]{24}$/.test(result.meta.request_id) ? result.meta.request_id : null;
    if (!plain(result) || typeof result.ok !== 'boolean' || request_id === null) throw new ArnproxyError('INVALID_API_RESPONSE', { http_status: status, retry_after, uncertain: write });
    if (status < 200 || status >= 300 || result.ok !== true) {
      const code = typeof result.error?.code === 'string' && /^[A-Z][A-Z0-9_]{0,79}$/.test(result.error.code) ? result.error.code : 'API_HTTP_ERROR';
      throw new ArnproxyError(code, { http_status: status, request_id, retry_after, uncertain: write && status >= 500 });
    }
    if (!Object.hasOwn(result, 'data')) throw new ArnproxyError('INVALID_API_RESPONSE', { http_status: status, request_id, uncertain: write });
    return result;
  }
  _send(method, path, headers, body) {
    return new Promise((resolve, reject) => {
      let done = false, timer, req;
      const finish = (err, value) => { if (done) return; done = true; clearTimeout(timer); err ? reject(err) : resolve(value); };
      try {
        // Fixed HTTPS destination, native API (no redirect following), no shared keep-alive agent or environment proxy.
        req = https.request({ hostname: 'www.arnproxy.com', port: 443, path, method, headers, rejectUnauthorized: true, agent: false }, res => {
          const chunks = []; let size = 0;
          res.on('data', chunk => { size += chunk.length; if (size > MAX) { finish(new ArnproxyError('RESPONSE_TOO_LARGE')); res.destroy(); req.destroy(); } else chunks.push(chunk); });
          res.on('end', () => finish(null, { status: res.statusCode, headers: { 'retry-after': res.headers['retry-after'] ?? '' }, body: Buffer.concat(chunks) }));
          res.on('aborted', () => finish(new ArnproxyError('TRANSPORT_ERROR'))); res.on('error', () => finish(new ArnproxyError('TRANSPORT_ERROR')));
        });
        timer = setTimeout(() => { finish(new ArnproxyError('TRANSPORT_TIMEOUT')); req.destroy(); }, this.timeout * 1000);
        req.on('error', () => finish(new ArnproxyError('TRANSPORT_ERROR'))); req.end(body);
      } catch { finish(new ArnproxyError('TRANSPORT_ERROR')); if (req) req.destroy(); }
    });
  }
}

export function verifyWebhook(rawBody, headers, signingSecret, { now = Math.floor(Date.now() / 1000) } = {}) {
  try {
    if (!Buffer.isBuffer(rawBody) || rawBody.length > 4096 || !plain(headers)) throw new Error();
    const values = Object.create(null);
    for (const [k, v] of Object.entries(headers)) if (['webhook-id', 'webhook-timestamp', 'webhook-signature'].includes(k.toLowerCase())) {
      if (Object.hasOwn(values, k.toLowerCase()) || typeof v !== 'string') throw new Error(); values[k.toLowerCase()] = v;
    }
    const id = values['webhook-id'], timestamp = values['webhook-timestamp'], signature = values['webhook-signature'];
    if (typeof id !== 'string' || !/^evt_[a-f0-9]{32}$/.test(id) || typeof timestamp !== 'string' || !/^[1-9][0-9]{0,11}$/.test(timestamp) || typeof signature !== 'string' || signature.length > 1024 || !Number.isSafeInteger(now) || Math.abs(now - Number(timestamp)) > 300) throw new Error();
    if (typeof signingSecret !== 'string' || !/^whsec_[A-Za-z0-9+/]{43}=$/.test(signingSecret)) throw new Error();
    const secret = Buffer.from(signingSecret.slice(6), 'base64'); if (secret.length !== 32 || secret.toString('base64') !== signingSecret.slice(6)) throw new Error();
    const expected = createHmac('sha256', secret).update(id + '.' + timestamp + '.').update(rawBody).digest();
    let valid = false;
    for (const token of signature.split(/\s+/)) if (/^v1,[A-Za-z0-9+/]{43}=$/.test(token)) { const actual = Buffer.from(token.slice(3), 'base64'); if (actual.length === expected.length) valid = timingSafeEqual(actual, expected) || valid; }
    if (!valid) throw new Error();
    const event = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(rawBody));
    if (!plain(event) || event.id !== id || event.api_version !== '1' || !plain(event.data) || typeof event.type !== 'string') throw new Error();
    return event;
  } catch { throw new ArnproxyError('WEBHOOK_VERIFICATION_FAILED'); }
}

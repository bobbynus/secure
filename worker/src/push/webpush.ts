/**
 * Minimal Web Push sender on Web Crypto:
 *  - payload encryption: RFC 8291 (Message Encryption for Web Push) with RFC 8188 "aes128gcm";
 *  - authentication: RFC 8292 VAPID (ES256 JWT).
 */

const enc = new TextEncoder();

export interface PushTarget {
  endpoint: string;
  p256dh: string; // base64url, uncompressed P-256 point (65 bytes)
  auth: string; // base64url, 16 bytes
}

export interface Vapid {
  publicKey: string; // base64url, uncompressed P-256 point
  privateJwk: JsonWebKey;
  subject: string; // mailto: or https: URL
}

export interface PushResult {
  status: number;
  /** Subscription no longer valid: delete it. */
  gone: boolean;
  ok: boolean;
  text?: string;
}

/** Hosts of browser push services. Anything else is rejected (no arbitrary outbound requests). */
const PUSH_HOSTS = [
  /^fcm\.googleapis\.com$/,
  /^updates\.push\.services\.mozilla\.com$/,
  /^push\.services\.mozilla\.com$/,
  /(^|\.)push\.apple\.com$/,
  /(^|\.)notify\.windows\.com$/,
  /^web\.push\.apple\.com$/,
];

export function isAllowedEndpoint(endpoint: string): boolean {
  try {
    const u = new URL(endpoint);
    return u.protocol === 'https:' && !u.port && PUSH_HOSTS.some((re) => re.test(u.hostname));
  } catch {
    return false;
  }
}

export async function sendPush(target: PushTarget, payload: string, vapid: Vapid, opts: { ttl?: number; urgency?: 'normal' | 'high'; topic?: string } = {}): Promise<PushResult> {
  const body = await encryptPayload(target, enc.encode(payload));
  const jwt = await vapidJwt(new URL(target.endpoint).origin, vapid);
  const headers: Record<string, string> = {
    'Content-Encoding': 'aes128gcm',
    'Content-Type': 'application/octet-stream',
    TTL: String(opts.ttl ?? 86_400),
    Urgency: opts.urgency ?? 'normal',
    Authorization: `vapid t=${jwt}, k=${vapid.publicKey}`,
  };
  if (opts.topic) headers.Topic = opts.topic.replace(/[^A-Za-z0-9_-]/g, '').slice(0, 32);
  const r = await fetch(target.endpoint, { method: 'POST', headers, body });
  return { status: r.status, ok: r.status >= 200 && r.status < 300, gone: r.status === 404 || r.status === 410, text: r.ok ? undefined : (await r.text()).slice(0, 200) };
}

// ---------- RFC 8291 / 8188 ----------

export async function encryptPayload(target: PushTarget, plaintext: Uint8Array, salt = crypto.getRandomValues(new Uint8Array(16))): Promise<Uint8Array> {
  const uaPublic = b64urlDecode(target.p256dh);
  const authSecret = b64urlDecode(target.auth);
  if (uaPublic.length !== 65 || uaPublic[0] !== 4) throw new Error('bad p256dh');
  if (authSecret.length < 16) throw new Error('bad auth');

  const asKeys = (await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'])) as CryptoKeyPair;
  const asPublic = new Uint8Array((await crypto.subtle.exportKey('raw', asKeys.publicKey)) as ArrayBuffer);
  const uaKey = await crypto.subtle.importKey('raw', uaPublic, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const ecdhSecret = new Uint8Array(
    await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey } as unknown as SubtleCryptoDeriveKeyAlgorithm, asKeys.privateKey, 256),
  );

  // PRK_key = HMAC(auth, ecdh); IKM = HMAC(PRK_key, "WebPush: info\0" || ua_public || as_public || 0x01)
  const prkKey = await hmac(authSecret, ecdhSecret);
  const keyInfo = concat(enc.encode('WebPush: info\0'), uaPublic, asPublic, new Uint8Array([1]));
  const ikm = await hmac(prkKey, keyInfo);

  // PRK = HMAC(salt, IKM); CEK and NONCE via HKDF-Expand (single block).
  const prk = await hmac(salt, ikm);
  const cek = (await hmac(prk, concat(enc.encode('Content-Encoding: aes128gcm\0'), new Uint8Array([1])))).slice(0, 16);
  const nonce = (await hmac(prk, concat(enc.encode('Content-Encoding: nonce\0'), new Uint8Array([1])))).slice(0, 12);

  // Single record: plaintext || 0x02 (last-record delimiter).
  const record = concat(plaintext, new Uint8Array([2]));
  const rs = 4096;
  if (record.length + 16 > rs) throw new Error('payload too large');
  const key = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, record));

  const header = new Uint8Array(16 + 4 + 1 + asPublic.length);
  header.set(salt, 0);
  new DataView(header.buffer).setUint32(16, rs);
  header[20] = asPublic.length;
  header.set(asPublic, 21);
  return concat(header, ciphertext);
}

// ---------- RFC 8292 VAPID ----------

async function vapidJwt(audience: string, vapid: Vapid): Promise<string> {
  const header = b64urlEncode(enc.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const claims = b64urlEncode(enc.encode(JSON.stringify({ aud: audience, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: vapid.subject })));
  const key = await crypto.subtle.importKey('jwk', vapid.privateJwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  // Web Crypto returns IEEE P1363 (r || s), which is exactly the JWS ES256 format.
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, enc.encode(`${header}.${claims}`)));
  return `${header}.${claims}.${b64urlEncode(sig)}`;
}

// ---------- helpers ----------

async function hmac(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, data));
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function b64urlEncode(b: Uint8Array): string {
  let s = '';
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function b64urlDecode(s: string): Uint8Array {
  const b = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4));
  return Uint8Array.from(b, (c) => c.charCodeAt(0));
}

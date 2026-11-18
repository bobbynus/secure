// Run: node --test worker/test/webpush.test.ts   (Node ≥ 22.18 strips types natively)
// Round-trip: encrypt with our sender, decrypt with an independent receiver implementation (RFC 8291 §3.4).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { b64urlDecode, b64urlEncode, encryptPayload, isAllowedEndpoint } from '../src/push/webpush.ts';

const { subtle } = globalThis.crypto;
const enc = new TextEncoder();

async function hmac(key: Uint8Array, data: Uint8Array) {
  const k = await subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await subtle.sign('HMAC', k, data));
}
const cat = (...a: Uint8Array[]) => Uint8Array.from(a.flatMap((x) => [...x]));

test('aes128gcm payload decrypts on the receiver side', async () => {
  // User agent (browser) keys.
  const ua = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const uaPublic = new Uint8Array(await subtle.exportKey('raw', ua.publicKey));
  const authSecret = crypto.getRandomValues(new Uint8Array(16));
  const message = JSON.stringify({ title: 'Тест · Test · Prüfung', body: 'x'.repeat(500), url: '/ru/' });

  const body = await encryptPayload({ endpoint: 'https://fcm.googleapis.com/x', p256dh: b64urlEncode(uaPublic), auth: b64urlEncode(authSecret) }, enc.encode(message));

  // Parse RFC 8188 header.
  const salt = body.slice(0, 16);
  const rs = new DataView(body.buffer, body.byteOffset).getUint32(16);
  const idlen = body[20]!;
  const asPublic = body.slice(21, 21 + idlen);
  const ciphertext = body.slice(21 + idlen);
  assert.equal(rs, 4096);
  assert.equal(idlen, 65);

  // Receiver key schedule.
  const asKey = await subtle.importKey('raw', asPublic, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const ecdh = new Uint8Array(await subtle.deriveBits({ name: 'ECDH', public: asKey }, ua.privateKey, 256));
  const ikm = await hmac(await hmac(authSecret, ecdh), cat(enc.encode('WebPush: info\0'), uaPublic, asPublic, new Uint8Array([1])));
  const prk = await hmac(salt, ikm);
  const cek = (await hmac(prk, cat(enc.encode('Content-Encoding: aes128gcm\0'), new Uint8Array([1])))).slice(0, 16);
  const nonce = (await hmac(prk, cat(enc.encode('Content-Encoding: nonce\0'), new Uint8Array([1])))).slice(0, 12);
  const key = await subtle.importKey('raw', cek, 'AES-GCM', false, ['decrypt']);
  const plain = new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: nonce }, key, ciphertext));

  assert.equal(plain.at(-1), 2, 'last-record delimiter');
  assert.equal(new TextDecoder().decode(plain.slice(0, -1)), message);
});

test('endpoint allowlist blocks arbitrary hosts', () => {
  assert.ok(isAllowedEndpoint('https://fcm.googleapis.com/fcm/send/abc'));
  assert.ok(isAllowedEndpoint('https://updates.push.services.mozilla.com/wpush/v2/abc'));
  assert.ok(isAllowedEndpoint('https://web.push.apple.com/abc'));
  assert.ok(isAllowedEndpoint('https://wns2-par02p.notify.windows.com/w/?token=abc'));
  assert.ok(!isAllowedEndpoint('http://fcm.googleapis.com/x'));
  assert.ok(!isAllowedEndpoint('https://fcm.googleapis.com:8443/x'));
  assert.ok(!isAllowedEndpoint('https://evil.example/fcm.googleapis.com'));
  assert.ok(!isAllowedEndpoint('https://169.254.169.254/latest'));
  assert.ok(!isAllowedEndpoint('https://fcm.googleapis.com.evil.example/x'));
});

test('base64url round-trip', () => {
  const b = crypto.getRandomValues(new Uint8Array(65));
  assert.deepEqual(b64urlDecode(b64urlEncode(b)), b);
});

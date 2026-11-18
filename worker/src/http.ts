import type { Env, RateLimit } from './env';

export class HttpError extends Error {
  constructor(public status: number, public code: string, public extra: Record<string, unknown> = {}) {
    super(code);
  }
}

const BASE_HEADERS = {
  'Content-Type': 'application/json; charset=utf-8',
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
};

export function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { ...BASE_HEADERS, ...headers } });
}

export function errorResponse(e: unknown): Response {
  if (e instanceof HttpError) return json({ ok: false, error: e.code, ...e.extra }, e.status);
  console.error('unhandled', e instanceof Error ? e.stack : e);
  return json({ ok: false, error: 'internal' }, 500);
}

/**
 * Same-origin only: the API is not meant for third-party sites. Browsers always send Origin on POST;
 * it must equal the site origin or the host the request was made to (covers `wrangler dev`).
 */
export function assertOrigin(req: Request, env: Env) {
  const origin = req.headers.get('Origin');
  if (!origin) throw new HttpError(403, 'forbidden_origin');
  if (origin === env.SITE_ORIGIN) return;
  let host: string;
  try {
    host = new URL(origin).host;
  } catch {
    throw new HttpError(403, 'forbidden_origin');
  }
  if (host !== new URL(req.url).host) throw new HttpError(403, 'forbidden_origin');
}

export async function readJson<T>(req: Request, maxBytes = 8192): Promise<T> {
  if (!(req.headers.get('Content-Type') ?? '').startsWith('application/json')) throw new HttpError(415, 'unsupported_media_type');
  const text = await req.text();
  if (text.length > maxBytes) throw new HttpError(413, 'too_large');
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new HttpError(400, 'bad_json');
  }
}

/** Rate limit keyed by client IP. The IP is only used as an in-memory key, never stored. */
export async function rateLimit(rl: RateLimit, req: Request, scope: string) {
  const ip = req.headers.get('CF-Connecting-IP') ?? 'local';
  const { success } = await rl.limit({ key: `${scope}:${ip}` });
  if (!success) throw new HttpError(429, 'rate_limited');
}

const BOT_UA = /bot|crawl|spider|slurp|headless|lighthouse|preview|fetch|curl|wget|python|httpclient|java\/|go-http|monitor/i;
export function isBot(req: Request): boolean {
  const ua = req.headers.get('User-Agent') ?? '';
  return !ua || BOT_UA.test(ua);
}

export const now = () => Math.floor(Date.now() / 1000);
export const utcDay = (d = new Date()) => d.toISOString().slice(0, 10);

export async function sha256Hex(s: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Constant-time comparison for bearer tokens. */
export function safeEqual(a: string, b: string): boolean {
  const x = new TextEncoder().encode(a);
  const y = new TextEncoder().encode(b);
  if (x.length !== y.length) return false;
  let r = 0;
  for (let i = 0; i < x.length; i++) r |= x[i]! ^ y[i]!;
  return r === 0;
}

export function assertBearer(req: Request, token: string | undefined) {
  const h = req.headers.get('Authorization') ?? '';
  if (!token || !h.startsWith('Bearer ') || !safeEqual(h.slice(7), token)) throw new HttpError(401, 'unauthorized');
}
